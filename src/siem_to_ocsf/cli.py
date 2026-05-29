"""Command-line interface for siem-to-ocsf."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from siem_to_ocsf import __version__, parsers
from siem_to_ocsf.ocsf import CLASS_NAME, OCSF_VERSION, load_schema
from siem_to_ocsf.pipeline import RunResult, RunSummary, load_records, process


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="siem-to-ocsf",
        description=(
            "Normalise SIEM/vendor alerts from six formats into OCSF "
            f"{CLASS_NAME} events (OCSF {OCSF_VERSION})."
        ),
    )
    p.add_argument("input", help="Input .json file or a directory of them (searched recursively)")
    p.add_argument(
        "--source",
        default="auto",
        choices=["auto", *parsers.available_sources()],
        help="Vendor source, or 'auto' to detect per record (default: auto)",
    )
    p.add_argument(
        "--out",
        "-o",
        help="Output path for normalised OCSF events (required unless --validate-only)",
    )
    p.add_argument(
        "--format",
        choices=["jsonl", "array"],
        default="jsonl",
        help="Output format: one JSON object per line, or a single JSON array (default: jsonl)",
    )
    p.add_argument(
        "--deadletter",
        help="Path for dead-lettered records (default: alongside --out as *.deadletter.jsonl)",
    )
    p.add_argument(
        "--validate-only",
        action="store_true",
        help="Parse, map and validate but write no normalised output",
    )
    p.add_argument(
        "--no-enrich",
        action="store_true",
        help="Disable the enrichment hook (internal/external tagging, geo stub)",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _write_events(events: list[dict], out: Path, fmt: str) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        if fmt == "array":
            json.dump(events, fh, indent=2)
            fh.write("\n")
        else:
            for ev in events:
                fh.write(json.dumps(ev, separators=(",", ":")))
                fh.write("\n")


def _write_dead_letters(result: RunResult, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for dl in result.dead_letters:
            fh.write(json.dumps(dl.to_dict(), separators=(",", ":")))
            fh.write("\n")


def _fmt_row(cols: list[str], widths: list[int]) -> str:
    cells = [
        c.ljust(w) if i == 0 else c.rjust(w)
        for i, (c, w) in enumerate(zip(cols, widths, strict=True))
    ]
    return "| " + " | ".join(cells) + " |"


def render_summary(summary: RunSummary) -> str:
    headers = ["Source", "In", "OCSF", "Dead", "Raw flds", "OCSF flds"]
    rows: list[list[str]] = []
    sources = sorted(set(summary.records_in) | set(summary.dead_lettered))
    for src in sources:
        rows.append(
            [
                src,
                str(summary.records_in.get(src, 0) + _dl_only(summary, src)),
                str(summary.normalized.get(src, 0)),
                str(summary.dead_lettered.get(src, 0)),
                f"{summary.avg_raw_fields(src):.0f}" if summary.raw_fields.get(src) else "-",
                f"{summary.avg_ocsf_fields(src):.0f}" if summary.ocsf_fields.get(src) else "-",
            ]
        )
    total = [
        "TOTAL",
        str(summary.total_in + summary.total_dead_lettered - _dl_with_source(summary)),
        str(summary.total_normalized),
        str(summary.total_dead_lettered),
        "",
        "",
    ]

    widths = [max(len(h), *(len(r[i]) for r in [*rows, total])) for i, h in enumerate(headers)]
    sep = "+-" + "-+-".join("-" * w for w in widths) + "-+"

    lines = [sep, _fmt_row(headers, widths), sep]
    lines += [_fmt_row(r, widths) for r in rows]
    lines += [sep, _fmt_row(total, widths), sep]

    schema_fields = len(load_schema().get("properties", {}))
    all_raw = [n for vals in summary.raw_fields.values() for n in vals]
    all_ocsf = [n for vals in summary.ocsf_fields.values() for n in vals]
    avg_raw = sum(all_raw) / len(all_raw) if all_raw else 0
    avg_ocsf = sum(all_ocsf) / len(all_ocsf) if all_ocsf else 0

    lines.append("")
    lines.append(
        f"Before/after: ~{avg_raw:.0f} heterogeneous vendor fields per alert  ->  "
        f"~{avg_ocsf:.0f} fields on one OCSF {CLASS_NAME} model "
        f"({schema_fields} fields available in OCSF {OCSF_VERSION})."
    )
    if summary.reasons:
        reasons = ", ".join(f"{r} x{c}" for r, c in summary.reasons.most_common())
        lines.append(f"Dead-letter reasons: {reasons}")
    return "\n".join(lines)


def _dl_only(summary: RunSummary, src: str) -> int:
    # Records dead-lettered before a source could be counted in records_in (e.g. parse
    # failures still increment records_in; auto-detect failures land under 'unknown').
    return summary.dead_lettered.get(src, 0) if src not in summary.records_in else 0


def _dl_with_source(summary: RunSummary) -> int:
    return sum(c for s, c in summary.dead_lettered.items() if s in summary.records_in)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    in_path = Path(args.input)
    if not in_path.exists():
        print(f"error: input path does not exist: {in_path}", file=sys.stderr)
        return 2
    if not args.validate_only and not args.out:
        print("error: --out is required unless --validate-only is set", file=sys.stderr)
        return 2

    records = load_records(in_path)
    result = process(
        records,
        source=args.source,
        enrich=not args.no_enrich,
        validate_only=args.validate_only,
    )

    if not args.validate_only:
        out_path = Path(args.out)
        _write_events(result.events, out_path, args.format)
        dl_path = Path(args.deadletter) if args.deadletter else out_path.with_suffix(
            out_path.suffix + ".deadletter.jsonl"
        )
        _write_dead_letters(result, dl_path)
        print(f"Wrote {len(result.events)} OCSF events -> {out_path}")
        print(f"Wrote {len(result.dead_letters)} dead-lettered records -> {dl_path}")
    else:
        print("validate-only: no output written")

    print()
    print(render_summary(result.summary))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
