"""Ingestion pipeline: load -> detect -> parse -> enrich -> map -> validate.

Kept separate from the CLI so the run logic is unit-testable. The cardinal rule here
is *resilience*: a single bad record must never abort the run. Anything that fails to
load, detect, parse, or validate is captured as a :class:`DeadLetter` with a reason.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from siem_to_ocsf import parsers
from siem_to_ocsf.enrichment import enrich as default_enrich
from siem_to_ocsf.ocsf import OCSFValidationError, build_and_validate


@dataclass
class LoadedRecord:
    """A single raw record plus where it came from."""

    raw: Any
    origin: str  # "path" or "path#index"


@dataclass
class DeadLetter:
    reason: str
    origin: str
    source: str | None = None
    raw: Any = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "reason": self.reason,
            "origin": self.origin,
            "source": self.source,
            "raw": self.raw,
        }


@dataclass
class RunSummary:
    records_in: Counter = field(default_factory=Counter)
    normalized: Counter = field(default_factory=Counter)
    dead_lettered: Counter = field(default_factory=Counter)
    raw_fields: dict[str, list[int]] = field(default_factory=dict)
    ocsf_fields: dict[str, list[int]] = field(default_factory=dict)
    reasons: Counter = field(default_factory=Counter)

    @property
    def total_in(self) -> int:
        return sum(self.records_in.values())

    @property
    def total_normalized(self) -> int:
        return sum(self.normalized.values())

    @property
    def total_dead_lettered(self) -> int:
        return sum(self.dead_lettered.values())

    def _avg(self, table: dict[str, list[int]], source: str) -> float:
        vals = table.get(source, [])
        return sum(vals) / len(vals) if vals else 0.0

    def avg_raw_fields(self, source: str) -> float:
        return self._avg(self.raw_fields, source)

    def avg_ocsf_fields(self, source: str) -> float:
        return self._avg(self.ocsf_fields, source)


@dataclass
class RunResult:
    events: list[dict[str, Any]]
    dead_letters: list[DeadLetter]
    summary: RunSummary


def _iter_json_files(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    return sorted(p for p in target.rglob("*.json") if p.is_file())


def load_records(target: str | Path) -> list[LoadedRecord]:
    """Load records from a file or directory.

    Each ``.json`` file may contain a single object, a JSON array, or one JSON object
    per line (JSONL). Unparseable files surface later as dead letters via
    :func:`process`; here we best-effort split files into records.
    """
    target = Path(target)
    records: list[LoadedRecord] = []
    for path in _iter_json_files(target):
        text = path.read_text().strip()
        if not text:
            continue
        sp = str(path)
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            # Try JSONL.
            for i, line in enumerate(text.splitlines()):
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(LoadedRecord(raw=json.loads(line), origin=f"{sp}#{i}"))
                except json.JSONDecodeError:
                    records.append(LoadedRecord(raw=line, origin=f"{sp}#{i}"))
            continue
        if isinstance(obj, list):
            records.extend(
                LoadedRecord(raw=item, origin=f"{sp}#{i}") for i, item in enumerate(obj)
            )
        else:
            records.append(LoadedRecord(raw=obj, origin=sp))
    return records


def process(
    records: list[LoadedRecord],
    source: str = "auto",
    *,
    enrich: bool = True,
    validate_only: bool = False,
) -> RunResult:
    """Run records through the full pipeline, never raising on a bad record."""
    summary = RunSummary()
    events: list[dict[str, Any]] = []
    dead_letters: list[DeadLetter] = []

    for rec in records:
        raw = rec.raw

        # Resolve source.
        if source == "auto":
            if not isinstance(raw, dict):
                dl = DeadLetter("record is not a JSON object", rec.origin, None, raw)
                _record_dl(summary, dead_letters, dl)
                continue
            src = parsers.detect_source(raw)
            if src is None:
                dl = DeadLetter("unable to auto-detect source", rec.origin, None, raw)
                _record_dl(summary, dead_letters, dl)
                continue
        else:
            src = source

        summary.records_in[src] += 1
        if isinstance(raw, dict):
            summary.raw_fields.setdefault(src, []).append(len(raw))

        try:
            alert = parsers.parse(raw, src)
            if enrich:
                alert = default_enrich(alert)
            event = build_and_validate(alert)
        except OCSFValidationError as exc:
            _record_dl(
                summary,
                dead_letters,
                DeadLetter(f"OCSF validation failed: {exc}", rec.origin, src, raw),
            )
            continue
        except Exception as exc:  # noqa: BLE001 - any parser error must be captured
            _record_dl(
                summary,
                dead_letters,
                DeadLetter(f"{type(exc).__name__}: {exc}", rec.origin, src, raw),
            )
            continue

        summary.normalized[src] += 1
        summary.ocsf_fields.setdefault(src, []).append(len(event))
        if not validate_only:
            events.append(event)

    return RunResult(events=events, dead_letters=dead_letters, summary=summary)


def _record_dl(summary: RunSummary, sink: list[DeadLetter], dl: DeadLetter) -> None:
    key = dl.source or "unknown"
    summary.dead_lettered[key] += 1
    summary.reasons[dl.reason.split(":")[0]] += 1
    sink.append(dl)
