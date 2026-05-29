"""End-to-end CLI tests."""

from __future__ import annotations

import json

from conftest import SAMPLES
from siem_to_ocsf import cli


def test_cli_writes_jsonl_and_deadletter(tmp_path, capsys):
    out = tmp_path / "ocsf.jsonl"
    rc = cli.main([str(SAMPLES), "--source", "auto", "--out", str(out)])
    assert rc == 0

    lines = out.read_text().splitlines()
    assert len(lines) == 18
    for line in lines:
        event = json.loads(line)
        assert event["class_uid"] == 2004

    dl = out.with_suffix(out.suffix + ".deadletter.jsonl")
    assert len(dl.read_text().splitlines()) == 2

    summary = capsys.readouterr().out
    assert "TOTAL" in summary
    assert "Before/after" in summary


def test_cli_array_format(tmp_path):
    out = tmp_path / "ocsf.json"
    rc = cli.main([str(SAMPLES / "logscale"), "--out", str(out), "--format", "array"])
    assert rc == 0
    data = json.loads(out.read_text())
    assert isinstance(data, list)
    assert len(data) == 3


def test_cli_validate_only_writes_nothing(tmp_path, capsys):
    rc = cli.main([str(SAMPLES / "cortex_xdr"), "--validate-only"])
    assert rc == 0
    assert list(tmp_path.iterdir()) == []
    assert "validate-only" in capsys.readouterr().out


def test_cli_missing_input_returns_error(capsys):
    rc = cli.main(["/nonexistent/path", "--out", "x.jsonl"])
    assert rc == 2
    assert "does not exist" in capsys.readouterr().err


def test_cli_requires_out_unless_validate_only(capsys):
    rc = cli.main([str(SAMPLES / "cortex_xdr")])
    assert rc == 2
    assert "--out is required" in capsys.readouterr().err
