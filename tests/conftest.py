"""Shared test fixtures and path helpers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"
GOLDEN = Path(__file__).resolve().parent / "golden"

# One representative sample per vendor, matched to its golden OCSF output.
GOLDEN_CASES = {
    "cortex_xdr": SAMPLES / "cortex_xdr" / "alert_powershell_download.json",
    "fortisiem": SAMPLES / "fortisiem" / "incident_ssh_bruteforce.json",
    "sentinel": SAMPLES / "sentinel" / "alert_impossible_travel.json",
    "logscale": SAMPLES / "logscale" / "detection_c2_beacon.json",
    "zscaler_zia": SAMPLES / "zscaler_zia" / "web_malware_download.json",
    "checkpoint": SAMPLES / "checkpoint" / "threat_emulation_malicious_doc.json",
}


def load_json(path: Path) -> dict:
    return json.loads(Path(path).read_text())


def vendor_sample_files() -> list[Path]:
    """All synthetic vendor samples (excludes the intentionally-malformed set)."""
    return sorted(
        p
        for p in SAMPLES.glob("*/*.json")
        if p.parent.name != "malformed"
    )


@pytest.fixture
def samples_dir() -> Path:
    return SAMPLES
