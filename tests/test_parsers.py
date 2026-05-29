"""Unit tests for each parser: raw sample in -> expected intermediate model out."""

from __future__ import annotations

import pytest

from conftest import load_json, vendor_sample_files
from siem_to_ocsf import parsers
from siem_to_ocsf.models import IntermediateAlert, SeverityId
from siem_to_ocsf.parsers._common import split_mitre, to_epoch_ms


@pytest.mark.parametrize("path", vendor_sample_files(), ids=lambda p: f"{p.parent.name}/{p.name}")
def test_every_sample_autodetects_and_parses(path):
    raw = load_json(path)
    src = parsers.detect_source(raw)
    assert src == path.parent.name, f"auto-detect mismatch for {path}"
    alert = parsers.parse(raw, src)
    assert isinstance(alert, IntermediateAlert)
    assert alert.source_id == src
    assert alert.alert_id
    assert alert.title
    assert alert.event_time > 0
    assert alert.raw == raw


def test_cortex_xdr_fields():
    raw = load_json("samples/cortex_xdr/alert_powershell_download.json")
    alert = parsers.cortex_xdr.parse(raw)
    assert alert.vendor_name == "Palo Alto Networks"
    assert alert.product_name == "Cortex XDR"
    assert alert.alert_id == "CRTX-100481"
    assert alert.severity_id == SeverityId.HIGH  # "high" -> 4
    assert alert.native_severity == "high"
    assert alert.src_endpoint.ip == "10.20.14.37"
    assert alert.dst_endpoint.ip == "203.0.113.45"
    assert alert.dst_endpoint.port == 443
    assert alert.actor_user == "acme\\j.harper"
    assert alert.device_hostname == "FIN-WS-014"
    assert alert.mitre[0].technique_uid == "T1059.001"
    assert alert.mitre[0].tactic_uid == "TA0002"
    # SHA-256 surfaced as an observable
    assert any(o.value == raw["action_file_sha256"] for o in alert.observables)


def test_cortex_severity_scale():
    crit = load_json("samples/cortex_xdr/alert_credential_dumping.json")
    assert parsers.cortex_xdr.parse(crit).severity_id == SeverityId.CRITICAL
    med = load_json("samples/cortex_xdr/alert_internal_port_scan.json")
    assert parsers.cortex_xdr.parse(med).severity_id == SeverityId.MEDIUM


def test_fortisiem_numeric_severity_buckets():
    high = load_json("samples/fortisiem/incident_ssh_bruteforce.json")  # 9 -> High
    assert parsers.fortisiem.parse(high).severity_id == SeverityId.HIGH
    med = load_json("samples/fortisiem/incident_malware_outbreak.json")  # 7 -> Medium
    assert parsers.fortisiem.parse(med).severity_id == SeverityId.MEDIUM
    low = load_json("samples/fortisiem/incident_data_exfil.json")  # 3 -> Low
    assert parsers.fortisiem.parse(low).severity_id == SeverityId.LOW


def test_sentinel_entities_and_severity():
    raw = load_json("samples/sentinel/alert_impossible_travel.json")
    alert = parsers.sentinel.parse(raw)
    assert alert.severity_id == SeverityId.MEDIUM
    assert alert.src_endpoint.ip == "203.0.113.77"
    assert alert.device_hostname == "sales-lt-009"
    assert alert.actor_user == "acme\\a.lindqvist"
    assert {m.technique_uid for m in alert.mitre} == {"T1078.004", "T1110"}


def test_logscale_numeric_severity_bands():
    raw = load_json("samples/logscale/detection_c2_beacon.json")  # 88 -> Critical
    alert = parsers.logscale.parse(raw)
    assert alert.severity_id == SeverityId.CRITICAL
    assert alert.device_hostname == "eng-ws-204"
    assert alert.dst_endpoint.ip == "198.51.100.140"
    assert alert.mitre[0].technique_uid == "T1071.001"


def test_zscaler_riskscore_to_severity():
    raw = load_json("samples/zscaler_zia/web_malware_download.json")  # riskscore 92 -> Critical
    alert = parsers.zscaler_zia.parse(raw)
    assert alert.severity_id == SeverityId.CRITICAL
    assert alert.src_endpoint.ip == "10.70.3.21"
    assert any(o.value.startswith("http") for o in alert.observables)


def test_checkpoint_confidence_and_severity():
    raw = load_json("samples/checkpoint/threat_emulation_malicious_doc.json")
    alert = parsers.checkpoint.parse(raw)
    assert alert.severity_id == SeverityId.CRITICAL
    assert alert.confidence_id == 3  # confidence_level 3 -> High
    assert alert.product_name == "Threat Emulation"
    assert alert.dst_endpoint.port == 443


def test_to_epoch_ms_accepts_seconds_ms_and_iso():
    assert to_epoch_ms(1779974400) == 1779974400000  # seconds -> ms
    assert to_epoch_ms(1779974400000) == 1779974400000  # already ms
    assert to_epoch_ms("2026-05-28T13:20:00Z") == 1779974400000


def test_split_mitre():
    assert split_mitre("T1059.001 - PowerShell") == ("T1059.001", "PowerShell")
    assert split_mitre("TA0002: Execution") == ("TA0002", "Execution")
    assert split_mitre(None) == (None, None)
