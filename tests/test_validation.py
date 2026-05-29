"""Validation tests: every normalised output must conform to the pinned OCSF schema.

Also covers the operational-resilience features: enrichment, dead-lettering, and the
run summary.
"""

from __future__ import annotations

import pytest

from conftest import SAMPLES, load_json, vendor_sample_files
from siem_to_ocsf import parsers
from siem_to_ocsf.enrichment import enrich
from siem_to_ocsf.ocsf import (
    OCSFValidationError,
    build_and_validate,
    load_schema,
    to_ocsf_dict,
    validate_ocsf,
)
from siem_to_ocsf.pipeline import load_records, process

# --- Schema conformance ---------------------------------------------------------


def test_vendored_schema_is_detection_finding():
    schema = load_schema()
    assert schema["title"] == "Detection Finding"
    assert schema["properties"]["class_uid"]["const"] == 2004
    assert schema["properties"]["category_uid"]["const"] == 2
    # Profile-injected requirements were relaxed back to the base class.
    assert "cloud" not in schema["required"]
    assert "osint" not in schema["required"]
    for req in ("activity_id", "class_uid", "finding_info", "metadata", "severity_id", "time"):
        assert req in schema["required"]


@pytest.mark.parametrize("path", vendor_sample_files(), ids=lambda p: f"{p.parent.name}/{p.name}")
def test_every_sample_validates_against_pinned_schema(path):
    raw = load_json(path)
    alert = enrich(parsers.parse(raw, path.parent.name))
    event = build_and_validate(alert)  # raises on non-conformance
    assert event["class_uid"] == 2004


def test_additional_properties_are_rejected():
    # The schema uses additionalProperties:false, so an invented field must fail.
    event = to_ocsf_dict(parsers.parse(load_json(vendor_sample_files()[0]), "checkpoint"))
    event["totally_invented_field"] = "nope"
    with pytest.raises(OCSFValidationError):
        validate_ocsf(event)


def test_bad_severity_id_is_rejected():
    event = to_ocsf_dict(parsers.parse(load_json(vendor_sample_files()[0]), "checkpoint"))
    event["severity_id"] = 7  # not in the OCSF enum
    with pytest.raises(OCSFValidationError):
        validate_ocsf(event)


# --- Enrichment -----------------------------------------------------------------


def test_enrichment_tags_internal_and_external():
    raw = load_json("samples/cortex_xdr/alert_powershell_download.json")
    alert = enrich(parsers.parse(raw, "cortex_xdr"))
    scopes = {e["data"]["role"]: e["value"] for e in alert.enrichments}
    assert scopes["src_endpoint"] == "internal"  # 10.20.14.37 (RFC1918)
    assert scopes["dst_endpoint"] == "external"  # 203.0.113.45 (TEST-NET / public)
    external = next(e for e in alert.enrichments if e["value"] == "external")
    assert external["data"]["geo"]["note"] == "synthetic"


def test_enrichment_appears_in_validated_event():
    raw = load_json("samples/cortex_xdr/alert_powershell_download.json")
    event = build_and_validate(enrich(parsers.parse(raw, "cortex_xdr")))
    assert any(e["name"] == "ip_scope" for e in event["enrichments"])


# --- Pipeline: dead-lettering and summary ---------------------------------------


def test_pipeline_dead_letters_malformed_records():
    records = load_records(SAMPLES)  # includes samples/malformed/*
    result = process(records, source="auto")
    assert result.summary.total_normalized == 18
    assert result.summary.total_dead_lettered == 2
    reasons = " ".join(dl.reason for dl in result.dead_letters)
    assert "auto-detect" in reasons  # unknown_vendor.json
    assert "alert_id" in reasons  # cortex_missing_alert_id.json


def test_pipeline_never_raises_on_bad_input():
    from siem_to_ocsf.pipeline import LoadedRecord

    junk = [
        LoadedRecord(raw="not a dict", origin="x"),
        LoadedRecord(raw={"unrecognised": True}, origin="y"),
    ]
    result = process(junk, source="auto")
    assert result.summary.total_dead_lettered == 2
    assert result.events == []


def test_validate_only_produces_no_events():
    records = load_records(SAMPLES / "sentinel")
    result = process(records, source="auto", validate_only=True)
    assert result.events == []
    assert result.summary.total_normalized == 3
