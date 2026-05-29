"""Golden-file and invariant tests for the OCSF mapping.

Golden files live in ``tests/golden/<source>.ocsf.json`` and capture the exact OCSF
output for one representative alert per vendor (mapping only, no enrichment, so the
files stay deterministic). Regenerate intentionally with::

    SIEM_TO_OCSF_REGEN=1 pytest tests/test_ocsf_mapping.py
"""

from __future__ import annotations

import json
import os

import pytest

from conftest import GOLDEN, GOLDEN_CASES, load_json
from siem_to_ocsf import parsers
from siem_to_ocsf.ocsf import (
    CATEGORY_UID,
    CLASS_UID,
    OCSF_VERSION,
    to_ocsf_dict,
    type_uid_for,
)

REGEN = os.environ.get("SIEM_TO_OCSF_REGEN") == "1"


@pytest.mark.parametrize("source", sorted(GOLDEN_CASES), ids=sorted(GOLDEN_CASES))
def test_golden_mapping(source):
    raw = load_json(GOLDEN_CASES[source])
    event = to_ocsf_dict(parsers.parse(raw, source))

    golden_path = GOLDEN / f"{source}.ocsf.json"
    if REGEN:
        golden_path.write_text(json.dumps(event, indent=2, sort_keys=True) + "\n")

    expected = load_json(golden_path)
    assert event == expected, f"OCSF mapping drift for {source}; rerun with SIEM_TO_OCSF_REGEN=1"


@pytest.mark.parametrize("source", sorted(GOLDEN_CASES), ids=sorted(GOLDEN_CASES))
def test_classification_uids(source):
    event = to_ocsf_dict(parsers.parse(load_json(GOLDEN_CASES[source]), source))
    assert event["class_uid"] == CLASS_UID == 2004
    assert event["category_uid"] == CATEGORY_UID == 2
    assert event["type_uid"] == type_uid_for(event["activity_id"])
    assert event["metadata"]["version"] == OCSF_VERSION


def test_type_uid_formula():
    assert type_uid_for(1) == 200401
    assert type_uid_for(2) == 200402
    assert type_uid_for(99) == 200499


def test_severity_id_and_caption_consistent():
    event = to_ocsf_dict(parsers.parse(load_json(GOLDEN_CASES["cortex_xdr"]), "cortex_xdr"))
    assert event["severity_id"] == 4
    assert event["severity"] == "High"


def test_metadata_product_populated():
    event = to_ocsf_dict(parsers.parse(load_json(GOLDEN_CASES["checkpoint"]), "checkpoint"))
    product = event["metadata"]["product"]
    assert product["vendor_name"] == "Check Point"
    assert product["name"]  # blade name


def test_observables_deduplicated():
    # The Cortex sample has host_ip == action_local_ip; the IP must appear once.
    event = to_ocsf_dict(parsers.parse(load_json(GOLDEN_CASES["cortex_xdr"]), "cortex_xdr"))
    ips = [o["value"] for o in event["observables"] if o["type_id"] == 2]
    assert len(ips) == len(set(ips))
