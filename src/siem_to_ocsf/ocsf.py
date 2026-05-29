"""OCSF mapping and validation.

This module is the single place that converts the vendor-neutral
:class:`~siem_to_ocsf.models.IntermediateAlert` into a validated OCSF *Detection
Finding* event. Per the brief, adding a new source touches a parser, never this file.

OCSF version is pinned with :data:`OCSF_VERSION`; the matching official JSON Schema is
vendored under ``schema/`` and used for authoritative validation.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from functools import lru_cache
from importlib import resources
from typing import Any

from jsonschema import Draft7Validator

from siem_to_ocsf.models import (
    ACTIVITY_CAPTION,
    OBSERVABLE_CAPTION,
    SEVERITY_CAPTION,
    STATUS_CAPTION,
    Attack,
    DetectionFinding,
    Enrichment,
    Evidence,
    FindingInfo,
    IntermediateAlert,
    Metadata,
    NetworkEndpoint,
    ObservableTypeId,
    OCSFObservable,
    Product,
    Tactic,
    Technique,
)

# --- Pinned OCSF identifiers (from the 1.8.0 schema; do not edit by hand) ----------
OCSF_VERSION = "1.8.0"
CATEGORY_UID = 2  # Findings
CATEGORY_NAME = "Findings"
CLASS_UID = 2004  # Detection Finding
CLASS_NAME = "Detection Finding"

_SCHEMA_FILE = f"detection_finding-{OCSF_VERSION}.schema.json"


class OCSFValidationError(ValueError):
    """Raised when an emitted event fails OCSF JSON Schema validation."""


def type_uid_for(activity_id: int) -> int:
    """OCSF type_uid = class_uid * 100 + activity_id (e.g. Create -> 200401)."""
    return CLASS_UID * 100 + activity_id


@lru_cache(maxsize=1)
def load_schema() -> dict[str, Any]:
    """Load and cache the vendored OCSF Detection Finding JSON Schema."""
    text = resources.files("siem_to_ocsf.schema").joinpath(_SCHEMA_FILE).read_text()
    return json.loads(text)


@lru_cache(maxsize=1)
def _validator() -> Draft7Validator:
    return Draft7Validator(load_schema())


def validate_ocsf(event: dict[str, Any]) -> None:
    """Validate a serialized OCSF event against the pinned schema.

    Raises :class:`OCSFValidationError` with a readable message listing every problem.
    """
    errors = sorted(_validator().iter_errors(event), key=lambda e: list(e.path))
    if errors:
        details = "; ".join(
            f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}" for e in errors
        )
        raise OCSFValidationError(details)


def _epoch_ms_to_iso(epoch_ms: int) -> str:
    return (
        datetime.fromtimestamp(epoch_ms / 1000, tz=UTC)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _endpoint(ep: Any) -> NetworkEndpoint | None:
    if ep is None or ep.is_empty():
        return None
    return NetworkEndpoint(ip=ep.ip, hostname=ep.hostname, port=ep.port)


def _derive_observables(alert: IntermediateAlert) -> list[OCSFObservable]:
    """Build OCSF observables from structured entities plus parser-supplied ones.

    Observables are the OCSF idiom for "pivotable indicators". We synthesise them from
    endpoints/user/device so correlation works even when a source only provides
    structured fields, then append any domain-specific observables the parser surfaced
    (hashes, URLs, files). Deduplicated on (type_id, value).
    """
    out: list[OCSFObservable] = []

    def add(type_id: int, value: str | None) -> None:
        if not value:
            return
        out.append(
            OCSFObservable(name=OBSERVABLE_CAPTION[type_id], type_id=type_id, value=value)
        )

    for ep in (alert.src_endpoint, alert.dst_endpoint):
        if ep is not None:
            add(ObservableTypeId.IP_ADDRESS, ep.ip)
            add(ObservableTypeId.HOSTNAME, ep.hostname)
    add(ObservableTypeId.HOSTNAME, alert.device_hostname)
    add(ObservableTypeId.USER_NAME, alert.actor_user)

    for obs in alert.observables:
        out.append(
            OCSFObservable(
                name=obs.name or OBSERVABLE_CAPTION.get(obs.type_id, "Other"),
                type_id=int(obs.type_id),
                value=obs.value,
            )
        )

    seen: set[tuple[int, str | None]] = set()
    deduped: list[OCSFObservable] = []
    for o in out:
        key = (o.type_id, o.value)
        if key not in seen:
            seen.add(key)
            deduped.append(o)
    return deduped


def _finding_info(alert: IntermediateAlert) -> FindingInfo:
    attacks: list[Attack] = []
    for m in alert.mitre:
        technique = (
            Technique(uid=m.technique_uid, name=m.technique_name)
            if (m.technique_uid or m.technique_name)
            else None
        )
        tactic = (
            Tactic(uid=m.tactic_uid, name=m.tactic_name)
            if (m.tactic_uid or m.tactic_name)
            else None
        )
        if technique or tactic:
            attacks.append(Attack(technique=technique, tactic=tactic))

    types = [alert.rule_name] if alert.rule_name else None
    return FindingInfo(
        uid=alert.rule_uid or alert.alert_id,
        title=alert.title,
        desc=alert.description,
        created_time=alert.event_time,
        types=types,
        attacks=attacks or None,
    )


def to_detection_finding(alert: IntermediateAlert) -> DetectionFinding:
    """Map a vendor-neutral alert to a typed OCSF Detection Finding model."""
    evidences: list[Evidence] = []
    src = _endpoint(alert.src_endpoint)
    dst = _endpoint(alert.dst_endpoint)
    if src or dst:
        evidences.append(Evidence(name=alert.title, src_endpoint=src, dst_endpoint=dst))

    enrichments = [Enrichment(**e) for e in alert.enrichments] or None

    return DetectionFinding(
        activity_id=int(alert.activity_id),
        activity_name=ACTIVITY_CAPTION[int(alert.activity_id)],
        category_uid=CATEGORY_UID,
        category_name=CATEGORY_NAME,
        class_uid=CLASS_UID,
        class_name=CLASS_NAME,
        type_uid=type_uid_for(int(alert.activity_id)),
        type_name=f"{CLASS_NAME}: {ACTIVITY_CAPTION[int(alert.activity_id)]}",
        time=alert.event_time,
        time_dt=_epoch_ms_to_iso(alert.event_time),
        severity_id=int(alert.severity_id),
        severity=SEVERITY_CAPTION[int(alert.severity_id)],
        status_id=int(alert.status_id) if alert.status_id is not None else None,
        status=STATUS_CAPTION[int(alert.status_id)] if alert.status_id is not None else None,
        confidence_id=alert.confidence_id,
        message=alert.message or alert.title,
        metadata=Metadata(
            version=OCSF_VERSION,
            product=Product(
                vendor_name=alert.vendor_name,
                name=alert.product_name,
                version=alert.product_version,
            ),
            log_name=alert.source_id,
            original_time=_epoch_ms_to_iso(alert.event_time),
        ),
        finding_info=_finding_info(alert),
        observables=_derive_observables(alert) or None,
        evidences=evidences or None,
        enrichments=enrichments,
        is_alert=True,
        raw_data=json.dumps(alert.raw, separators=(",", ":"), sort_keys=True),
    )


def to_ocsf_dict(alert: IntermediateAlert) -> dict[str, Any]:
    """Map to OCSF and serialize to a plain dict (None fields dropped)."""
    finding = to_detection_finding(alert)
    return finding.model_dump(mode="json", exclude_none=True)


def build_and_validate(alert: IntermediateAlert) -> dict[str, Any]:
    """Map, serialize, and validate against the pinned OCSF schema.

    Returns the validated event dict, or raises :class:`OCSFValidationError`.
    """
    event = to_ocsf_dict(alert)
    validate_ocsf(event)
    return event
