"""Palo Alto Cortex XDR alert parser.

Cortex XDR exposes alerts (via the ``get_alerts`` API) with a flat structure and very
characteristic field names: ``detection_timestamp``, ``action_local_ip`` /
``action_remote_ip``, ``mitre_technique_id_and_name``, ``action_file_sha256``, etc.

Severity scale (native -> OCSF severity_id):
    informational -> 1, low -> 2, medium -> 3, high -> 4, critical -> 5
"""

from __future__ import annotations

from typing import Any

from siem_to_ocsf.models import (
    ActivityId,
    Endpoint,
    IntermediateAlert,
    MitreTechnique,
    Observable,
    ObservableTypeId,
    SeverityId,
    StatusId,
)
from siem_to_ocsf.parsers._common import first, split_mitre, to_epoch_ms

SOURCE_ID = "cortex_xdr"
VENDOR_NAME = "Palo Alto Networks"
PRODUCT_NAME = "Cortex XDR"

_SEVERITY: dict[str, SeverityId] = {
    "informational": SeverityId.INFORMATIONAL,
    "info": SeverityId.INFORMATIONAL,
    "low": SeverityId.LOW,
    "medium": SeverityId.MEDIUM,
    "high": SeverityId.HIGH,
    "critical": SeverityId.CRITICAL,
}


def detect(raw: dict[str, Any]) -> bool:
    return "detection_timestamp" in raw and (
        "mitre_technique_id_and_name" in raw
        or "action_local_ip" in raw
        or "agent_id" in raw
    )


def _severity(value: Any) -> SeverityId:
    return _SEVERITY.get(str(value).strip().lower(), SeverityId.UNKNOWN)


def _endpoint(ip: Any, port: Any) -> Endpoint | None:
    if not ip and not port:
        return None
    return Endpoint(ip=ip or None, port=int(port) if port not in (None, "") else None)


def parse(raw: dict[str, Any]) -> IntermediateAlert:
    technique_uid, technique_name = split_mitre(raw.get("mitre_technique_id_and_name"))
    tactic_uid, tactic_name = split_mitre(raw.get("mitre_tactic_id_and_name"))
    mitre = []
    if technique_uid or tactic_uid:
        mitre.append(
            MitreTechnique(
                technique_uid=technique_uid,
                technique_name=technique_name,
                tactic_uid=tactic_uid,
                tactic_name=tactic_name,
            )
        )

    observables: list[Observable] = []
    if raw.get("action_file_sha256"):
        observables.append(
            Observable(
                name="SHA-256", type_id=ObservableTypeId.HASH, value=raw["action_file_sha256"]
            )
        )
    if raw.get("action_file_name"):
        observables.append(
            Observable(
                name="File Name",
                type_id=ObservableTypeId.FILE_NAME,
                value=raw["action_file_name"],
            )
        )

    src = _endpoint(raw.get("action_local_ip"), raw.get("action_local_port"))
    dst = _endpoint(raw.get("action_remote_ip"), raw.get("action_remote_port"))

    return IntermediateAlert(
        source_id=SOURCE_ID,
        vendor_name=VENDOR_NAME,
        product_name=PRODUCT_NAME,
        alert_id=str(raw["alert_id"]),
        title=first(raw, "name", "alert_name", default="Cortex XDR Alert"),
        description=raw.get("description"),
        severity_id=_severity(raw.get("severity")),
        native_severity=str(raw.get("severity")) if raw.get("severity") is not None else None,
        event_time=to_epoch_ms(raw["detection_timestamp"]),
        activity_id=ActivityId.CREATE,
        status_id=StatusId.NEW,
        message=first(raw, "action_pretty", "description", "name"),
        src_endpoint=src,
        dst_endpoint=dst,
        actor_user=first(raw, "user_name", "actor_effective_username"),
        device_hostname=first(raw, "host_name", "endpoint_name"),
        rule_name=first(raw, "category", "alert_category"),
        mitre=mitre,
        observables=observables,
        raw=raw,
    )
