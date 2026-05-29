"""Fortinet FortiSIEM incident parser.

FortiSIEM exports incidents with attributes such as ``incidentId``, ``incidentTitle``,
``ruleName``, ``incidentSeverity`` (numeric 0-10), ``srcIpAddr`` / ``destIpAddr``,
``attackTactic`` / ``attackTechnique``, and ``incidentStatus``.

Severity scale (FortiSIEM's own numeric buckets -> OCSF severity_id):
    0-4  LOW    -> 2 (Low)
    5-8  MEDIUM -> 3 (Medium)
    9-10 HIGH   -> 4 (High)
"""

from __future__ import annotations

from typing import Any

from siem_to_ocsf.models import (
    ActivityId,
    Endpoint,
    IntermediateAlert,
    MitreTechnique,
    SeverityId,
    StatusId,
)
from siem_to_ocsf.parsers._common import first, split_mitre, to_epoch_ms

SOURCE_ID = "fortisiem"
VENDOR_NAME = "Fortinet"
PRODUCT_NAME = "FortiSIEM"

_STATUS: dict[str, StatusId] = {
    "active": StatusId.NEW,
    "open": StatusId.NEW,
    "in progress": StatusId.IN_PROGRESS,
    "cleared": StatusId.RESOLVED,
    "closed": StatusId.RESOLVED,
}


def detect(raw: dict[str, Any]) -> bool:
    return "incidentId" in raw and ("incidentSeverity" in raw or "incidentTitle" in raw)


def _severity(value: Any) -> SeverityId:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return SeverityId.UNKNOWN
    if n <= 4:
        return SeverityId.LOW
    if n <= 8:
        return SeverityId.MEDIUM
    return SeverityId.HIGH


def _endpoint(ip: Any, port: Any, host: Any = None) -> Endpoint | None:
    if not ip and not port and not host:
        return None
    return Endpoint(
        ip=ip or None,
        hostname=host or None,
        port=int(port) if port not in (None, "") else None,
    )


def parse(raw: dict[str, Any]) -> IntermediateAlert:
    technique_uid, technique_name = split_mitre(raw.get("attackTechnique"))
    tactic_uid, tactic_name = split_mitre(raw.get("attackTactic"))
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

    status = _STATUS.get(str(raw.get("incidentStatus", "")).strip().lower(), StatusId.NEW)

    return IntermediateAlert(
        source_id=SOURCE_ID,
        vendor_name=VENDOR_NAME,
        product_name=PRODUCT_NAME,
        alert_id=str(raw["incidentId"]),
        title=first(raw, "incidentTitle", "ruleName", default="FortiSIEM Incident"),
        description=first(raw, "ruleDescription", "incidentTitle"),
        severity_id=_severity(raw.get("incidentSeverity")),
        native_severity=str(raw.get("incidentSeverity"))
        if raw.get("incidentSeverity") is not None
        else None,
        event_time=to_epoch_ms(first(raw, "incidentFirstSeen", "phRecvTime", "eventReceiveTime")),
        activity_id=ActivityId.CREATE,
        status_id=status,
        message=first(raw, "ruleDescription", "incidentTitle"),
        src_endpoint=_endpoint(raw.get("srcIpAddr"), raw.get("srcIpPort"), raw.get("srcName")),
        dst_endpoint=_endpoint(raw.get("destIpAddr"), raw.get("destIpPort"), raw.get("destName")),
        actor_user=first(raw, "user", "srcOwner"),
        device_hostname=first(raw, "hostName", "reptDevName"),
        rule_name=first(raw, "ruleName", "eventType"),
        rule_uid=str(raw["ruleId"]) if raw.get("ruleId") is not None else None,
        mitre=mitre,
        raw=raw,
    )
