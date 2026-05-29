"""CrowdStrike LogScale (Falcon LogScale) alert parser.

LogScale alert payloads carry the platform's characteristic ``#repo`` / ``@timestamp``
metadata alongside dotted ECS-style fields (``host.name``, ``threat.technique.id``,
``file.hash.sha256``) and a numeric ``severity`` on CrowdStrike's 0-100 scale.

Severity scale (CrowdStrike 0-100 bands -> OCSF severity_id):
    0-19  Informational -> 1
    20-39 Low           -> 2
    40-59 Medium        -> 3
    60-79 High          -> 4
    80-100 Critical     -> 5
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
from siem_to_ocsf.parsers._common import first, to_epoch_ms

SOURCE_ID = "logscale"
VENDOR_NAME = "CrowdStrike"
PRODUCT_NAME = "Falcon LogScale"


def detect(raw: dict[str, Any]) -> bool:
    return "#repo" in raw and "@timestamp" in raw


def _severity(value: Any) -> SeverityId:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return SeverityId.UNKNOWN
    if n < 20:
        return SeverityId.INFORMATIONAL
    if n < 40:
        return SeverityId.LOW
    if n < 60:
        return SeverityId.MEDIUM
    if n < 80:
        return SeverityId.HIGH
    return SeverityId.CRITICAL


def _endpoint(ip: Any, port: Any = None) -> Endpoint | None:
    if not ip and not port:
        return None
    return Endpoint(ip=ip or None, port=int(port) if port not in (None, "") else None)


def parse(raw: dict[str, Any]) -> IntermediateAlert:
    mitre = []
    if raw.get("threat.technique.id") or raw.get("threat.tactic.id"):
        mitre.append(
            MitreTechnique(
                technique_uid=raw.get("threat.technique.id"),
                technique_name=raw.get("threat.technique.name"),
                tactic_uid=raw.get("threat.tactic.id"),
                tactic_name=raw.get("threat.tactic.name"),
            )
        )

    observables: list[Observable] = []
    if raw.get("file.hash.sha256"):
        observables.append(
            Observable(
                name="SHA-256", type_id=ObservableTypeId.HASH, value=raw["file.hash.sha256"]
            )
        )
    if raw.get("file.name"):
        observables.append(
            Observable(
                name="File Name", type_id=ObservableTypeId.FILE_NAME, value=raw["file.name"]
            )
        )

    return IntermediateAlert(
        source_id=SOURCE_ID,
        vendor_name=VENDOR_NAME,
        product_name=PRODUCT_NAME,
        alert_id=str(first(raw, "alert.id", "@id")),
        title=first(raw, "alert.name", default="LogScale Detection"),
        description=raw.get("alert.description"),
        severity_id=_severity(first(raw, "severity", "alert.severity")),
        native_severity=str(first(raw, "severity", "alert.severity"))
        if first(raw, "severity", "alert.severity") is not None
        else None,
        event_time=to_epoch_ms(raw["@timestamp"]),
        activity_id=ActivityId.CREATE,
        status_id=StatusId.NEW,
        message=first(raw, "alert.description", "alert.name"),
        src_endpoint=_endpoint(first(raw, "source.ip", "aip", "LocalAddressIP4")),
        dst_endpoint=_endpoint(
            first(raw, "destination.ip", "RemoteAddressIP4"), raw.get("destination.port")
        ),
        actor_user=first(raw, "user.name", "UserName"),
        device_hostname=first(raw, "host.name", "ComputerName"),
        rule_name=first(raw, "#repo", "event.category"),
        mitre=mitre,
        observables=observables,
        raw=raw,
    )
