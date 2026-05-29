"""Check Point parser (Log Exporter / SmartConsole log format).

Check Point logs use fields such as ``product`` (the blade: "Threat Emulation",
"Anti-Bot", "IPS"...), ``src`` / ``dst``, ``protection_name``, ``malware_family``,
``rule_name`` / ``rule_uid``, a textual ``severity``, and ``confidence_level`` (1-3).

Severity scale (native -> OCSF severity_id):
    Informational -> 1, Low -> 2, Medium -> 3, High -> 4, Critical -> 5

``confidence_level`` (1=Low, 2=Medium, 3=High) maps directly onto OCSF
``confidence_id`` (1=Low, 2=Medium, 3=High).
"""

from __future__ import annotations

from typing import Any

from siem_to_ocsf.models import (
    ActivityId,
    Endpoint,
    IntermediateAlert,
    Observable,
    ObservableTypeId,
    SeverityId,
    StatusId,
)
from siem_to_ocsf.parsers._common import first, to_epoch_ms

SOURCE_ID = "checkpoint"
VENDOR_NAME = "Check Point"
PRODUCT_NAME = "Check Point"

_SEVERITY: dict[str, SeverityId] = {
    "informational": SeverityId.INFORMATIONAL,
    "info": SeverityId.INFORMATIONAL,
    "low": SeverityId.LOW,
    "medium": SeverityId.MEDIUM,
    "high": SeverityId.HIGH,
    "critical": SeverityId.CRITICAL,
}


def detect(raw: dict[str, Any]) -> bool:
    return "src" in raw and ("protection_name" in raw or "confidence_level" in raw)


def _severity(value: Any) -> SeverityId:
    return _SEVERITY.get(str(value).strip().lower(), SeverityId.UNKNOWN)


def _confidence_id(value: Any) -> int | None:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return None
    return n if n in (1, 2, 3) else None


def _endpoint(ip: Any, port: Any = None) -> Endpoint | None:
    if not ip and not port:
        return None
    return Endpoint(ip=ip or None, port=int(port) if port not in (None, "") else None)


def parse(raw: dict[str, Any]) -> IntermediateAlert:
    observables: list[Observable] = []
    if raw.get("malware_family"):
        observables.append(
            Observable(
                name="Malware Family",
                type_id=ObservableTypeId.OTHER,
                value=raw["malware_family"],
            )
        )
    if raw.get("protection_name"):
        observables.append(
            Observable(
                name="Protection Name",
                type_id=ObservableTypeId.OTHER,
                value=raw["protection_name"],
            )
        )

    title = first(raw, "protection_name", "attack_info", "rule_name", default="Check Point Log")

    return IntermediateAlert(
        source_id=SOURCE_ID,
        vendor_name=VENDOR_NAME,
        product_name=first(raw, "product", default=PRODUCT_NAME),
        alert_id=str(first(raw, "uuid", "id", "rule_uid", "time")),
        title=title,
        description=first(raw, "attack_info", "description", "malware_action"),
        severity_id=_severity(raw.get("severity")),
        native_severity=raw.get("severity"),
        event_time=to_epoch_ms(first(raw, "time", "received_time")),
        activity_id=ActivityId.CREATE,
        status_id=StatusId.NEW,
        message=first(raw, "attack_info", "action", "protection_name"),
        confidence_id=_confidence_id(raw.get("confidence_level")),
        src_endpoint=_endpoint(raw.get("src")),
        dst_endpoint=_endpoint(raw.get("dst"), first(raw, "service", "dst_port")),
        actor_user=first(raw, "src_user_name", "user"),
        device_hostname=first(raw, "origin", "orig"),
        rule_name=first(raw, "rule_name", "smartdefense_profile", "product"),
        rule_uid=raw.get("rule_uid"),
        observables=observables,
        raw=raw,
    )
