"""Microsoft Sentinel (SecurityAlert) parser.

Sentinel's ``SecurityAlert`` records use PascalCase columns: ``SystemAlertId``,
``AlertName``, ``AlertSeverity`` ("High"/"Medium"/"Low"/"Informational"),
``TimeGenerated`` (ISO-8601), ``Tactics``, ``Techniques``, ``Status``, and an
``Entities`` JSON array describing hosts/accounts/IPs.

Severity scale (native -> OCSF severity_id):
    Informational -> 1, Low -> 2, Medium -> 3, High -> 4
"""

from __future__ import annotations

import json
from typing import Any

from siem_to_ocsf.models import (
    ActivityId,
    Endpoint,
    IntermediateAlert,
    MitreTechnique,
    SeverityId,
    StatusId,
)
from siem_to_ocsf.parsers._common import first, to_epoch_ms

SOURCE_ID = "sentinel"
VENDOR_NAME = "Microsoft"
PRODUCT_NAME = "Microsoft Sentinel"

_SEVERITY: dict[str, SeverityId] = {
    "informational": SeverityId.INFORMATIONAL,
    "low": SeverityId.LOW,
    "medium": SeverityId.MEDIUM,
    "high": SeverityId.HIGH,
}

_STATUS: dict[str, StatusId] = {
    "new": StatusId.NEW,
    "inprogress": StatusId.IN_PROGRESS,
    "in progress": StatusId.IN_PROGRESS,
    "resolved": StatusId.RESOLVED,
    "dismissed": StatusId.SUPPRESSED,
}


def detect(raw: dict[str, Any]) -> bool:
    return "AlertName" in raw and ("AlertSeverity" in raw or "SystemAlertId" in raw)


def _severity(value: Any) -> SeverityId:
    return _SEVERITY.get(str(value).strip().lower(), SeverityId.UNKNOWN)


def _as_list(value: Any) -> list[Any]:
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        s = value.strip()
        if s.startswith("["):
            try:
                return json.loads(s)
            except json.JSONDecodeError:
                pass
        return [part.strip() for part in s.split(",") if part.strip()]
    return [value]


def _entities(raw: dict[str, Any]) -> dict[str, Any]:
    """Pull host / account / ip out of the Sentinel Entities array."""
    out: dict[str, Any] = {}
    for ent in _as_list(raw.get("Entities")):
        if not isinstance(ent, dict):
            continue
        etype = str(ent.get("Type", "")).lower()
        if etype == "host" and "host" not in out:
            out["host"] = ent.get("HostName") or ent.get("NetBiosName")
        elif etype == "account" and "account" not in out:
            name = ent.get("Name")
            domain = ent.get("NTDomain") or ent.get("UPNSuffix")
            out["account"] = f"{domain}\\{name}" if domain and name else name
        elif etype == "ip" and "ip" not in out:
            out["ip"] = ent.get("Address")
    return out


def parse(raw: dict[str, Any]) -> IntermediateAlert:
    mitre: list[MitreTechnique] = []
    techniques = _as_list(raw.get("Techniques"))
    tactics = _as_list(raw.get("Tactics"))
    for i in range(max(len(techniques), len(tactics))):
        tech = techniques[i] if i < len(techniques) else None
        tac = tactics[i] if i < len(tactics) else None
        mitre.append(
            MitreTechnique(
                technique_uid=str(tech) if tech else None,
                tactic_name=str(tac) if tac else None,
            )
        )

    ents = _entities(raw)
    src = Endpoint(ip=ents["ip"]) if ents.get("ip") else None

    return IntermediateAlert(
        source_id=SOURCE_ID,
        vendor_name=VENDOR_NAME,
        product_name=first(raw, "ProductName", default=PRODUCT_NAME),
        alert_id=str(first(raw, "SystemAlertId", "AlertName")),
        title=raw["AlertName"],
        description=raw.get("Description"),
        severity_id=_severity(raw.get("AlertSeverity")),
        native_severity=raw.get("AlertSeverity"),
        event_time=to_epoch_ms(first(raw, "TimeGenerated", "StartTime")),
        activity_id=ActivityId.CREATE,
        status_id=_STATUS.get(str(raw.get("Status", "")).strip().lower(), StatusId.NEW),
        message=first(raw, "Description", "AlertName"),
        src_endpoint=src,
        actor_user=first(raw, "CompromisedEntity") or ents.get("account"),
        device_hostname=ents.get("host"),
        rule_name=first(raw, "AlertType", "ProviderName"),
        mitre=mitre,
        raw=raw,
    )
