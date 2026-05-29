"""Zscaler Internet Access (ZIA) parser.

ZIA web/threat logs (NSS feed) use lowercase field names such as ``clientip`` /
``serverip``, ``url`` / ``urlcategory``, ``threatname`` / ``threatcategory``,
``action``, ``user``, and a numeric ``riskscore`` (0-100).

ZIA has no Informational..Critical severity column, so severity is normalised from
``riskscore`` (native -> OCSF severity_id):
    0      Informational -> 1
    1-39   Low           -> 2
    40-69  Medium        -> 3
    70-89  High          -> 4
    90-100 Critical      -> 5

These map to the OCSF *Detection Finding* class. A network-oriented OCSF mapping
(Network Activity, class 4001) is noted as a documented stretch in the README.
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

SOURCE_ID = "zscaler_zia"
VENDOR_NAME = "Zscaler"
PRODUCT_NAME = "Zscaler Internet Access"


def detect(raw: dict[str, Any]) -> bool:
    return "urlcategory" in raw and ("clientip" in raw or "cip" in raw)


def _severity(value: Any) -> SeverityId:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return SeverityId.UNKNOWN
    if n <= 0:
        return SeverityId.INFORMATIONAL
    if n < 40:
        return SeverityId.LOW
    if n < 70:
        return SeverityId.MEDIUM
    if n < 90:
        return SeverityId.HIGH
    return SeverityId.CRITICAL


def parse(raw: dict[str, Any]) -> IntermediateAlert:
    observables: list[Observable] = []
    if raw.get("url"):
        observables.append(
            Observable(name="URL", type_id=ObservableTypeId.URL_STRING, value=raw["url"])
        )
    if raw.get("host"):
        observables.append(
            Observable(name="Hostname", type_id=ObservableTypeId.HOSTNAME, value=raw["host"])
        )

    client_ip = first(raw, "clientip", "cip")
    server_ip = first(raw, "serverip", "sip")

    return IntermediateAlert(
        source_id=SOURCE_ID,
        vendor_name=VENDOR_NAME,
        product_name=PRODUCT_NAME,
        alert_id=str(first(raw, "recordid", "transactionid", "epochtime")),
        title=first(raw, "threatname", "reason", "ruleName", default="ZIA Web Transaction"),
        description=first(raw, "reason", "threatcategory"),
        severity_id=_severity(raw.get("riskscore")),
        native_severity=str(raw.get("riskscore")) if raw.get("riskscore") is not None else None,
        event_time=to_epoch_ms(first(raw, "epochtime", "datetime", "time")),
        activity_id=ActivityId.CREATE,
        status_id=StatusId.NEW,
        message=first(raw, "reason", "action"),
        src_endpoint=Endpoint(ip=client_ip) if client_ip else None,
        dst_endpoint=Endpoint(ip=server_ip) if server_ip else None,
        actor_user=raw.get("user"),
        device_hostname=raw.get("host"),
        rule_name=first(raw, "ruletype", "urlcategory", "threatcategory"),
        observables=observables,
        raw=raw,
    )
