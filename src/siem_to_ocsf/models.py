"""Data models.

Two layers live here:

* The **intermediate model** (`IntermediateAlert` and friends) is the vendor-neutral
  shape every parser produces. Adding a new source means writing a parser that returns
  one of these — nothing in the core changes.
* The **OCSF output model** (`DetectionFinding` and friends) is a typed, validated
  representation of the OCSF 1.8.0 *Detection Finding* class subset we populate. It is
  the construction-time guardrail; the authoritative conformance check is the JSON
  Schema validation in :mod:`siem_to_ocsf.ocsf`.

All OCSF enum integer values here are taken from the pinned OCSF 1.8.0 schema, not
invented. See ``schema/PROVENANCE.md``.
"""

from __future__ import annotations

from enum import IntEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# ---------------------------------------------------------------------------
# OCSF enumerations (values verified against OCSF 1.8.0 detection_finding schema)
# ---------------------------------------------------------------------------


class SeverityId(IntEnum):
    """OCSF base-event ``severity_id``."""

    UNKNOWN = 0
    INFORMATIONAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5
    FATAL = 6
    OTHER = 99


class StatusId(IntEnum):
    """OCSF ``status_id`` for Detection Finding."""

    UNKNOWN = 0
    NEW = 1
    IN_PROGRESS = 2
    SUPPRESSED = 3
    RESOLVED = 4
    ARCHIVED = 5
    DELETED = 6
    OTHER = 99


class ActivityId(IntEnum):
    """OCSF Detection Finding ``activity_id``."""

    UNKNOWN = 0
    CREATE = 1
    UPDATE = 2
    CLOSE = 3
    OTHER = 99


class ObservableTypeId(IntEnum):
    """Subset of OCSF ``observable.type_id`` values used by this project."""

    UNKNOWN = 0
    HOSTNAME = 1
    IP_ADDRESS = 2
    MAC_ADDRESS = 3
    USER_NAME = 4
    EMAIL_ADDRESS = 5
    URL_STRING = 6
    FILE_NAME = 7
    HASH = 8
    PROCESS_NAME = 9
    RESOURCE_UID = 10
    OTHER = 99


# Human-readable captions, matching the OCSF dictionary.
SEVERITY_CAPTION: dict[int, str] = {
    0: "Unknown",
    1: "Informational",
    2: "Low",
    3: "Medium",
    4: "High",
    5: "Critical",
    6: "Fatal",
    99: "Other",
}

STATUS_CAPTION: dict[int, str] = {
    0: "Unknown",
    1: "New",
    2: "In Progress",
    3: "Suppressed",
    4: "Resolved",
    5: "Archived",
    6: "Deleted",
    99: "Other",
}

ACTIVITY_CAPTION: dict[int, str] = {
    0: "Unknown",
    1: "Create",
    2: "Update",
    3: "Close",
    99: "Other",
}

OBSERVABLE_CAPTION: dict[int, str] = {
    0: "Unknown",
    1: "Hostname",
    2: "IP Address",
    3: "MAC Address",
    4: "User Name",
    5: "Email Address",
    6: "URL String",
    7: "File Name",
    8: "Hash",
    9: "Process Name",
    10: "Resource UID",
    99: "Other",
}


# ---------------------------------------------------------------------------
# Intermediate model (vendor-neutral)
# ---------------------------------------------------------------------------


class Endpoint(BaseModel):
    """A network endpoint as seen in a raw alert."""

    model_config = ConfigDict(extra="forbid")

    ip: str | None = None
    hostname: str | None = None
    port: int | None = None

    def is_empty(self) -> bool:
        return self.ip is None and self.hostname is None and self.port is None


class Observable(BaseModel):
    """A domain-specific observable a parser chooses to surface (hash, URL, file...)."""

    model_config = ConfigDict(extra="forbid")

    name: str
    type_id: ObservableTypeId
    value: str


class MitreTechnique(BaseModel):
    """A single MITRE ATT&CK technique/tactic reference."""

    model_config = ConfigDict(extra="forbid")

    technique_uid: str | None = None
    technique_name: str | None = None
    tactic_uid: str | None = None
    tactic_name: str | None = None


class IntermediateAlert(BaseModel):
    """Vendor-neutral alert. Every parser produces one of these.

    The parser is responsible for normalising the vendor's native severity scale into
    an OCSF :class:`SeverityId` (keep the original string in ``native_severity`` for
    traceability). The OCSF mapper never re-interprets vendor severities.
    """

    model_config = ConfigDict(extra="forbid")

    # Provenance / product
    source_id: str = Field(description="Parser key, e.g. 'cortex_xdr'")
    vendor_name: str = Field(description="OCSF metadata.product.vendor_name")
    product_name: str = Field(description="OCSF metadata.product.name")
    product_version: str | None = None

    # Core finding
    alert_id: str
    title: str
    description: str | None = None
    severity_id: SeverityId
    native_severity: str | None = None
    event_time: int = Field(description="Epoch milliseconds (OCSF time base)")
    activity_id: ActivityId = ActivityId.CREATE
    status_id: StatusId | None = None
    message: str | None = None
    confidence_id: int | None = None

    # Entities
    src_endpoint: Endpoint | None = None
    dst_endpoint: Endpoint | None = None
    actor_user: str | None = None
    device_hostname: str | None = None

    # Detection context
    rule_name: str | None = None
    rule_uid: str | None = None
    mitre: list[MitreTechnique] = Field(default_factory=list)
    observables: list[Observable] = Field(default_factory=list)

    # Pipeline-attached
    enrichments: list[dict[str, Any]] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# OCSF output model (Detection Finding 1.8.0 subset)
# ---------------------------------------------------------------------------


class _OCSFBase(BaseModel):
    # extra="forbid" mirrors the schema's additionalProperties:false, so a typo in a
    # field name fails loudly at construction rather than silently passing through.
    model_config = ConfigDict(extra="forbid")


class Product(_OCSFBase):
    vendor_name: str
    name: str
    version: str | None = None


class Metadata(_OCSFBase):
    version: str
    product: Product
    log_name: str | None = None
    original_time: str | None = None
    logged_time: int | None = None


class NetworkEndpoint(_OCSFBase):
    ip: str | None = None
    hostname: str | None = None
    port: int | None = None


class OCSFObservable(_OCSFBase):
    name: str
    type: str | None = None
    type_id: int
    value: str | None = None


class Technique(_OCSFBase):
    uid: str | None = None
    name: str | None = None


class Tactic(_OCSFBase):
    uid: str | None = None
    name: str | None = None


class Attack(_OCSFBase):
    technique: Technique | None = None
    tactic: Tactic | None = None
    version: str | None = None


class FindingInfo(_OCSFBase):
    uid: str
    title: str
    desc: str | None = None
    created_time: int | None = None
    types: list[str] | None = None
    attacks: list[Attack] | None = None


class Evidence(_OCSFBase):
    name: str | None = None
    src_endpoint: NetworkEndpoint | None = None
    dst_endpoint: NetworkEndpoint | None = None


class Enrichment(_OCSFBase):
    name: str
    value: str
    data: dict[str, Any]
    provider: str | None = None
    type: str | None = None


class DetectionFinding(_OCSFBase):
    """OCSF Detection Finding (class_uid 2004), subset populated by this tool."""

    # Classification (constants for this class)
    activity_id: int
    activity_name: str | None = None
    category_uid: int
    category_name: str | None = None
    class_uid: int
    class_name: str | None = None
    type_uid: int
    type_name: str | None = None

    # Occurrence + severity
    time: int
    time_dt: str | None = None
    severity_id: int
    severity: str | None = None
    status_id: int | None = None
    status: str | None = None
    confidence_id: int | None = None

    # Content
    message: str | None = None
    metadata: Metadata
    finding_info: FindingInfo
    observables: list[OCSFObservable] | None = None
    evidences: list[Evidence] | None = None
    enrichments: list[Enrichment] | None = None
    is_alert: bool | None = None
    count: int | None = None
    raw_data: str | None = None
