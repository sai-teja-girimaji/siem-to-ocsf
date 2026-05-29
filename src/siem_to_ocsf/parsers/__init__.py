"""Parser registry.

Each vendor parser is a module exposing three names:

* ``SOURCE_ID``                — stable key, e.g. ``"cortex_xdr"``
* ``detect(raw: dict) -> bool``— True if a raw record looks like this vendor's format
* ``parse(raw: dict) -> IntermediateAlert``

Adding a source = drop a module in this package and register it in ``_MODULES`` below.
Nothing else in the codebase changes.
"""

from __future__ import annotations

from types import ModuleType

from siem_to_ocsf.models import IntermediateAlert
from siem_to_ocsf.parsers import (
    checkpoint,
    cortex_xdr,
    fortisiem,
    logscale,
    sentinel,
    zscaler_zia,
)

_MODULES: tuple[ModuleType, ...] = (
    cortex_xdr,
    fortisiem,
    sentinel,
    logscale,
    zscaler_zia,
    checkpoint,
)

PARSERS: dict[str, ModuleType] = {m.SOURCE_ID: m for m in _MODULES}


class UnknownSourceError(ValueError):
    """Raised when a source key is not registered or cannot be auto-detected."""


def available_sources() -> list[str]:
    return sorted(PARSERS)


def get_parser(source_id: str) -> ModuleType:
    try:
        return PARSERS[source_id]
    except KeyError as exc:
        raise UnknownSourceError(
            f"unknown source '{source_id}'; known: {', '.join(available_sources())}"
        ) from exc


def detect_source(raw: dict) -> str | None:
    """Return the source_id whose parser claims this record, or None."""
    for module in _MODULES:
        try:
            if module.detect(raw):
                return module.SOURCE_ID
        except Exception:  # noqa: BLE001 - detection must never crash a run
            continue
    return None


def parse(raw: dict, source_id: str) -> IntermediateAlert:
    return get_parser(source_id).parse(raw)
