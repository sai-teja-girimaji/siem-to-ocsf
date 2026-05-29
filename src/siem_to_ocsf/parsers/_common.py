"""Helpers shared across parsers (time normalisation, MITRE parsing, lookups)."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

_MITRE_RE = re.compile(r"\s*(?P<uid>T[A?]?\d[\w.]*)\s*[-:]\s*(?P<name>.+?)\s*$", re.IGNORECASE)


def to_epoch_ms(value: Any) -> int:
    """Normalise a vendor timestamp to epoch milliseconds (the OCSF time base).

    Accepts:
      * int/float epoch in seconds (10-digit) or milliseconds (13-digit)
      * ISO-8601 strings, including a trailing 'Z'
    Raises ValueError if it cannot be interpreted.
    """
    if isinstance(value, bool):  # bool is an int subclass; reject explicitly
        raise ValueError(f"invalid timestamp: {value!r}")
    if isinstance(value, (int, float)):
        v = float(value)
        # < 1e12 => seconds (anything up to year ~33658 in seconds); else milliseconds.
        return int(v * 1000) if v < 1e12 else int(v)
    if isinstance(value, str):
        s = value.strip()
        if s.isdigit():
            return to_epoch_ms(int(s))
        iso = s.replace("Z", "+00:00")
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return int(dt.timestamp() * 1000)
    raise ValueError(f"unsupported timestamp type: {type(value).__name__}")


def split_mitre(value: str | None) -> tuple[str | None, str | None]:
    """Split a 'T1059.001 - PowerShell' / 'TA0002: Execution' string into (uid, name)."""
    if not value:
        return None, None
    m = _MITRE_RE.match(value)
    if not m:
        return value.strip() or None, None
    return m.group("uid").upper(), m.group("name").strip() or None


def first(raw: dict[str, Any], *keys: str, default: Any = None) -> Any:
    """Return the first present, non-empty value among ``keys``."""
    for k in keys:
        if k in raw and raw[k] not in (None, "", []):
            return raw[k]
    return default
