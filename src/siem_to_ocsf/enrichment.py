"""Enrichment hook.

This is the seam where a real pipeline attaches identity, asset, and geo/threat-intel
context at ingestion time — exactly where you'd call into an IPAM/CMDB, an identity
provider, or a TI platform. To keep the seam *demonstrable* rather than hypothetical,
:func:`enrich` ships one working, fully synthetic example: it classifies each endpoint
IP as internal (RFC1918 / loopback / link-local) vs external, and attaches a synthetic
geo/ASN placeholder for external addresses.

Enrichments are emitted as OCSF ``enrichment`` objects (``name``/``value``/``data``)
and ride along on the finding under the top-level ``enrichments`` array, so downstream
consumers can see provenance without the values being baked into core fields.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from siem_to_ocsf.models import IntermediateAlert

PROVIDER = "siem-to-ocsf:demo-enrichment"

# "Internal" is defined explicitly as RFC1918 / loopback / link-local / unique-local
# rather than via ipaddress.is_private. Python 3.12.4+ folded the IANA special-purpose
# ranges (incl. the RFC5737 TEST-NET documentation blocks this project uses to stand in
# for public addresses) into is_private, which would mislabel those synthetic "external"
# IPs as internal. This explicit set keeps the corp-vs-internet classification correct.
_INTERNAL_NETS = tuple(
    ipaddress.ip_network(c)
    for c in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
)


def _ip_scope(ip: str) -> str | None:
    """Return 'internal' / 'external' for a valid IP, or None if unparseable."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return "internal" if any(addr in net for net in _INTERNAL_NETS) else "external"


def _synthetic_geo(ip: str) -> dict[str, Any]:
    """A deterministic, obviously-synthetic geo/ASN stub for external IPs.

    Real deployments would replace this body with a MaxMind/IPinfo/TI lookup. The
    output is derived from the address bytes so it is stable across runs (good for
    golden tests) and clearly fake.
    """
    packed = ipaddress.ip_address(ip).packed
    bucket = packed[-1] % 3
    regions = [
        {"country": "ZZ", "region": "Example-Region-A"},
        {"country": "ZZ", "region": "Example-Region-B"},
        {"country": "ZZ", "region": "Example-Region-C"},
    ]
    geo = dict(regions[bucket])
    geo["asn"] = f"AS{64500 + bucket}"  # RFC 5398 documentation ASN range
    geo["note"] = "synthetic"
    return geo


def enrich(alert: IntermediateAlert) -> IntermediateAlert:
    """Attach synthetic context to an alert in place and return it.

    Idempotency is not assumed; call once per record in the pipeline.
    """
    endpoints = [
        ("src_endpoint", alert.src_endpoint),
        ("dst_endpoint", alert.dst_endpoint),
    ]
    for role, ep in endpoints:
        if ep is None or ep.ip is None:
            continue
        scope = _ip_scope(ep.ip)
        if scope is None:
            continue
        data: dict[str, Any] = {"ip": ep.ip, "role": role, "scope": scope}
        if scope == "external":
            data["geo"] = _synthetic_geo(ep.ip)
        alert.enrichments.append(
            {
                "name": "ip_scope",
                "value": scope,
                "data": data,
                "provider": PROVIDER,
                "type": "network",
            }
        )
    return alert
