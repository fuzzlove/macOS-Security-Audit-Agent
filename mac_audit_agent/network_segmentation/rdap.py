from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

RIRS = {"ARIN", "RIPE NCC", "APNIC", "AFRINIC", "LACNIC", "UNKNOWN"}


@dataclass(frozen=True)
class RdapClassification:
    rir: str = "UNKNOWN"
    authoritative_server: str = ""
    asn: int | None = None
    prefix: str | None = None
    network_handle: str = ""
    organization: str = ""
    country: str = ""
    checked_at: str = ""
    referral_chain: tuple[str, ...] = ()
    error: str = ""
    cached: bool = False


def parse_rdap(payload: dict[str, Any], *, server: str = "", cached: bool = False) -> RdapClassification:
    """Parse supplied RDAP evidence without inferring registry from geography or DNS."""
    port43 = str(payload.get("port43", "")).lower()
    notices = " ".join(str(item) for item in payload.get("notices", ())).lower()
    text = f"{server.lower()} {port43} {notices}"
    if "arin" in text: rir = "ARIN"
    elif "ripe" in text: rir = "RIPE NCC"
    elif "apnic" in text: rir = "APNIC"
    elif "afrinic" in text: rir = "AFRINIC"
    elif "lacnic" in text: rir = "LACNIC"
    else: rir = "UNKNOWN"
    cidr = payload.get("cidr0_cidrs") or []
    prefix = None
    if cidr and isinstance(cidr[0], dict):
        prefix = f"{cidr[0].get('v4prefix') or cidr[0].get('v6prefix')}/{cidr[0].get('length')}"
    return RdapClassification(rir, server, payload.get("asn"), prefix, str(payload.get("handle", "")), str(payload.get("name", "")), str(payload.get("country", "")), datetime.now(timezone.utc).isoformat(), tuple(str(link.get("href", "")) for link in payload.get("links", ()) if isinstance(link, dict)), cached=cached)


def filter_by_rir(classifications: dict[str, RdapClassification], requested_rir: str) -> tuple[str, ...]:
    if requested_rir not in RIRS - {"UNKNOWN"}:
        raise ValueError("unsupported RIR filter")
    matches = tuple(address for address, item in classifications.items() if item.rir == requested_rir)
    if not matches:
        raise LookupError("NO_QUALIFIED_DESTINATION_FOR_RIR")
    return matches
