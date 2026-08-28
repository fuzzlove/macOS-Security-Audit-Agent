from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .models import ProviderState


@dataclass(frozen=True)
class QualificationRecord:
    provider_id: str
    state: ProviderState
    checked_at: datetime
    expires_at: datetime
    dns_ok: bool
    transport_ok: bool
    response_ok: bool
    rdap_ok: bool
    failure_reason: str = ""

    @property
    def expired(self) -> bool:
        return datetime.now(timezone.utc) >= self.expires_at


def qualification_state(*, dns_ok: bool, transport_ok: bool, response_ok: bool, rdap_ok: bool) -> ProviderState:
    if dns_ok and transport_ok and response_ok and rdap_ok:
        return ProviderState.HEALTHY
    if dns_ok and transport_ok:
        return ProviderState.DEGRADED
    return ProviderState.FAILED


def make_record(provider_id: str, *, dns_ok: bool, transport_ok: bool, response_ok: bool, rdap_ok: bool, healthy_ttl_hours: int = 24, degraded_ttl_hours: int = 4, failed_retry_minutes: int = 30, failure_reason: str = "") -> QualificationRecord:
    now = datetime.now(timezone.utc)
    state = qualification_state(dns_ok=dns_ok, transport_ok=transport_ok, response_ok=response_ok, rdap_ok=rdap_ok)
    ttl = timedelta(hours=healthy_ttl_hours if state is ProviderState.HEALTHY else degraded_ttl_hours) if state is not ProviderState.FAILED else timedelta(minutes=failed_retry_minutes)
    return QualificationRecord(provider_id, state, now, now + ttl, dns_ok, transport_ok, response_ok, rdap_ok, failure_reason)
