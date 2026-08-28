from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import uuid4


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ProviderState(StrEnum):
    UNKNOWN = "UNKNOWN"
    RESOLVING = "RESOLVING"
    UNQUALIFIED = "UNQUALIFIED"
    QUALIFYING = "QUALIFYING"
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"
    DISABLED = "DISABLED"


@dataclass(frozen=True)
class RetryPolicy:
    attempts: int = 1
    delay_seconds: float = 0.25


@dataclass(frozen=True)
class EgressService:
    service_id: str
    hostname: str
    port: int | None
    transport: str
    validation_type: str
    port_range: tuple[int, int] | None = None
    ip_versions: frozenset[int] = frozenset({4, 6})
    timeout_seconds: float = 2.0
    retry_policy: RetryPolicy = RetryPolicy()

    def validate(self) -> None:
        if self.transport not in {"tcp", "udp", "tls", "mtls"}:
            raise ValueError("unsupported egress transport")
        if self.port is not None and not 1 <= self.port <= 65535:
            raise ValueError("service port must be between 1 and 65535")
        if self.port_range and (self.port_range[0] < 1 or self.port_range[1] > 65535 or self.port_range[0] > self.port_range[1]):
            raise ValueError("invalid service port range")
        if self.timeout_seconds < 0.1 or self.timeout_seconds > 30:
            raise ValueError("service timeout is outside the safe range")


@dataclass(frozen=True)
class Provider:
    provider_id: str
    name: str
    hostname: str
    protocols: tuple[str, ...]
    source_url: str
    description: str
    license_note: str = "External testing service; review provider terms before use."
    enabled_by_default: bool = False
    qualification_required: bool = False
    capabilities: frozenset[str] = frozenset()
    services: tuple[EgressService, ...] = ()
    initial_state: ProviderState = ProviderState.UNQUALIFIED


@dataclass(frozen=True)
class EgressProbe:
    port: int
    protocol: str = "tcp"

    def validate(self) -> None:
        if not 1 <= int(self.port) <= 65535:
            raise ValueError("port must be between 1 and 65535")
        if self.protocol != "tcp":
            raise ValueError("the compatibility probe engine currently accepts tcp only; use a provider service for udp/tls/mtls")


@dataclass(frozen=True)
class EgressResult:
    probe_id: str
    port: int
    protocol: str
    status: str
    started_at: str
    completed_at: str
    latency_ms: float | None
    resolved_addresses: tuple[str, ...]
    error_code: str
    evidence_sha256: str
    hostname: str = ""
    resolved_ip: str = ""
    ip_version: int | None = None
    transport_connected: bool = False
    response_validated: bool = False
    rir: str = "UNKNOWN"
    asn: int | None = None
    prefix: str | None = None
    provider_health: str = ProviderState.UNQUALIFIED.value
    outcome: str = "INCONCLUSIVE"


@dataclass
class EgressRun:
    run_id: str
    schema_version: str
    started_at: str
    completed_at: str
    provider: Provider
    authorization_reference: str
    target_scope: str
    results: list[EgressResult] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    source_methodology: list[dict[str, str]] = field(default_factory=list)
    configuration: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(cls, provider: Provider, authorization_reference: str, target_scope: str) -> "EgressRun":
        return cls(str(uuid4()), "msaa.network-segmentation.v1", utc_now(), "", provider, authorization_reference, target_scope)

    def to_dict(self) -> dict[str, Any]:
        return _json_safe(asdict(self))


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (tuple, list, set, frozenset)):
        return [_json_safe(item) for item in value]
    if isinstance(value, StrEnum):
        return value.value
    return value
