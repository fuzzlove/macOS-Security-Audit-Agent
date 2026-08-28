from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any
from uuid import uuid4

from mac_audit_agent.models import utc_now_iso


@dataclass(frozen=True)
class CredentialFinding:
    finding_id: str
    scan_id: str
    detected_at: str
    target_url: str
    host: str
    port: int
    scheme: str
    product: str
    category: str
    path: str
    cpe: str
    username: str
    password: str
    severity: str = "critical"
    confidence: str = "high"
    status: str = "open"
    source: str = "nmap:http-default-accounts"
    recommendation: str = "Change the default credential, revoke active sessions, restrict management access, and verify the replacement credential through the approved secrets-management process."

    @classmethod
    def create(cls, *, scan_id: str, target_url: str, host: str, port: int, scheme: str,
               product: str, category: str, path: str, cpe: str, username: str,
               password: str) -> CredentialFinding:
        return cls(
            f"default-credential-{uuid4().hex}", scan_id, utc_now_iso(), target_url,
            host, port, scheme, product, category, path, cpe, username, password,
        )

    @property
    def masked_password(self) -> str:
        if not self.password:
            return "<blank>"
        return "•" * min(max(len(self.password), 6), 16)

    def to_dict(self, *, reveal_password: bool = False) -> dict[str, Any]:
        payload = asdict(self)
        payload["password"] = self.password if reveal_password else self.masked_password
        payload["credential_exposure"] = "plaintext export" if reveal_password else "redacted"
        return payload


@dataclass(frozen=True)
class TargetResult:
    target_url: str
    status: str
    finding_count: int
    duration_seconds: float
    command_redacted: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CredentialScanReport:
    scan_id: str
    started_at: str
    completed_at: str
    authorization_reference: str
    fingerprint_sha256: str
    nmap_version: str
    target_results: tuple[TargetResult, ...] = ()
    findings: tuple[CredentialFinding, ...] = ()
    errors: tuple[str, ...] = ()
    schema_version: str = "1.0"
    qualification: str = "An accepted default credential proves that the tested credential worked at collection time. It does not establish compromise, attribution, or whether the account was previously used."

    def to_dict(self, *, reveal_passwords: bool = False) -> dict[str, Any]:
        payload = asdict(self)
        payload["target_results"] = [item.to_dict() for item in self.target_results]
        payload["findings"] = [item.to_dict(reveal_password=reveal_passwords) for item in self.findings]
        return payload
