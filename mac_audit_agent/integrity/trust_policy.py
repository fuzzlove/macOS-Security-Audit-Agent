from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from mac_audit_agent.compat.datetime_compat import utc_now

from mac_audit_agent.integrity.manifest_paths import integrity_manifest_paths


@dataclass(slots=True)
class EnrolledYubiKey:
    yubikey_id: str
    label: str
    owner_developer_id: str
    public_key_pem: str = ""
    certificate_pem: str = ""
    certificate_fingerprint_sha256: str = ""
    piv_slot: str = "9c"
    serial_hash: str = ""
    attestation_certificate_fingerprint: str = ""
    status: str = "active"
    created_at: str = ""


@dataclass(slots=True)
class TrustPolicy:
    policy_version: str = "1"
    project_name: str = "macOS Security Audit Agent"
    required_signature_quorum: dict[str, Any] = field(default_factory=lambda: {"mode": "all_required", "required_count": 2})
    enrolled_yubikeys: list[EnrolledYubiKey] = field(default_factory=list)
    allowed_developer_ids: list[str] = field(default_factory=lambda: ["liquidsky"])
    signing_algorithm: str = "piv_ecdsa_p256_sha256"
    pkcs11_provider: str = "ykcs11"
    require_pin: bool = True
    require_touch: bool = True
    require_distinct_devices: bool = True
    require_manifest_hash_binding: bool = True
    require_git_commit_binding: bool = True
    require_build_id_binding: bool = True
    source_exclusion_policy_id: str = "msaa-source-exclusions-v1"
    created_at: str = ""
    updated_at: str = ""
    require_codex_provenance_for_manifest_update: bool = False

    @property
    def required_count(self) -> int:
        return int(self.required_signature_quorum.get("required_count", 2))

    def active_yubikeys(self) -> list[EnrolledYubiKey]:
        return [key for key in self.enrolled_yubikeys if key.status == "active"]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["enrolled_yubikeys"] = [asdict(key) for key in self.enrolled_yubikeys]
        return data


def utc_now_iso() -> str:
    return utc_now().replace(microsecond=0).isoformat().replace("+00:00", "Z")


def default_trust_policy() -> TrustPolicy:
    now = utc_now_iso()
    return TrustPolicy(created_at=now, updated_at=now)


def load_trust_policy(root: Path | None = None, path: Path | None = None) -> TrustPolicy:
    policy_path = Path(path) if path else integrity_manifest_paths(root).canonical_trust_policy
    if not policy_path.exists():
        return default_trust_policy()
    payload = json.loads(policy_path.read_text(encoding="utf-8"))
    yubikeys = [EnrolledYubiKey(**item) for item in payload.get("enrolled_yubikeys", [])]
    payload = {key: value for key, value in payload.items() if key != "enrolled_yubikeys"}
    return TrustPolicy(enrolled_yubikeys=yubikeys, **payload)


def write_trust_policy(policy: TrustPolicy, root: Path | None = None, path: Path | None = None) -> Path:
    policy_path = Path(path) if path else integrity_manifest_paths(root).canonical_trust_policy
    policy_path.parent.mkdir(parents=True, exist_ok=True)
    policy.updated_at = utc_now_iso()
    policy_path.write_text(json.dumps(policy.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return policy_path


__all__ = ["EnrolledYubiKey", "TrustPolicy", "default_trust_policy", "load_trust_policy", "write_trust_policy"]
