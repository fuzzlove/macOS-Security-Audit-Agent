from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from mac_audit_agent.compat.datetime_compat import utc_now


DEVELOPER_IDENTITIES_RELATIVE_PATH = Path("mac_audit_agent/integrity/developer_identities.json")


@dataclass(slots=True)
class DeveloperIdentity:
    developer_id: str
    display_name: str
    organization: str
    email: str = ""
    github_username: str = ""
    git_signing_key_fingerprint: str = ""
    codex_operator_label: str = ""
    codex_account_reference: str = ""
    codex_identity_verification: str = "metadata_only"
    allowed_roles: list[str] = field(default_factory=lambda: ["developer", "release_manager", "integrity_approver"])
    enrolled_yubikey_ids: list[str] = field(default_factory=list)
    created_at: str = ""
    status: str = "active"


def utc_now_iso() -> str:
    return utc_now().replace(microsecond=0).isoformat().replace("+00:00", "Z")


def default_developer_identities() -> list[DeveloperIdentity]:
    return [
        DeveloperIdentity(
            developer_id="liquidsky",
            display_name="Liquidsky Network Security",
            organization="Liquidsky Network Security",
            created_at=utc_now_iso(),
        )
    ]


def identities_path(root: Path | None = None) -> Path:
    return Path(root or Path.cwd()).resolve(strict=False) / DEVELOPER_IDENTITIES_RELATIVE_PATH


def load_developer_identities(root: Path | None = None, path: Path | None = None) -> list[DeveloperIdentity]:
    target = Path(path) if path else identities_path(root)
    if not target.exists():
        return default_developer_identities()
    payload = json.loads(target.read_text(encoding="utf-8"))
    records = payload.get("developer_identities", payload if isinstance(payload, list) else [])
    return [DeveloperIdentity(**item) for item in records]


def write_developer_identities(identities: list[DeveloperIdentity], root: Path | None = None, path: Path | None = None) -> Path:
    target = Path(path) if path else identities_path(root)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = {"developer_identities": [asdict(identity) for identity in identities]}
    target.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target


def active_developer_ids(root: Path | None = None) -> set[str]:
    return {identity.developer_id for identity in load_developer_identities(root) if identity.status == "active"}


__all__ = [
    "DEVELOPER_IDENTITIES_RELATIVE_PATH",
    "DeveloperIdentity",
    "active_developer_ids",
    "default_developer_identities",
    "load_developer_identities",
    "write_developer_identities",
]
