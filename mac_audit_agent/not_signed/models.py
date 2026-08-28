from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Mapping


class SoftwareTrustClassification(str, Enum):
    APPLE_PLATFORM = "apple_platform"
    MAC_APP_STORE = "mac_app_store"
    DEVELOPER_ID_NOTARIZED = "developer_id_notarized"
    DEVELOPER_ID_VALID = "developer_id_valid"
    AD_HOC = "ad_hoc"
    UNSIGNED = "unsigned"
    INVALID = "invalid"
    REVOKED = "revoked"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class SigningAssessment:
    classification: SoftwareTrustClassification
    signature_valid: bool | None
    gatekeeper_accepted: bool | None
    notarized: bool | None
    app_store_provenance: str = "unknown"
    signing_identifier: str | None = None
    team_identifier: str | None = None
    authorities: tuple[str, ...] = ()
    cdhash: str | None = None
    hardened_runtime: bool | None = None
    entitlements: Mapping[str, object] = field(default_factory=dict)
    assessment_errors: tuple[str, ...] = ()
    assessed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    raw_evidence: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class ProcessRecord:
    pid: int
    ppid: int
    name: str
    executable_path: Path
    user: str
    start_time: str = ""
    arguments: str = ""
    architecture: str = ""
    deleted_executable: bool = False
    privileged: bool = False


@dataclass(frozen=True)
class PersistenceRecord:
    kind: str
    path: Path
    label: str
    executable_path: Path | None
    enabled: bool = True
    confidence: str = "confirmed"


@dataclass(frozen=True)
class AssociatedFileRecord:
    path: Path
    category: str
    confidence: str
    reason: str
    selected_by_default: bool = False
    user_data: bool = False


@dataclass(frozen=True)
class InstalledSoftwareItem:
    item_id: str
    display_name: str
    executable_path: Path
    bundle_path: Path | None
    bundle_identifier: str | None
    version: str | None
    icon_path: Path | None
    signing: SigningAssessment
    running_processes: tuple[ProcessRecord, ...] = ()
    persistence_items: tuple[PersistenceRecord, ...] = ()
    associated_files: tuple[AssociatedFileRecord, ...] = ()
    severity: str = "informational"
    risk_reasons: tuple[str, ...] = ()
    source: str = "unknown"
    size_bytes: int = 0
    modified_at: str = ""
    protected: bool = False
    protection_reason: str = ""
    user_disposition: str = "review"

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["executable_path"] = str(self.executable_path)
        payload["bundle_path"] = str(self.bundle_path) if self.bundle_path else None
        payload["icon_path"] = str(self.icon_path) if self.icon_path else None
        payload["signing"]["classification"] = self.signing.classification.value
        payload["signing"]["assessed_at"] = self.signing.assessed_at.isoformat()
        return payload


@dataclass(frozen=True)
class RemovalPlan:
    plan_id: str
    item_id: str
    display_name: str
    executable_hash: str
    processes: tuple[ProcessRecord, ...]
    persistence: tuple[PersistenceRecord, ...]
    selected_files: tuple[AssociatedFileRecord, ...]
    excluded_files: tuple[AssociatedFileRecord, ...]
    requires_admin: bool
    privileged_available: bool
    reversible: bool
    estimated_bytes: int
    warnings: tuple[str, ...]
    created_at: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)
