from __future__ import annotations

import hashlib
import json
import platform
import socket
from dataclasses import asdict, dataclass, field
from typing import Any
from uuid import uuid4

from mac_audit_agent.models import utc_now_iso
from mac_audit_agent.storage import json_safe


def _id(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex[:12]}"


@dataclass
class ProcessArtifact:
    pid: int | None = None
    name: str = ""
    path: str = ""
    cmdline: str = ""
    user: str = ""
    signature_status: str = "unknown"
    risk_indicator: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class NetworkArtifact:
    local_address: str = ""
    remote_address: str = ""
    port: str = ""
    process: str = ""
    pid: int | None = None
    state: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FileArtifact:
    path: str = ""
    hash: str = ""
    permissions: str = ""
    owner: str = ""
    modified_time: str = ""
    risk_flag: str = ""
    source: str = "msaa"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PersistenceArtifact:
    mechanism: str = ""
    path: str = ""
    launch_item: str = ""
    risk_score: int = 0
    source: str = "msaa_persistence_intelligence"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class LiveResponseSnapshot:
    snapshot_id: str = field(default_factory=lambda: _id("lrsnap"))
    timestamp: str = field(default_factory=utc_now_iso)
    hostname: str = field(default_factory=socket.gethostname)
    os_version: str = field(default_factory=lambda: platform.mac_ver()[0] or platform.platform())
    collection_scope: str = "quick"
    collectors_used: list[str] = field(default_factory=list)
    process_artifacts: list[ProcessArtifact] = field(default_factory=list)
    network_artifacts: list[NetworkArtifact] = field(default_factory=list)
    file_system_artifacts: list[FileArtifact] = field(default_factory=list)
    persistence_artifacts: list[PersistenceArtifact] = field(default_factory=list)
    user_session_artifacts: list[dict[str, Any]] = field(default_factory=list)
    security_artifacts: list[dict[str, Any]] = field(default_factory=list)
    diagnostics: dict[str, Any] = field(default_factory=dict)
    evidence_hash: str = ""
    integrity_status: str = "unknown"
    source: str = "live_response_collector"
    linked_case_id: str = ""

    def compute_evidence_hash(self) -> str:
        payload = self.to_dict(include_hash=False)
        stable = json.dumps(json_safe(payload), sort_keys=True, separators=(",", ":"))
        self.evidence_hash = hashlib.sha256(stable.encode("utf-8")).hexdigest()
        self.integrity_status = "hashed"
        return self.evidence_hash

    def artifact_counts(self) -> dict[str, int]:
        return {
            "processes": len(self.process_artifacts),
            "network": len(self.network_artifacts),
            "files": len(self.file_system_artifacts),
            "persistence": len(self.persistence_artifacts),
            "user_sessions": len(self.user_session_artifacts),
            "security": len(self.security_artifacts),
        }

    def to_dict(self, *, include_hash: bool = True) -> dict[str, Any]:
        payload = {
            "snapshot_id": self.snapshot_id,
            "timestamp": self.timestamp,
            "hostname": self.hostname,
            "os_version": self.os_version,
            "collection_scope": self.collection_scope,
            "collectors_used": list(self.collectors_used),
            "process_artifacts": [item.to_dict() for item in self.process_artifacts],
            "network_artifacts": [item.to_dict() for item in self.network_artifacts],
            "file_system_artifacts": [item.to_dict() for item in self.file_system_artifacts],
            "persistence_artifacts": [item.to_dict() for item in self.persistence_artifacts],
            "user_session_artifacts": list(self.user_session_artifacts),
            "security_artifacts": list(self.security_artifacts),
            "diagnostics": dict(self.diagnostics),
            "integrity_status": self.integrity_status,
            "source": self.source,
            "linked_case_id": self.linked_case_id,
            "artifact_counts": self.artifact_counts(),
        }
        if include_hash:
            payload["evidence_hash"] = self.evidence_hash
        return payload
