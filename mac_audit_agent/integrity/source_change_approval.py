from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from mac_audit_agent.integrity.dev_manifest import git_output, utc_now_iso
from mac_audit_agent.integrity.signing import calculate_file_sha256


APPROVAL_RECORD_PATH = Path("mac_audit_agent/integrity/approved_source_changes.jsonl")


@dataclass(slots=True)
class SourceChangeApprovalRecord:
    approval_id: str
    approved_at: str
    approved_by: str
    reason: str
    build_id: str
    git_commit: str
    changed_files: list[str]
    old_hashes: dict[str, str] = field(default_factory=dict)
    new_hashes: dict[str, str] = field(default_factory=dict)
    codex_provenance_id: str = ""
    command: str = ""
    policy: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def write_source_change_approval(
    root: Path,
    *,
    approved_by: str,
    reason: str,
    build_id: str,
    changed_files: list[str],
    policy: str,
    command: str,
    old_hashes: dict[str, str] | None = None,
    codex_provenance_id: str = "",
) -> SourceChangeApprovalRecord:
    root = Path(root).resolve(strict=False)
    new_hashes = {
        rel: calculate_file_sha256(root / rel)
        for rel in changed_files
        if (root / rel).exists() and (root / rel).is_file()
    }
    record = SourceChangeApprovalRecord(
        approval_id=f"source-approval-{uuid.uuid4().hex}",
        approved_at=utc_now_iso(),
        approved_by=approved_by,
        reason=reason,
        build_id=build_id,
        git_commit=git_output(["rev-parse", "HEAD"], root),
        changed_files=sorted(set(changed_files)),
        old_hashes=old_hashes or {},
        new_hashes=new_hashes,
        codex_provenance_id=codex_provenance_id,
        command=command,
        policy=policy,
    )
    path = root / APPROVAL_RECORD_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record.to_dict(), sort_keys=True) + "\n")
    return record


__all__ = ["APPROVAL_RECORD_PATH", "SourceChangeApprovalRecord", "write_source_change_approval"]
