from __future__ import annotations

import json
import subprocess
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path

from mac_audit_agent.compat.datetime_compat import utc_now


CODEX_PROVENANCE_DIR = Path("mac_audit_agent/integrity/codex_provenance")


@dataclass(slots=True)
class CodexProvenanceRecord:
    codex_provenance_id: str
    created_at: str
    codex_operator_label: str
    prompt_summary: str
    files_changed: list[str] = field(default_factory=list)
    codex_account_reference: str = ""
    codex_identity_verification: str = "metadata_only"
    git_commit_before: str = ""
    git_commit_after: str = ""
    developer_reviewed_by: str = ""
    developer_reviewed_at: str = ""
    approved_change_id: str = ""
    notes: str = ""


def utc_now_iso() -> str:
    return utc_now().replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _git(root: Path, args: list[str]) -> str:
    try:
        result = subprocess.run(["git", *args], cwd=root, text=True, capture_output=True, check=False, timeout=10)
    except Exception:
        return ""
    return result.stdout.strip() if result.returncode == 0 else ""


def create_codex_provenance(root: Path | None = None, *, operator: str, summary: str, approved_change_id: str = "", notes: str = "") -> Path:
    project_root = Path(root or Path.cwd()).resolve(strict=False)
    record = CodexProvenanceRecord(
        codex_provenance_id=f"codex-{uuid.uuid4().hex}",
        created_at=utc_now_iso(),
        codex_operator_label=operator,
        prompt_summary=summary,
        files_changed=[line[3:].strip() for line in _git(project_root, ["status", "--porcelain"]).splitlines() if line.strip()],
        git_commit_before=_git(project_root, ["rev-parse", "HEAD"]),
        git_commit_after=_git(project_root, ["rev-parse", "HEAD"]),
        approved_change_id=approved_change_id,
        notes=notes,
    )
    target_dir = project_root / CODEX_PROVENANCE_DIR
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / f"{record.codex_provenance_id}.json"
    target.write_text(json.dumps(asdict(record), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target


__all__ = ["CODEX_PROVENANCE_DIR", "CodexProvenanceRecord", "create_codex_provenance"]
