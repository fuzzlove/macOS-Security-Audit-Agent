from __future__ import annotations

import json
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from mac_audit_agent.integrity.approved_changes import ApprovedChangeRecord, latest_pending_approved_change, mark_tests_passed
from mac_audit_agent.integrity.manifest import create_integrity_manifest, select_manifest_path_for_root, write_integrity_manifest
from mac_audit_agent.integrity.verifier import verify_integrity_manifest
from mac_audit_agent.models import utc_now_iso


@dataclass
class VerificationEvidence:
    command: str
    exit_code: int
    timestamp: str
    output_path: str = ""
    duration: float = 0.0
    status: str = "failed"
    stdout_summary: str = ""
    stderr_summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ApprovedChangeReview:
    status: str
    approved_change: dict[str, Any] | None
    modified_files: list[dict[str, str]] = field(default_factory=list)
    unapproved_files: list[str] = field(default_factory=list)
    excluded_runtime_files: list[str] = field(default_factory=list)
    update_baseline_allowed: bool = False
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def run_verification_command(command: str, root: Path, output_dir: Path | None = None) -> VerificationEvidence:
    started = time.monotonic()
    timestamp = utc_now_iso()
    try:
        result = subprocess.run(command.split(), cwd=root, text=True, capture_output=True, timeout=120, check=False)
        exit_code = int(result.returncode)
        stdout = result.stdout[-4000:]
        stderr = result.stderr[-4000:]
    except Exception as exc:
        exit_code = 127
        stdout = ""
        stderr = str(exc)
    duration = time.monotonic() - started
    output_path = ""
    if output_dir is not None:
        output_dir.mkdir(parents=True, exist_ok=True)
        output = output_dir / f"integrity_verification_{int(time.time())}.json"
        output.write_text(
            json.dumps({"command": command, "exit_code": exit_code, "stdout": stdout, "stderr": stderr, "timestamp": timestamp}, indent=2),
            encoding="utf-8",
        )
        output_path = str(output)
    return VerificationEvidence(
        command=command,
        exit_code=exit_code,
        timestamp=timestamp,
        output_path=output_path,
        duration=duration,
        status="passed" if exit_code == 0 else "failed",
        stdout_summary=stdout,
        stderr_summary=stderr,
    )


def review_approved_change(root: Path, manifest_path: Path | None = None) -> ApprovedChangeReview:
    base = Path(root).resolve(strict=False)
    manifest_path = manifest_path or select_manifest_path_for_root(base)
    verification = verify_integrity_manifest(manifest_path, root=base, expected_source_type="source_tree", bypass_cache=True)
    record = latest_pending_approved_change(base)
    modified = verification.modified_file_classification
    unapproved = [item["file"] for item in modified if item.get("classification") == "unapproved"]
    approved = [item["file"] for item in modified if item.get("classification") == "approved"]
    reasons: list[str] = []
    if record is None:
        reasons.append("No approved change record exists.")
    if unapproved:
        reasons.append("Unapproved modified files are present.")
    if not modified and verification.overall_status in {"verified", "verified_with_warnings"}:
        reasons.append("No modified files require rebaseline.")
    allowed = bool(record and approved and not unapproved)
    return ApprovedChangeReview(
        status="ready" if allowed else "blocked",
        approved_change=record.to_dict() if record else None,
        modified_files=modified,
        unapproved_files=unapproved,
        excluded_runtime_files=verification.excluded_runtime_files,
        update_baseline_allowed=allowed,
        reasons=reasons,
    )


def update_trusted_development_baseline(
    root: Path,
    *,
    approved_change: ApprovedChangeRecord | None = None,
    manifest_path: Path | None = None,
    verification_commands: list[str] | None = None,
    require_verification: bool = True,
    explicit_dev_only: bool = False,
) -> dict[str, Any]:
    base = Path(root).resolve(strict=False)
    manifest_path = manifest_path or select_manifest_path_for_root(base)
    record = approved_change or latest_pending_approved_change(base)
    review = review_approved_change(base, manifest_path)
    if record is None:
        return {"status": "blocked", "reason": "No approved change record exists.", "review": review.to_dict()}
    if review.unapproved_files and not explicit_dev_only:
        return {"status": "blocked", "reason": "Unapproved modified files are present.", "review": review.to_dict()}
    commands = verification_commands or record.tests_required or ["python3 -m compileall -q mac_audit_agent"]
    evidence = [run_verification_command(command, base, base / "release_evidence" / "integrity") for command in commands]
    failed = [item for item in evidence if item.exit_code != 0]
    if failed and require_verification and not explicit_dev_only:
        return {
            "status": "blocked",
            "reason": "Required verification failed.",
            "review": review.to_dict(),
            "verification_evidence": [item.to_dict() for item in evidence],
        }
    backup_path = None
    if manifest_path.exists():
        backup_path = manifest_path.with_suffix(f".{int(time.time())}.bak")
        backup_path.write_text(manifest_path.read_text(encoding="utf-8"), encoding="utf-8")
    passed_commands = [item.command for item in evidence if item.exit_code == 0]
    mark_tests_passed(base, record, passed_commands, build_verified=not failed)
    manifest = create_integrity_manifest(
        base,
        source_type="source_tree",
        notes=f"Trusted development baseline after approved change {record.change_id}.",
        trust_state="trusted",
        approved_change_id=record.change_id,
        verification_commands=commands,
        verification_results=[item.to_dict() for item in evidence],
        signature_status="not_required_dev_mode",
    )
    write_integrity_manifest(manifest, manifest_path)
    fresh = verify_integrity_manifest(manifest_path, root=base, expected_source_type="source_tree", bypass_cache=True)
    return {
        "status": "rebaselined",
        "manifest_path": str(manifest_path),
        "backup_path": str(backup_path) if backup_path else "",
        "approved_change_id": record.change_id,
        "verification_evidence": [item.to_dict() for item in evidence],
        "fresh_verification": fresh.to_dict(),
    }


__all__ = ["VerificationEvidence", "ApprovedChangeReview", "review_approved_change", "update_trusted_development_baseline", "run_verification_command"]
