from __future__ import annotations

import argparse
import getpass
import json
import subprocess
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

from mac_audit_agent.integrity.hasher import calculate_sha256
from mac_audit_agent.integrity.manifest import load_integrity_manifest, select_manifest_path_for_root
from mac_audit_agent.models import utc_now_iso


ApprovalSource = Literal["codex", "developer", "release_process", "manual_review"]
ApprovalStatus = Literal["pending", "approved", "rejected", "superseded"]


@dataclass
class ApprovedChangeRecord:
    change_id: str
    created_at: str
    approved_by: str
    approval_source: ApprovalSource
    description: str
    affected_files: list[str]
    expected_hashes_before: dict[str, str] = field(default_factory=dict)
    expected_hashes_after: dict[str, str] = field(default_factory=dict)
    git_commit_before: str = ""
    git_commit_after: str = ""
    tests_required: list[str] = field(default_factory=lambda: ["python3 -m compileall -q mac_audit_agent"])
    tests_passed: list[str] = field(default_factory=list)
    build_verified: bool = False
    signed_manifest_path: str | None = None
    approval_status: ApprovalStatus = "pending"
    notes: str = ""
    diff_stat: str = ""
    untracked_files: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ApprovedChangeRecord":
        return cls(
            change_id=str(payload.get("change_id", "")),
            created_at=str(payload.get("created_at", "")),
            approved_by=str(payload.get("approved_by", "")),
            approval_source=str(payload.get("approval_source", "developer")),  # type: ignore[arg-type]
            description=str(payload.get("description", "")),
            affected_files=[str(item) for item in payload.get("affected_files", [])],
            expected_hashes_before={str(k): str(v) for k, v in dict(payload.get("expected_hashes_before", {})).items()},
            expected_hashes_after={str(k): str(v) for k, v in dict(payload.get("expected_hashes_after", {})).items()},
            git_commit_before=str(payload.get("git_commit_before", "")),
            git_commit_after=str(payload.get("git_commit_after", "")),
            tests_required=[str(item) for item in payload.get("tests_required", [])],
            tests_passed=[str(item) for item in payload.get("tests_passed", [])],
            build_verified=bool(payload.get("build_verified", False)),
            signed_manifest_path=payload.get("signed_manifest_path"),
            approval_status=str(payload.get("approval_status", "pending")),  # type: ignore[arg-type]
            notes=str(payload.get("notes", "")),
            diff_stat=str(payload.get("diff_stat", "")),
            untracked_files=[str(item) for item in payload.get("untracked_files", [])],
        )


def approved_changes_dir(root: Path) -> Path:
    return Path(root) / ".msaa" / "approved_changes"


def record_path(root: Path, change_id: str) -> Path:
    return approved_changes_dir(root) / f"{change_id}.json"


def _git(args: list[str], root: Path) -> str:
    try:
        result = subprocess.run(["git", *args], cwd=root, text=True, capture_output=True, timeout=10, check=False)
    except Exception:
        return ""
    return result.stdout.strip() if result.returncode == 0 else ""


def git_changed_files(root: Path) -> list[str]:
    output = _git(["status", "--porcelain"], root)
    files: list[str] = []
    for line in output.splitlines():
        path = line[3:].strip()
        if path:
            files.append(path)
    return sorted(set(files))


def _manifest_expected_hashes(root: Path) -> dict[str, str]:
    manifest_path = select_manifest_path_for_root(root)
    if not manifest_path.exists():
        return {}
    try:
        manifest = load_integrity_manifest(manifest_path)
    except Exception:
        return {}
    return {entry.relative_path: entry.sha256 for entry in manifest.file_entries if entry.sha256}


def _current_hashes(root: Path, files: list[str]) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for rel in files:
        path = root / rel
        if path.exists() and path.is_file():
            try:
                hashes[rel] = calculate_sha256(path)
            except Exception:
                hashes[rel] = ""
        else:
            hashes[rel] = ""
    return hashes


def create_approved_change_record(
    root: Path,
    *,
    description: str,
    source: ApprovalSource = "codex",
    approved_by: str | None = None,
    affected_files: list[str] | None = None,
    tests_required: list[str] | None = None,
    notes: str = "",
) -> ApprovedChangeRecord:
    base = Path(root).resolve(strict=False)
    changed = sorted(set(affected_files or git_changed_files(base)))
    expected_before = _manifest_expected_hashes(base)
    record = ApprovedChangeRecord(
        change_id=f"approved-change-{uuid.uuid4().hex[:12]}",
        created_at=utc_now_iso(),
        approved_by=approved_by or getpass.getuser(),
        approval_source=source,
        description=description,
        affected_files=changed,
        expected_hashes_before={path: expected_before.get(path, "") for path in changed},
        expected_hashes_after=_current_hashes(base, changed),
        git_commit_before=_git(["rev-parse", "HEAD"], base),
        git_commit_after=_git(["rev-parse", "HEAD"], base),
        tests_required=tests_required or ["python3 -m compileall -q mac_audit_agent"],
        tests_passed=[],
        build_verified=False,
        approval_status="pending",
        notes=notes,
        diff_stat=_git(["diff", "--stat"], base),
        untracked_files=[path for path in changed if path and not (base / path).exists()],
    )
    save_approved_change_record(base, record)
    return record


def save_approved_change_record(root: Path, record: ApprovedChangeRecord) -> Path:
    path = record_path(root, record.change_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
    return path


def load_approved_change_records(root: Path) -> list[ApprovedChangeRecord]:
    directory = approved_changes_dir(root)
    if not directory.exists():
        return []
    records: list[ApprovedChangeRecord] = []
    for path in sorted(directory.glob("*.json")):
        try:
            records.append(ApprovedChangeRecord.from_dict(json.loads(path.read_text(encoding="utf-8"))))
        except Exception:
            continue
    return sorted(records, key=lambda item: item.created_at, reverse=True)


def latest_pending_approved_change(root: Path) -> ApprovedChangeRecord | None:
    for record in load_approved_change_records(root):
        if record.approval_status in {"pending", "approved"}:
            return record
    return None


def mark_tests_passed(root: Path, record: ApprovedChangeRecord, tests_passed: list[str], *, build_verified: bool = False) -> ApprovedChangeRecord:
    record.tests_passed = sorted(set(record.tests_passed + tests_passed))
    record.build_verified = bool(record.build_verified or build_verified)
    record.approval_status = "approved"
    save_approved_change_record(root, record)
    return record


def classify_files_against_record(files: list[str], record: ApprovedChangeRecord | None) -> dict[str, str]:
    approved = set(record.affected_files if record else [])
    return {path: ("approved" if path in approved else "unapproved") for path in files}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create an auditable MSAA approved-change record without trusting files.")
    parser.add_argument("--root", default=".")
    parser.add_argument("--description", required=True)
    parser.add_argument("--source", choices=["codex", "developer", "release_process", "manual_review"], default="codex")
    parser.add_argument("--file", action="append", default=[], help="Affected file. Defaults to git changed files.")
    parser.add_argument("--notes", default="")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    record = create_approved_change_record(
        Path(args.root),
        description=args.description,
        source=args.source,
        affected_files=args.file or None,
        notes=args.notes,
    )
    if args.json:
        print(json.dumps(record.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"approved change record created: {record_path(Path(args.root), record.change_id)}")
        print("This did not update the trusted integrity baseline.")
    return 0


__all__ = [
    "ApprovedChangeRecord",
    "create_approved_change_record",
    "save_approved_change_record",
    "load_approved_change_records",
    "latest_pending_approved_change",
    "mark_tests_passed",
    "classify_files_against_record",
    "approved_changes_dir",
    "record_path",
]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
