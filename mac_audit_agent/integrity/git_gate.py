from __future__ import annotations

import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path

from mac_audit_agent.integrity.source_scope import classify_source_scope


@dataclass(slots=True)
class GitGateResult:
    status: str
    source_change_status: str
    untracked_source_files: list[str] = field(default_factory=list)
    modified_source_files: list[str] = field(default_factory=list)
    staged_source_files: list[str] = field(default_factory=list)
    generated_files: list[str] = field(default_factory=list)
    manual_review_files: list[str] = field(default_factory=list)
    git_status: list[str] = field(default_factory=list)
    blocking_reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def evaluate_git_gate(root: Path, *, approve_current_source: bool = False) -> GitGateResult:
    root = Path(root).resolve(strict=False)
    status_lines = _git_lines(root, ["status", "--porcelain"])
    untracked = _git_lines(root, ["ls-files", "--others", "--exclude-standard"])
    modified = _git_lines(root, ["diff", "--name-only"])
    staged = _git_lines(root, ["diff", "--cached", "--name-only"])
    result = GitGateResult("passed", "clean_or_generated_only", git_status=status_lines)
    for rel in sorted(set(untracked)):
        _classify(result, rel, "untracked")
    for rel in sorted(set(modified)):
        _classify(result, rel, "modified")
    for rel in sorted(set(staged)):
        _classify(result, rel, "staged")
    source_changes = result.untracked_source_files + result.modified_source_files + result.staged_source_files + result.manual_review_files
    if source_changes and not approve_current_source:
        result.status = "failed"
        result.source_change_status = "unapproved_source_changes"
        result.blocking_reasons.append("source changes require --approve-current-source and typed confirmation")
    return result


def _classify(result: GitGateResult, rel: str, state: str) -> None:
    classification = classify_source_scope(rel)
    if classification.excluded:
        result.generated_files.append(rel)
    elif classification.included and state == "untracked":
        result.untracked_source_files.append(rel)
    elif classification.included and state == "staged":
        result.staged_source_files.append(rel)
    elif classification.included:
        result.modified_source_files.append(rel)
    elif classification.classification == "unknown_source_candidate":
        result.manual_review_files.append(rel)


def _git_lines(root: Path, args: list[str]) -> list[str]:
    try:
        completed = subprocess.run(["git", *args], cwd=root, text=True, capture_output=True, check=False, timeout=15)
    except Exception:
        return []
    if completed.returncode != 0:
        return []
    if args[:1] == ["status"]:
        return [line for line in completed.stdout.splitlines() if line.strip()]
    return [line.strip().strip('"') for line in completed.stdout.splitlines() if line.strip()]


__all__ = ["GitGateResult", "evaluate_git_gate"]
