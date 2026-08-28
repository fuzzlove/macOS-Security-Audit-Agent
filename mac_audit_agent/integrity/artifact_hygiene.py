from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from mac_audit_agent.integrity.exclusions import default_excluded_patterns, is_runtime_mutable_path


@dataclass(slots=True)
class ArtifactHygieneResult:
    status: str
    checked_paths: list[str] = field(default_factory=list)
    offenders: list[str] = field(default_factory=list)
    blocking_reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


BAD_NAMES = {".tmp_pre_uat", ".env"}
BAD_SUFFIXES = (".sqlite3", ".sqlite3-wal", ".sqlite3-shm", ".sqlite", ".db", ".log", ".key")
SECRET_PATTERNS = (
    re.compile(r"BEGIN (?:RSA |EC |OPENSSH |)?PRIVATE KEY"),
)


def scan_artifact_hygiene(root: Path | None = None, *, include_dist: bool = True) -> ArtifactHygieneResult:
    root = Path(root or Path.cwd()).resolve(strict=False)
    candidates = [root]
    if include_dist and (root / "dist").exists():
        candidates.append(root / "dist")
    checked: list[str] = []
    offenders: list[str] = []
    reasons: list[str] = []
    seen: set[Path] = set()
    for base in candidates:
        for path in sorted((item for item in base.rglob("*") if item.is_file()), key=lambda item: item.as_posix()):
            resolved = path.resolve(strict=False)
            if resolved in seen:
                continue
            seen.add(resolved)
            rel = _rel(root, path)
            # Distribution output is intentionally inspected even though it is
            # excluded from the source manifest. Other generated/runtime paths
            # must not block source re-signing merely because they exist.
            if not rel.startswith("dist/") and is_runtime_mutable_path(rel, default_excluded_patterns()):
                continue
            checked.append(rel)
            reason = _artifact_reason(path, root)
            if reason:
                offenders.append(rel)
                reasons.append(f"{rel}: {reason}")
    status = "passed" if not offenders else "failed"
    return ArtifactHygieneResult(status, checked, sorted(offenders), sorted(reasons))


def _artifact_reason(path: Path, root: Path) -> str:
    rel = _rel(root, path)
    parts = set(rel.split("/"))
    if path.name in BAD_NAMES or parts & BAD_NAMES:
        return "temporary or environment file"
    if path.name.endswith(BAD_SUFFIXES):
        return "runtime/private artifact suffix"
    if "Library/Application Support" in rel or "/Users/" in rel:
        return "absolute local user path"
    if "crash" in path.name.lower() and path.suffix.lower() in {".log", ".ips", ".crash"}:
        return "crash report"
    if path.suffix.lower() in {".pem", ".key", ".env"} or "secret" in path.name.lower() or "private" in path.name.lower():
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")[:65536]
        except OSError:
            return ""
        for pattern in SECRET_PATTERNS:
            if pattern.search(text):
                return "secret-like material"
    return ""


def _rel(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


__all__ = ["ArtifactHygieneResult", "scan_artifact_hygiene"]
