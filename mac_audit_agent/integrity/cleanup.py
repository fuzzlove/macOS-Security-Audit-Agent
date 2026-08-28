from __future__ import annotations

import json
import shutil
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from mac_audit_agent.integrity.dev_manifest import utc_now_iso
from mac_audit_agent.integrity.hash_scope import DEPRECATED_ARTIFACT_PREFIXES, LEGACY_IGNORED_FILES


CLEANUP_LEGACY_CONFIRMATION = "CLEANUP_LEGACY_INTEGRITY"
CLEANUP_GENERATED_CONFIRMATION = "CLEANUP_GENERATED"


@dataclass(slots=True)
class CleanupResult:
    status: str
    dry_run: bool
    archive_path: str = ""
    candidates: list[str] = field(default_factory=list)
    moved: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    report_path: str = ""
    recommended_action: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def legacy_cleanup_candidates(root: Path) -> list[Path]:
    root = Path(root).resolve(strict=False)
    candidates = [root / rel for rel in sorted(LEGACY_IGNORED_FILES)]
    for prefix in DEPRECATED_ARTIFACT_PREFIXES:
        path = root / prefix.rstrip("/")
        if path.exists():
            candidates.append(path)
    return [path for path in candidates if path.exists()]


def cleanup_legacy_integrity(
    root: Path,
    *,
    dry_run: bool = True,
    archive: bool = False,
    confirm: str = "",
) -> CleanupResult:
    root = Path(root).resolve(strict=False)
    candidates = legacy_cleanup_candidates(root)
    if dry_run:
        return CleanupResult("dry_run", True, candidates=[_rel(root, path) for path in candidates], recommended_action="Rerun with --archive --confirm CLEANUP_LEGACY_INTEGRITY to archive and move legacy artifacts.")
    if not archive or confirm != CLEANUP_LEGACY_CONFIRMATION:
        return CleanupResult("blocked", False, candidates=[_rel(root, path) for path in candidates], recommended_action="Archive cleanup requires --archive --confirm CLEANUP_LEGACY_INTEGRITY.")
    archive_path = _archive_path("legacy_archive")
    moved = _archive_and_move(root, candidates, archive_path)
    result = CleanupResult("archived", False, archive_path=str(archive_path), candidates=[_rel(root, path) for path in candidates], moved=moved, recommended_action="Legacy artifacts were archived outside active project scope.")
    result.report_path = str(_write_cleanup_report("legacy_cleanup", result))
    return result


def generated_cleanup_candidates(root: Path, *, egg_info: bool = False) -> list[Path]:
    root = Path(root).resolve(strict=False)
    candidates: list[Path] = []
    if egg_info:
        candidates.extend(path for path in root.rglob("*.egg-info") if path.exists())
    return sorted(set(candidates), key=lambda item: item.as_posix())


def cleanup_generated(
    root: Path,
    *,
    egg_info: bool = False,
    dry_run: bool = True,
    confirm: str = "",
) -> CleanupResult:
    root = Path(root).resolve(strict=False)
    candidates = generated_cleanup_candidates(root, egg_info=egg_info)
    if dry_run:
        return CleanupResult("dry_run", True, candidates=[_rel(root, path) for path in candidates], recommended_action="Rerun with --confirm CLEANUP_GENERATED to remove generated artifacts.")
    if confirm != CLEANUP_GENERATED_CONFIRMATION:
        return CleanupResult("blocked", False, candidates=[_rel(root, path) for path in candidates], recommended_action="Generated cleanup requires --confirm CLEANUP_GENERATED.")
    removed: list[str] = []
    for path in candidates:
        rel = _rel(root, path)
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink(missing_ok=True)
        removed.append(rel)
    result = CleanupResult("removed", False, candidates=[_rel(root, path) for path in candidates], removed=removed, recommended_action="Generated artifacts removed.")
    result.report_path = str(_write_cleanup_report("generated_cleanup", result))
    return result


def _archive_path(kind: str) -> Path:
    timestamp = utc_now_iso().replace(":", "").replace("-", "")
    base = Path.home() / "Library" / "Application Support" / "MacAuditAgent" / "integrity" / kind
    base.mkdir(parents=True, exist_ok=True)
    return base / f"{timestamp}.zip"


def _archive_and_move(root: Path, candidates: list[Path], archive_path: Path) -> list[str]:
    moved: list[str] = []
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    staging = archive_path.with_suffix("")
    staging.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in candidates:
            rel = _rel(root, path)
            if path.is_dir():
                for child in sorted(path.rglob("*")):
                    if child.is_file():
                        zf.write(child, Path(rel) / child.relative_to(path))
            elif path.exists():
                zf.write(path, rel)
            target = staging / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(path), str(target))
            moved.append(rel)
    return moved


def _write_cleanup_report(prefix: str, result: CleanupResult) -> Path:
    base = Path.home() / "Library" / "Application Support" / "MacAuditAgent" / "integrity"
    base.mkdir(parents=True, exist_ok=True)
    path = base / f"{prefix}_{utc_now_iso().replace(':', '').replace('-', '')}.json"
    path.write_text(json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _rel(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


__all__ = [
    "CLEANUP_GENERATED_CONFIRMATION",
    "CLEANUP_LEGACY_CONFIRMATION",
    "CleanupResult",
    "cleanup_generated",
    "cleanup_legacy_integrity",
    "generated_cleanup_candidates",
    "legacy_cleanup_candidates",
]
