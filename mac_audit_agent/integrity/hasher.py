from __future__ import annotations

import hashlib
import stat
from pathlib import Path
from typing import Iterable

from mac_audit_agent.integrity.exclusions import default_excluded_patterns, is_runtime_mutable_path


CHUNK_SIZE = 1024 * 1024

DEFAULT_EXCLUDED_PATTERNS = default_excluded_patterns()


def calculate_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalize_relative_path(path: Path, root: Path) -> str:
    return path.resolve(strict=False).relative_to(root.resolve(strict=False)).as_posix()


def is_excluded(relative_path: str, patterns: Iterable[str]) -> bool:
    return is_runtime_mutable_path(relative_path, patterns)


def iter_integrity_files(root: Path, excluded_patterns: Iterable[str], *, include_symlinks: bool = True) -> list[Path]:
    base = Path(root).resolve(strict=False)
    if not base.exists():
        return []
    files: list[Path] = []
    for path in base.rglob("*"):
        try:
            rel = path.relative_to(base).as_posix()
        except ValueError:
            continue
        if is_excluded(rel, excluded_patterns):
            continue
        try:
            mode = path.lstat().st_mode
        except OSError:
            files.append(path)
            continue
        if stat.S_ISLNK(mode):
            if include_symlinks:
                files.append(path)
            continue
        if path.is_file():
            files.append(path)
    return sorted(files, key=lambda item: item.relative_to(base).as_posix())


def collect_integrity_files(root_path: Path, mode: str = "source_tree", excluded_patterns: Iterable[str] | None = None) -> list[Path]:
    """Public deterministic file collector for integrity manifests.

    The mode argument is intentionally accepted here so callers can use a stable
    API while the current collector applies the same immutable-file exclusions
    across source and runtime roots.
    """
    _ = mode
    return iter_integrity_files(root_path, list(excluded_patterns or DEFAULT_EXCLUDED_PATTERNS))
