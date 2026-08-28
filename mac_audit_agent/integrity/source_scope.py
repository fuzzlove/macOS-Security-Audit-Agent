from __future__ import annotations

from dataclasses import asdict, dataclass
from fnmatch import fnmatch
from pathlib import Path

from mac_audit_agent.integrity.exclusions import default_excluded_patterns, is_runtime_mutable_path


INCLUDE_PATTERNS = [
    "mac_audit_agent/*.py",
    "mac_audit_agent/*.json",
    "mac_audit_agent/*.yaml",
    "mac_audit_agent/*.yml",
    "mac_audit_agent/*.toml",
    "mac_audit_agent/*.plist",
    "mac_audit_agent/*.html",
    "mac_audit_agent/*.css",
    "mac_audit_agent/*.qss",
    "mac_audit_agent/*.png",
    "mac_audit_agent/*.jpg",
    "mac_audit_agent/*.jpeg",
    "mac_audit_agent/*.icns",
    "mac_audit_agent/*.ico",
    "mac_audit_agent/**/*.py",
    "mac_audit_agent/**/*.json",
    "mac_audit_agent/**/*.yaml",
    "mac_audit_agent/**/*.yml",
    "mac_audit_agent/**/*.toml",
    "mac_audit_agent/**/*.plist",
    "mac_audit_agent/**/*.html",
    "mac_audit_agent/**/*.css",
    "mac_audit_agent/**/*.qss",
    "mac_audit_agent/**/*.png",
    "mac_audit_agent/**/*.jpg",
    "mac_audit_agent/**/*.jpeg",
    "mac_audit_agent/**/*.icns",
    "mac_audit_agent/**/*.ico",
    "mac_audit_agent/help/resources/**/*.md",
    "pyproject.toml",
    "README.md",
    "LICENSE",
    "MANIFEST.in",
    "requirements.txt",
    "mac_audit_agent/integrity/trust/*.pem",
    "scripts/**/*.py",
    "scripts/**/*.sh",
    "scripts/*.py",
    "scripts/*.sh",
    "scripts/msaa",
    "scripts/msaa-python3",
]


@dataclass(slots=True)
class SourceScopeClassification:
    relative_path: str
    classification: str
    included: bool
    excluded: bool

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def is_included_source_path(relative_path: str) -> bool:
    rel = relative_path.replace("\\", "/").lstrip("./")
    return any(fnmatch(rel, pattern) for pattern in INCLUDE_PATTERNS)


def classify_source_scope(relative_path: str) -> SourceScopeClassification:
    rel = relative_path.replace("\\", "/").lstrip("./")
    excluded = is_runtime_mutable_path(rel, default_excluded_patterns())
    included = is_included_source_path(rel) and not excluded
    if included:
        classification = "source"
    elif excluded:
        classification = "generated_candidate"
    elif rel.startswith("mac_audit_agent/") or rel.startswith("scripts/"):
        classification = "unknown_source_candidate"
    else:
        classification = "ignored_by_policy"
    return SourceScopeClassification(rel, classification, included, excluded)


def classify_project_files(root: Path) -> list[SourceScopeClassification]:
    root = Path(root).resolve(strict=False)
    results = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            continue
        if rel.startswith(".git/"):
            continue
        results.append(classify_source_scope(rel))
    return results


__all__ = ["INCLUDE_PATTERNS", "SourceScopeClassification", "classify_project_files", "classify_source_scope", "is_included_source_path"]
