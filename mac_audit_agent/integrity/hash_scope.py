from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from mac_audit_agent.integrity.dev_manifest import is_excluded_integrity_path, iter_protected_files
from mac_audit_agent.integrity.exclusions import default_excluded_patterns
from mac_audit_agent.integrity.source_scope import classify_source_scope


@dataclass(slots=True)
class HashScopeReport:
    included_files: list[str] = field(default_factory=list)
    excluded_files: list[str] = field(default_factory=list)
    excluded_patterns: list[str] = field(default_factory=list)
    source_files: list[str] = field(default_factory=list)
    generated_files: list[str] = field(default_factory=list)
    trust_metadata_files: list[str] = field(default_factory=list)
    legacy_ignored_files: list[str] = field(default_factory=list)
    deprecated_artifacts: list[str] = field(default_factory=list)
    runtime_files: list[str] = field(default_factory=list)
    build_files: list[str] = field(default_factory=list)
    unknown_files: list[str] = field(default_factory=list)
    inclusion_reason_by_file: dict[str, str] = field(default_factory=dict)
    exclusion_reason_by_file: dict[str, str] = field(default_factory=dict)
    dangerous_unclassified_files: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


RUNTIME_SUFFIXES = (".sqlite", ".sqlite3", ".sqlite-wal", ".sqlite3-wal", ".sqlite-shm", ".sqlite3-shm", ".db", ".log")
BUILD_PARTS = {"dist", "build", "htmlcov", ".tox", ".nox", "macos_security_audit_agent.egg-info"}
TRUST_METADATA_FILES = {
    "mac_audit_agent/integrity/integrity_manifest.json",
    "mac_audit_agent/integrity/integrity_manifest.signature.json",
    "mac_audit_agent/integrity/trusted_developer_machines.json",
}
LEGACY_IGNORED_FILES = {
    "mac_audit_agent/integrity/development_manifest.json",
    "mac_audit_agent/integrity/development_manifest.sig",
    "mac_audit_agent/integrity/release_manifest.json",
    "mac_audit_agent/integrity/release_manifest.sig",
    "mac_audit_agent/security/integrity_manifest.json",
    "mac_audit_agent/security/integrity_manifest.json.sig",
}
DEPRECATED_ARTIFACT_PREFIXES = (
    "mac_audit_agent/integrity/yubikey_signatures/",
)


def build_hash_scope_report(root: Path | None = None, *, policy: str = "dev") -> HashScopeReport:
    root = Path(root or Path.cwd()).resolve(strict=False)
    included = {path.relative_to(root).as_posix() for path in iter_protected_files(root)}
    report = HashScopeReport(excluded_patterns=sorted(set(default_excluded_patterns())))
    for path in sorted((item for item in root.rglob("*") if item.is_file()), key=lambda item: item.as_posix()):
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            continue
        classification = classify_source_scope(rel)
        parts = set(rel.split("/"))
        if rel in TRUST_METADATA_FILES:
            report.excluded_files.append(rel)
            report.trust_metadata_files.append(rel)
            report.exclusion_reason_by_file[rel] = "trust metadata validated by manifest signature process"
            continue
        if rel in LEGACY_IGNORED_FILES:
            report.excluded_files.append(rel)
            report.legacy_ignored_files.append(rel)
            report.exclusion_reason_by_file[rel] = "legacy integrity artifact ignored by active policy"
            continue
        if rel.startswith(DEPRECATED_ARTIFACT_PREFIXES):
            report.excluded_files.append(rel)
            report.deprecated_artifacts.append(rel)
            report.exclusion_reason_by_file[rel] = "deprecated integrity artifact outside active trust scope"
            continue
        if rel in included:
            report.included_files.append(rel)
            report.source_files.append(rel)
            report.inclusion_reason_by_file[rel] = "protected source scope"
            continue
        excluded_reason = _exclusion_reason(rel, parts)
        if excluded_reason:
            report.excluded_files.append(rel)
            report.exclusion_reason_by_file[rel] = excluded_reason
            if rel.endswith(RUNTIME_SUFFIXES) or "logs" in parts:
                report.runtime_files.append(rel)
            elif parts & BUILD_PARTS or rel.endswith((".egg-info/PKG-INFO", ".whl", ".tar.gz")):
                report.build_files.append(rel)
            else:
                report.generated_files.append(rel)
            continue
        if classification.classification == "unknown_source_candidate":
            report.unknown_files.append(rel)
            report.dangerous_unclassified_files.append(rel)
        else:
            report.unknown_files.append(rel)
    _dedupe_sort(report)
    return report


def _exclusion_reason(rel: str, parts: set[str]) -> str:
    if is_excluded_integrity_path(rel):
        return "integrity exclusion policy"
    if parts & BUILD_PARTS:
        return "build artifact"
    if rel.endswith(RUNTIME_SUFFIXES):
        return "runtime mutable artifact"
    if rel.startswith(".git/"):
        return "git metadata"
    if "/__pycache__/" in rel or rel.endswith(".pyc"):
        return "python cache"
    return ""


def _dedupe_sort(report: HashScopeReport) -> None:
    for name in (
        "included_files",
        "excluded_files",
        "source_files",
        "generated_files",
        "trust_metadata_files",
        "legacy_ignored_files",
        "deprecated_artifacts",
        "runtime_files",
        "build_files",
        "unknown_files",
        "dangerous_unclassified_files",
    ):
        setattr(report, name, sorted(set(getattr(report, name))))


def classify_integrity_metadata_path(relative_path: str) -> str:
    rel = str(relative_path).replace("\\", "/")
    if rel in TRUST_METADATA_FILES:
        return "trust_metadata"
    if rel in LEGACY_IGNORED_FILES:
        return "legacy_ignored"
    if rel.startswith(DEPRECATED_ARTIFACT_PREFIXES):
        return "deprecated_artifact"
    return ""


__all__ = [
    "HashScopeReport",
    "TRUST_METADATA_FILES",
    "LEGACY_IGNORED_FILES",
    "DEPRECATED_ARTIFACT_PREFIXES",
    "build_hash_scope_report",
    "classify_integrity_metadata_path",
]
