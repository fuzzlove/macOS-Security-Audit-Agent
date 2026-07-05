from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class IntegrityState(str, Enum):
    VERIFIED = "VERIFIED"
    MODIFIED = "MODIFIED"
    MISSING_FILES = "MISSING_FILES"
    EXTRA_FILES = "EXTRA_FILES"
    STALE_MANIFEST = "STALE_MANIFEST"
    UNKNOWN = "UNKNOWN"
    DRAFT = "DRAFT"
    FAILED = "FAILED"


@dataclass
class IntegrityFileChange:
    file_path: str
    expected_hash: str = ""
    actual_hash: str = ""
    change_type: str = ""
    severity: str = "medium"
    risk_classification: str = "review recommended"
    explanation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class IntegrityDiffReport:
    summary: str
    state: IntegrityState
    file_changes: list[IntegrityFileChange] = field(default_factory=list)
    missing_files: list[IntegrityFileChange] = field(default_factory=list)
    extra_files: list[IntegrityFileChange] = field(default_factory=list)
    modified_files: list[IntegrityFileChange] = field(default_factory=list)
    severity: str = "info"
    explanation: str = ""
    recommended_actions: list[str] = field(default_factory=list)
    manifest_path: str = ""
    manifest_version: str = ""
    build_id: str = ""
    last_verified_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary,
            "state": self.state.value,
            "file_changes": [item.to_dict() for item in self.file_changes],
            "missing_files": [item.to_dict() for item in self.missing_files],
            "extra_files": [item.to_dict() for item in self.extra_files],
            "modified_files": [item.to_dict() for item in self.modified_files],
            "severity": self.severity,
            "explanation": self.explanation,
            "recommended_actions": list(self.recommended_actions),
            "manifest_path": self.manifest_path,
            "manifest_version": self.manifest_version,
            "build_id": self.build_id,
            "last_verified_at": self.last_verified_at,
        }


def report_from_verification(result) -> IntegrityDiffReport:
    payload = result.to_dict() if hasattr(result, "to_dict") else dict(result)
    state = classify_state(payload)
    changes: list[IntegrityFileChange] = []
    for item in payload.get("file_results", []):
        if not isinstance(item, dict):
            continue
        status = str(item.get("verification_status", ""))
        if status not in {"mismatch", "missing", "extra"}:
            continue
        changes.append(_change_from_file_result(item, state))
    missing = [item for item in changes if item.change_type == "missing"]
    extra = [item for item in changes if item.change_type == "extra"]
    modified = [item for item in changes if item.change_type == "modified"]
    severity = _severity_for_state(state, extra)
    return IntegrityDiffReport(
        summary=_summary_for_state(state, payload, changes),
        state=state,
        file_changes=changes,
        missing_files=missing,
        extra_files=extra,
        modified_files=modified,
        severity=severity,
        explanation=_explanation_for_state(state, payload),
        recommended_actions=[str(item) for item in payload.get("recommended_actions", [])],
        manifest_path=str(payload.get("manifest_path", "")),
        manifest_version=str(payload.get("manifest_app_version", "")),
        build_id=str(payload.get("manifest_build_id", "")),
        last_verified_at=str(payload.get("verified_at", payload.get("checked_at", ""))),
    )


def classify_state(payload: dict[str, Any]) -> IntegrityState:
    status = str(payload.get("overall_status", "")).lower()
    if status in {"verified", "verified_with_warnings"}:
        return IntegrityState.VERIFIED
    if status == "draft":
        return IntegrityState.DRAFT
    if status in {"unknown", "incompatible_manifest"}:
        return IntegrityState.UNKNOWN
    if status == "failed":
        return IntegrityState.FAILED
    if status == "stale":
        return IntegrityState.STALE_MANIFEST
    if int(payload.get("missing_count", 0) or 0) > 0:
        return IntegrityState.MISSING_FILES
    if int(payload.get("mismatched_count", 0) or 0) > 0:
        return IntegrityState.MODIFIED
    if int(payload.get("extra_count", 0) or 0) > 0:
        return IntegrityState.EXTRA_FILES
    return IntegrityState.UNKNOWN


def _change_from_file_result(item: dict[str, Any], state: IntegrityState) -> IntegrityFileChange:
    status = str(item.get("verification_status", ""))
    change_type = "modified" if status == "mismatch" else status
    executable = bool(item.get("executable"))
    severity = "critical" if change_type == "missing" else ("high" if executable or change_type == "modified" else "medium")
    path = str(item.get("relative_path", item.get("file_path", "")))
    return IntegrityFileChange(
        file_path=path,
        expected_hash=str(item.get("sha256", "")),
        actual_hash=str(item.get("observed_sha256", "")),
        change_type=change_type,
        severity=severity,
        risk_classification="possible tampering" if severity in {"high", "critical"} else "configuration drift",
        explanation=_change_explanation(path, change_type, state, executable),
    )


def _change_explanation(path: str, change_type: str, state: IntegrityState, executable: bool) -> str:
    if change_type == "missing":
        return f"{path} is required by the trusted manifest but is missing. This can indicate corruption, failed update, or removal."
    if change_type == "extra":
        if executable:
            return f"{path} is an unexpected executable file. Review before trusting this installation."
        return f"{path} is not listed in the trusted manifest."
    return f"{path} has changed since the trusted installation. This may indicate update, corruption, or tampering."


def _severity_for_state(state: IntegrityState, extra: list[IntegrityFileChange]) -> str:
    if state == IntegrityState.MISSING_FILES:
        return "critical"
    if state == IntegrityState.MODIFIED:
        return "high"
    if state == IntegrityState.EXTRA_FILES:
        return "high" if any(item.severity == "high" for item in extra) else "medium"
    if state == IntegrityState.STALE_MANIFEST:
        return "medium"
    if state in {IntegrityState.UNKNOWN, IntegrityState.DRAFT, IntegrityState.FAILED}:
        return "medium"
    return "info"


def _summary_for_state(state: IntegrityState, payload: dict[str, Any], changes: list[IntegrityFileChange]) -> str:
    if state == IntegrityState.VERIFIED:
        return "MSAA application files match the trusted manifest."
    if state == IntegrityState.STALE_MANIFEST:
        return "Trusted manifest appears to belong to a different MSAA build or version."
    if state == IntegrityState.DRAFT:
        return "Only a draft manifest is available; draft manifests cannot verify integrity."
    if state == IntegrityState.UNKNOWN:
        return "No compatible trusted integrity manifest is available."
    if state == IntegrityState.FAILED:
        return "Integrity verification failed before a trustworthy comparison could complete."
    return f"Integrity verification found {len(changes)} file change(s)."


def _explanation_for_state(state: IntegrityState, payload: dict[str, Any]) -> str:
    if state == IntegrityState.VERIFIED:
        return "The scanned application files match the trusted baseline. Mutable files such as logs, databases, settings, reports, caches, and evidence exports are excluded."
    if state == IntegrityState.STALE_MANIFEST:
        return "File hashes did not show required-file changes, but manifest metadata differs from the current app build. Treat this as an update review, not automatic tamper proof."
    if state == IntegrityState.DRAFT:
        return "A draft manifest is useful for review, but it is not trusted and must not be used to prove application integrity."
    if state == IntegrityState.UNKNOWN:
        return "Create a trusted baseline only after confirming this installation came from a trusted source."
    if state == IntegrityState.FAILED:
        return "; ".join(str(item) for item in payload.get("errors", [])) or "The integrity engine returned an error."
    return str(payload.get("exact_mismatch_reason", "")) or "Application files differ from the trusted manifest."
