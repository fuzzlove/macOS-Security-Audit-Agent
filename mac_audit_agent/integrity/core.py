from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mac_audit_agent.integrity.diff_report import IntegrityDiffReport, IntegrityState, report_from_verification
from mac_audit_agent.integrity.hasher import DEFAULT_EXCLUDED_PATTERNS, calculate_sha256
from mac_audit_agent.integrity.manifest import create_integrity_manifest
from mac_audit_agent.integrity.wrapper_adapter import IntegrityWrapperAdapter, WrapperIntegrityStatus
from mac_audit_agent.models import BackgroundMonitorEvent, utc_now_iso
from mac_audit_agent.rules import rule_for_event


class IntegrityEngine:
    def __init__(self, root: Path | None = None, *, manifest_path: Path | None = None, db=None, log_path: Path | None = None) -> None:
        self.root = Path(root or Path(__file__).resolve().parents[2]).expanduser().resolve(strict=False)
        self.manifest_path = Path(manifest_path).expanduser() if manifest_path else None
        self.db = db
        self.log_path = log_path or (Path.home() / "Library" / "Logs" / "MacAuditAgent" / "integrity.log")

    def generate_file_hash(self, path: Path) -> str:
        digest = calculate_sha256(path)
        self._log("file_hashed", {"path": str(path), "sha256": digest})
        return digest

    def build_manifest_snapshot(self, *, trust_state: str = "draft"):
        manifest = create_integrity_manifest(self.root, source_type="source_tree", trust_state=trust_state)  # type: ignore[arg-type]
        self._log("manifest_snapshot_built", {"root": str(self.root), "entries": len(manifest.file_entries), "trust_state": trust_state})
        return manifest

    def compare_with_trusted_manifest(self):
        self._log("integrity_check_started", {"root": str(self.root), "manifest_path": str(self.manifest_path or "")})
        result = self._verification_payload_from_authority()
        report = report_from_verification(result)
        if report.state != IntegrityState.VERIFIED:
            self._log("mismatch_detected", report.to_dict())
        self._record_alert_event(report)
        return result

    def classify_integrity_state(self) -> IntegrityState:
        return self.generate_diff_report().state

    def generate_diff_report(self) -> IntegrityDiffReport:
        result = self.compare_with_trusted_manifest()
        report = report_from_verification(result)
        self._store_last_report(report, result.to_dict() if hasattr(result, "to_dict") else dict(result))
        return report

    def _verification_payload_from_authority(self) -> dict[str, Any]:
        status = IntegrityWrapperAdapter(self.root).get_current_integrity_status(consumer="integrity_engine")
        return _wrapper_status_to_verification_payload(status)

    def diagnostics(self, report: IntegrityDiffReport | None = None) -> dict[str, Any]:
        report = report or self.generate_diff_report()
        return {
            "hash_engine_status": "available",
            "manifest_path": report.manifest_path or str(self.manifest_path or ""),
            "trusted_vs_draft_status": "trusted" if report.state not in {IntegrityState.DRAFT, IntegrityState.UNKNOWN} else report.state.value.lower(),
            "files_scanned": len(report.file_changes) if report.file_changes else 0,
            "mismatches": len(report.modified_files),
            "missing_files": len(report.missing_files),
            "extra_files": len(report.extra_files),
            "excluded_files_list": list(DEFAULT_EXCLUDED_PATTERNS),
            "last_error": report.explanation if report.state == IntegrityState.FAILED else "",
            "repair_recommendation": "; ".join(report.recommended_actions),
            "root_cause": report.summary,
        }

    def event_for_report(self, report: IntegrityDiffReport) -> BackgroundMonitorEvent:
        event_type = {
            IntegrityState.VERIFIED: "integrity_verified",
            IntegrityState.MODIFIED: "integrity_modified",
            IntegrityState.MISSING_FILES: "integrity_missing_files",
            IntegrityState.EXTRA_FILES: "integrity_extra_files",
            IntegrityState.STALE_MANIFEST: "integrity_stale_manifest",
        }.get(report.state, "integrity_modified")
        rule = rule_for_event(event_type)
        top_changes = "; ".join(f"{item.change_type}:{item.file_path}" for item in report.file_changes[:3])
        return BackgroundMonitorEvent(
            event_id=f"integrity-{report.state.value.lower()}-{utc_now_iso()}",
            timestamp=utc_now_iso(),
            event_type=event_type,
            severity=report.severity,
            source="integrity_engine",
            evidence=f"{report.summary} {top_changes}".strip(),
            confidence="high" if report.state in {IntegrityState.MODIFIED, IntegrityState.MISSING_FILES, IntegrityState.EXTRA_FILES} else "medium",
            recommendation="; ".join(report.recommended_actions[:3]),
            rule_id=rule.rule_id,
            trigger_rule_id=rule.rule_id,
        )

    def _record_alert_event(self, report: IntegrityDiffReport) -> None:
        if self.db is None:
            return
        try:
            event = self.event_for_report(report)
            if hasattr(self.db, "record_background_monitor_event"):
                self.db.record_background_monitor_event(event, dedupe_window_seconds=0)
            elif hasattr(self.db, "record_monitor_event"):
                self.db.record_monitor_event(event, dedupe_window_seconds=0)
        except Exception as exc:
            self._log("alert_event_record_failed", {"error": f"{type(exc).__name__}: {exc}"})

    def _store_last_report(self, report: IntegrityDiffReport, verification_payload: dict[str, Any]) -> None:
        if self.db is None:
            return
        payload = {"diff_report": report.to_dict(), "verification": verification_payload, "diagnostics": self.diagnostics(report)}
        try:
            self.db.set_background_monitor_state("integrity_last_diff_report_json", json.dumps(payload, sort_keys=True))
            self.db.set_background_monitor_state("integrity_last_verified_at", report.last_verified_at)
        except Exception:
            pass

    def _log(self, action: str, payload: dict[str, Any]) -> None:
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            entry = {"timestamp": utc_now_iso(), "action": action, **payload}
            with self.log_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, sort_keys=True) + "\n")
        except Exception:
            pass


def _wrapper_status_to_verification_payload(status: WrapperIntegrityStatus) -> dict[str, Any]:
    file_results: list[dict[str, Any]] = []
    for rel_path in status.source_modified_files:
        file_results.append({"relative_path": rel_path, "verification_status": "mismatch"})
    for rel_path in status.missing_files:
        file_results.append({"relative_path": rel_path, "verification_status": "missing"})
    for rel_path in status.extra_files:
        file_results.append({"relative_path": rel_path, "verification_status": "extra"})

    verified = status.status == "verified" and status.result_code == "VALID"
    errors = [] if verified else [status.reason or status.failure_code or status.result_code]
    recommendations = []
    if status.recommended_action:
        recommendations.append(status.recommended_action)
    elif not verified:
        recommendations.append("Reinstall from an official release or rebuild from trusted source.")

    return {
        "overall_status": "verified" if verified else "failed",
        "health_impact": "healthy" if verified else "broken",
        "trust_state": status.trust_state,
        "result_code": status.result_code,
        "failure_code": status.failure_code,
        "signature_valid": status.signature_valid,
        "signature_path": status.signature_path,
        "manifest_path": status.manifest_path,
        "manifest_hash": status.manifest_sha256,
        "manifest_build_id": status.build_id,
        "current_build_id": status.build_id,
        "manifest_git_commit": status.git_commit,
        "current_git_commit": status.git_commit,
        "release_id": status.release_id,
        "signing_key_fingerprint": status.signing_key_fingerprint,
        "matched_count": int(status.authority.get("checked_files", 0) or 0),
        "mismatched_count": len(status.source_modified_files),
        "missing_count": len(status.missing_files),
        "extra_count": len(status.extra_files),
        "file_results": file_results,
        "errors": errors,
        "warnings": [] if verified else [status.reason] if status.reason else [],
        "recommended_actions": recommendations,
        "exact_mismatch_reason": status.reason,
        "verified_at": utc_now_iso(),
        "checked_at": utc_now_iso(),
        "wrapper": status.to_dict(),
    }
