from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from mac_audit_agent.assessment import build_security_assessment
from mac_audit_agent.baseline_drift import BaselineDriftEngine
from mac_audit_agent.collectors import CollectorSuite
from mac_audit_agent.config import AuditConfig
from mac_audit_agent.frameworks import NIST_CSF_FUNCTIONS
from mac_audit_agent.models import ScanResult, utc_now_iso
from mac_audit_agent.quality.audit_models import AuditContext, FunctionalCheck
from mac_audit_agent.runner import RunnerConfig, SafeCommandRunner
from mac_audit_agent.storage import AuditDatabase
from mac_audit_agent.visibility_integrity import VisibilityIntegrityEngine


def run_scan_audit(context: AuditContext) -> list[FunctionalCheck]:
    checks: list[FunctionalCheck] = []
    checks.append(_latest_or_safe_scan_check(context))
    checks.append(_artifact_check(context, "scan.localhost_ports", "localhost port scan", ["ports"], "No ports parsed bug or explicit parser errors must be visible."))
    checks.append(_artifact_check(context, "scan.network", "network scan", ["ports"], "Network parser must return structured active/listening connection data."))
    checks.append(_artifact_check(context, "scan.admin_persistence", "admin/persistence scan", ["launch_snapshots", "users"], "Admin/persistence artifacts should be present or explicitly unavailable."))
    checks.append(_artifact_check(context, "scan.physical_devices", "physical devices scan", ["physical_devices", "hardware"], "Physical device inventory should be present or explicitly unavailable."))
    checks.append(_apple_exposure_check(context))
    checks.append(_visibility_check(context))
    checks.append(_baseline_check(context))
    checks.append(_assessment_check(context))
    checks.append(_framework_mapping_check())
    checks.append(_freshness_check(context))
    return checks


def _latest_or_safe_scan_check(context: AuditContext) -> FunctionalCheck:
    check = FunctionalCheck("scan.safe_scan", "Scans", "Safe Scan", "Safe scan can run without destructive actions.", "critical", "smoke")
    db = AuditDatabase(context.db_path)
    try:
        if not context.allow_safe_scan:
            latest = db.latest_scan_result()
            if latest is None:
                return check.skipped("No latest scan and --run-safe-scan was not requested.", "Run pre-UAT audit with --run-safe-scan or run a Safe Scan first.")
            return check.passed("Latest saved scan is available for audit.", {"scan_id": latest.scan_id, "timestamp": latest.timestamp})
        config = AuditConfig(logs_dir=db.logs_dir, dry_run=False, disable_aggressive_scan=True)
        scan = CollectorSuite(SafeCommandRunner(RunnerConfig(dry_run=False)), config).run_safe_scan(previous_result=db.latest_scan_result())
        if not isinstance(scan, ScanResult):
            return check.failed("Safe scan did not return ScanResult.", "Repair CollectorSuite.run_safe_scan return path.", {})
        return check.passed("Safe scan completed and returned ScanResult.", {"scan_id": scan.scan_id, "findings": len(scan.findings)})
    except Exception as exc:
        return check.failed(str(exc), "Fix Safe Scan collector crash before UAT.", {"exception": type(exc).__name__})


def _artifact_check(context: AuditContext, check_id: str, name: str, keys: list[str], fix: str) -> FunctionalCheck:
    check = FunctionalCheck(check_id, "Scans", name, f"{name} returns structured result or explicit unavailable reason.", "high", "smoke")
    latest = AuditDatabase(context.db_path).latest_scan_result()
    if latest is None:
        return check.skipped("No latest scan available.", "Run Safe Scan before scan functionality audit.")
    present = [key for key in keys if key in latest.artifacts]
    if present:
        return check.passed("Scan artifact keys present.", {"present": present})
    errors = latest.artifacts.get("errors") or [error.to_dict() for error in latest.errors]
    if errors:
        return check.warn("Scan artifact unavailable with recorded errors.", fix, {"errors": errors[:5]})
    return check.warn(f"Scan artifact keys missing: {keys}", fix, {"available_keys": sorted(latest.artifacts)})


def _apple_exposure_check(context: AuditContext) -> FunctionalCheck:
    check = FunctionalCheck("scan.apple_exposure", "Scans", "Apple Exposure Assessment", "Freshness metadata exists and stale cache is not misrepresented.", "high", "smoke")
    db = AuditDatabase(context.db_path)
    keys = ["apple_exposure_last_check_attempt_at", "apple_exposure_last_successful_update_at", "cve_radar_last_refresh_at"]
    values = {key: db.get_background_monitor_state(key, "") for key in keys}
    if any(values.values()):
        return check.passed("Apple Exposure freshness metadata found.", values)
    return check.warn("Apple Exposure freshness metadata not found.", "Run Apple Exposure Assessment and persist last_check_attempt_at and last_successful_update_at separately.", values)


def _visibility_check(context: AuditContext) -> FunctionalCheck:
    check = FunctionalCheck("scan.visibility_integrity", "Scans", "visibility integrity scan", "Visibility integrity check returns component statuses.", "medium", "smoke")
    try:
        report = VisibilityIntegrityEngine(AuditDatabase(context.db_path)).build_report()
        return check.passed("Visibility integrity report built.", {"components": len(report.components)})
    except Exception as exc:
        return check.failed(str(exc), "Fix visibility integrity report generation.", {"exception": type(exc).__name__})


def _baseline_check(context: AuditContext) -> FunctionalCheck:
    check = FunctionalCheck("scan.baseline_drift", "Scans", "baseline drift scan", "Baseline drift engine can compare scan state.", "medium", "smoke")
    latest = AuditDatabase(context.db_path).latest_scan_result()
    if latest is None:
        return check.skipped("No latest scan available.", "Run Safe Scan before baseline drift audit.")
    try:
        comparison = BaselineDriftEngine().compare_current_state(latest.to_dict())
        return check.passed("Baseline drift comparison completed.", {"summary": comparison.get("summary", {})})
    except Exception as exc:
        return check.failed(str(exc), "Fix baseline drift comparison against current scan.", {"exception": type(exc).__name__})


def _assessment_check(context: AuditContext) -> FunctionalCheck:
    check = FunctionalCheck("core.assessment_builder", "Core", "assessment builder", "Security assessment builds from real local data structures.", "high", "smoke")
    db = AuditDatabase(context.db_path)
    try:
        assessment = build_security_assessment(scan_result=db.latest_scan_result(), monitor_state=db.get_background_monitor_status(), events=db.latest_monitor_events(limit=20), settings=None)
        if assessment.assessment_status == "unavailable":
            return check.warn("Assessment built but sources are unavailable.", "Run Safe Scan and collect monitor events before UAT.", assessment.to_dict())
        return check.passed("Assessment built from available data.", {"status": assessment.assessment_status, "limitations": assessment.limitations})
    except Exception as exc:
        return check.failed(str(exc), "Fix assessment builder before UAT.", {"exception": type(exc).__name__})


def _framework_mapping_check() -> FunctionalCheck:
    check = FunctionalCheck("framework.mapping", "Framework Mapping", "framework mapping integrity", "Framework IDs are valid and wording avoids unsupported claims.", "blocker", "smoke")
    try:
        from mac_audit_agent.rules import RULES

        bad: list[str] = []
        for rule in RULES:
            for mapping in getattr(rule, "framework_mappings", []) or []:
                if mapping.framework == "NIST_CSF_2_0" and mapping.category not in NIST_CSF_FUNCTIONS:
                    bad.append(f"{rule.rule_id}: invalid NIST CSF category {mapping.category}")
                if mapping.framework == "NIST_800_53_REV5" and not re.match(r"^[A-Z]{2}-\\d+(?:\\(\\d+\\))?$", mapping.id):
                    bad.append(f"{rule.rule_id}: invalid 800-53 id {mapping.id}")
                if mapping.framework == "MITRE_ATTACK_MACOS" and not re.match(r"^T\\d{4}(?:\\.\\d{3})?$", mapping.id):
                    bad.append(f"{rule.rule_id}: invalid MITRE id {mapping.id}")
        unsupported = []
        for path in ["README.md"]:
            text = __import__("pathlib").Path(path).read_text(encoding="utf-8", errors="ignore").lower()
            for phrase in ["government approved", "certified compliant", "certified, compliant"]:
                if phrase in text:
                    unsupported.append(f"{path}: {phrase}")
        if bad or unsupported:
            return check.failed("Framework mapping or wording problems found.", "Fix mapping IDs and replace unsupported compliance wording with mapped/aligned wording.", {"bad_mappings": bad[:25], "unsupported_wording": unsupported})
        return check.passed("Framework mapping format and unsupported wording checks passed.", {})
    except Exception as exc:
        return check.failed(str(exc), "Fix framework mapping audit path.", {"exception": type(exc).__name__})


def _freshness_check(context: AuditContext) -> FunctionalCheck:
    check = FunctionalCheck("freshness.timestamps", "Freshness", "data freshness", "Freshness timestamps are timezone-aware or explicitly unavailable.", "critical", "smoke")
    db = AuditDatabase(context.db_path)
    values = {
        "database_write_date": db.get_background_monitor_state("pre_uat_event_write_probe_at", ""),
        "monitor_heartbeat": db.get_background_monitor_state("last_heartbeat", ""),
        "notifier_heartbeat": db.get_background_monitor_state("notifier_last_poll", db.get_background_monitor_state("user_notifier_last_poll", "")),
    }
    latest = db.latest_scan_result()
    if latest:
        values["scan_timestamp"] = latest.timestamp
    invalid = {key: value for key, value in values.items() if value and not _timestamp_ok(value)}
    if invalid:
        check.failure_stage = "stale_data"
        return check.failed("Freshness timestamps are not timezone-aware ISO values.", "Use utc_now_iso internally and local-time formatting only in UI display.", invalid)
    if not any(values.values()):
        return check.warn("No freshness timestamps available.", "Run Safe Scan and monitor health checks before UAT.", values)
    return check.passed("Freshness timestamps are present and parseable where available.", values)


def _timestamp_ok(value: str) -> bool:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None
