from __future__ import annotations

import importlib.metadata
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from mac_audit_agent.models import BackgroundMonitorEvent, Finding, utc_now_iso
from mac_audit_agent.notification_manager import MANDATORY_VISIBLE_ALERT_EVENT_TYPES, OVERLAY_STATE_PATH, NotificationManager
from mac_audit_agent.privacy import redact_text
from mac_audit_agent.rules import canonical_event_type
from mac_audit_agent.reporting import get_reports_dir
from mac_audit_agent.storage import AuditDatabase, json_safe
from mac_audit_agent.version import APP_VERSION


CoverageStatus = str
RELEASE_GATE_EVIDENCE_MAX_AGE_SECONDS = 7 * 24 * 60 * 60
RELEASE_PYTEST_TIMEOUT_SECONDS = 30 * 60


def _parse_dt(value: str) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _age_seconds(value: str) -> int | None:
    parsed = _parse_dt(value)
    if parsed is None:
        return None
    return max(0, int((datetime.now(timezone.utc) - parsed).total_seconds()))


@dataclass
class AlertPipelineHealth:
    generated_at: str
    last_event_detected: str = ""
    last_event_stored: str = ""
    last_event_consumed_by_notifier: str = ""
    last_alert_shown: str = ""
    last_failure_stage: str = ""
    suppressed_count: int = 0
    no_policy_match_count: int = 0
    db_path_mismatch_status: str = "unknown"
    traces: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AlertPipelineInspector:
    def __init__(self, db: AuditDatabase) -> None:
        self.db = db

    def build_health(self, limit: int = 50) -> AlertPipelineHealth:
        traces = [trace.to_dict() for trace in self.db.latest_event_alert_traces(limit=limit)]
        events = self.db.latest_monitor_events(limit=1)
        deliveries = self.db.latest_alert_delivery_records(limit=25)
        last_event = events[0] if events else None
        shown = next((item for item in deliveries if item.overlay_success or item.dialog_success or item.notification_success), None)
        suppressed = sum(1 for item in traces if item.get("alert_suppressed"))
        no_policy = sum(1 for item in traces if item.get("notification_policy_result") == "no_policy_match")
        mismatch = "unknown"
        for trace in traces:
            stored_path = str(trace.get("stored_db_path", "") or "")
            notifier_path = str(trace.get("notifier_db_path", "") or "")
            if stored_path and notifier_path:
                mismatch = "mismatch" if Path(stored_path) != Path(notifier_path) else "match"
                break
        return AlertPipelineHealth(
            generated_at=utc_now_iso(),
            last_event_detected=f"{last_event.timestamp} {last_event.event_type}" if last_event else "",
            last_event_stored=self.db.get_background_monitor_state("last_event_timestamp", ""),
            last_event_consumed_by_notifier=next((str(item.get("notifier_seen_at", "")) for item in traces if item.get("notifier_seen")), ""),
            last_alert_shown=f"{shown.updated_at} {shown.event_id}" if shown else "",
            last_failure_stage=self._last_failure_stage(traces),
            suppressed_count=suppressed,
            no_policy_match_count=no_policy,
            db_path_mismatch_status=mismatch,
            traces=traces,
        )

    def _last_failure_stage(self, traces: list[dict[str, Any]]) -> str:
        for trace in traces:
            if not trace.get("stored_success"):
                return "sqlite_store"
            if trace.get("stored_success") and not trace.get("notifier_seen"):
                return "notifier_consume"
            if trace.get("notification_policy_checked") and trace.get("notification_policy_result") in {"no_policy_match", "invalid_incomplete"}:
                return f"policy:{trace.get('notification_policy_result')}"
            if trace.get("alert_required") and trace.get("alert_suppressed"):
                return f"suppressed:{trace.get('alert_suppression_reason', '')}"
            if trace.get("overlay_dispatch_attempted") and str(trace.get("overlay_dispatch_result", "")).upper() == "FAILED":
                return "overlay_dispatch"
        return ""


@dataclass
class CoverageComponent:
    component: str
    status: CoverageStatus
    last_successful_run: str = ""
    last_event: str = ""
    last_error: str = ""
    heartbeat_age_seconds: int | None = None
    permission_status: str = "unknown"
    failure_reason: str = ""
    recommended_fix: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class MonitoringCoverageReport:
    generated_at: str
    score: int
    problems: list[str]
    components: list[CoverageComponent]

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "MonitoringCoverageScore": self.score,
            "score": self.score,
            "problems": self.problems,
            "components": [item.to_dict() for item in self.components],
        }


class MonitoringCoverageEngine:
    COMPONENTS = [
        ("USB detector", "detector_enabled_hardware", {"usb_device_connected", "usb_device_removed", "new_usb_device_detected"}),
        ("Bluetooth detector", "detector_enabled_hardware", {"bluetooth_device_connected", "bluetooth_device_disconnected", "bluetooth_inventory_changed"}),
        ("Lid/display detector", "detector_enabled_session", {"lid_opened", "lid_closed", "display_wake", "display_sleep", "possible_lid_opened", "possible_lid_closed"}),
        ("Session detector", "detector_enabled_session", {"screen_unlocked", "screen_locked", "session_unlocked", "session_locked"}),
        ("Input/idle detector", "detector_enabled_session", {"idle_resume_detected", "mouse_or_keyboard_activity_after_idle", "input_activity_resumed_after_idle"}),
        ("Network detector", "detector_enabled_network", {"new_network_connection_detected", "network_ip_assigned", "vpn_connected"}),
        ("Persistence detector", "detector_enabled_persistence", {"launchagent_added", "launchdaemon_added", "persistence_item_created"}),
        ("Admin/user detector", "detector_enabled_sharing", {"new_admin_user_detected", "admin_user_removed"}),
        ("Apple Exposure source", "", {"apple_security_forecast_elevated", "apple_security_forecast_urgent"}),
        ("System daemon", "", set()),
        ("User notifier", "", set()),
        ("Alert overlay", "", set()),
        ("SQLite storage", "", set()),
        ("Report exporter", "", set()),
    ]

    def __init__(self, db: AuditDatabase, reports_dir: Path | None = None, overlay_state_path: Path | None = None) -> None:
        self.db = db
        self.reports_dir = reports_dir or get_reports_dir()
        self.overlay_state_path = overlay_state_path or OVERLAY_STATE_PATH

    def build_report(self) -> MonitoringCoverageReport:
        events = self.db.latest_monitor_events(limit=500)
        by_type = {event.event_type: event for event in events}
        heartbeat = self.db.latest_monitor_heartbeat()
        heartbeat_age = _age_seconds(heartbeat)
        detector_last_run = self.db.get_background_monitor_state("detector_last_run_timestamp", "")
        detector_errors = self.db.get_background_monitor_state("detector_errors", "")
        components: list[CoverageComponent] = []
        for name, enabled_key, event_types in self.COMPONENTS:
            components.append(self._component(name, enabled_key, event_types, by_type, detector_last_run, detector_errors, heartbeat_age))
        problems = [item.component for item in components if item.status in {"degraded", "failing", "disabled"}]
        score = max(0, min(100, round(sum(self._points(item.status) for item in components) / (len(components) * 4) * 100)))
        return MonitoringCoverageReport(utc_now_iso(), score, problems, components)

    def _component(
        self,
        name: str,
        enabled_key: str,
        event_types: set[str],
        events: dict[str, BackgroundMonitorEvent],
        detector_last_run: str,
        detector_errors: str,
        heartbeat_age: int | None,
    ) -> CoverageComponent:
        last_event = next((events[item] for item in event_types if item in events), None)
        enabled = self.db.get_background_monitor_state(enabled_key, "1") != "0" if enabled_key else True
        last_error = detector_errors if name.endswith("detector") else ""
        status = "healthy"
        failure_reason = ""
        fix = "No action required."
        if not enabled:
            status = "disabled"
            failure_reason = "Component disabled in monitor state."
            fix = "Enable the component or document why it is unsupported."
        elif name == "SQLite storage":
            try:
                quick = self.db.conn.execute("PRAGMA quick_check").fetchone()
                if str(quick[0] if quick else "").lower() != "ok":
                    status = "failing"
                    failure_reason = "SQLite quick_check failed."
                    fix = "Inspect or restore the database."
            except Exception as exc:
                status = "failing"
                failure_reason = str(exc)
                fix = "Fix database permissions or restore the DB."
        elif name == "Report exporter":
            try:
                self.reports_dir.mkdir(parents=True, exist_ok=True)
                test_path = self.reports_dir / ".write_test"
                test_path.write_text("ok", encoding="utf-8")
                test_path.unlink(missing_ok=True)
            except Exception as exc:
                status = "failing"
                failure_reason = str(exc)
                fix = "Fix report directory permissions."
        elif name == "User notifier":
            notification_status = self.db.get_background_monitor_state("notification_status", "")
            if "failed" in notification_status.lower() or "unavailable" in notification_status.lower():
                status = "failing"
                failure_reason = notification_status
                fix = "Repair the user notifier and rerun event flow verification."
        elif name == "Alert overlay":
            overlay_error = self.db.get_background_monitor_state("last_overlay_error", "")
            if overlay_error:
                status = "degraded"
                failure_reason = overlay_error
                fix = "Open Alert Pipeline Health and repair overlay launch failures."
            else:
                try:
                    self.overlay_state_path.parent.mkdir(parents=True, exist_ok=True)
                    test_path = self.overlay_state_path.with_name(".msaa_overlay_write_test")
                    test_path.write_text("ok", encoding="utf-8")
                    test_path.unlink(missing_ok=True)
                except Exception as exc:
                    fallback = self.db.logs_dir / "state" / "security_overlay.json"
                    try:
                        fallback.parent.mkdir(parents=True, exist_ok=True)
                        fallback_test = fallback.with_name(".msaa_overlay_write_test")
                        fallback_test.write_text("ok", encoding="utf-8")
                        fallback_test.unlink(missing_ok=True)
                        status = "degraded"
                        failure_reason = f"Default overlay state path is not writable; using fallback: {exc}"
                        fix = f"Repair ownership and permissions for {self.overlay_state_path.parent}; fallback state path is {fallback}."
                    except Exception as fallback_exc:
                        status = "failing"
                        failure_reason = f"Overlay state path and fallback are not writable: {exc}; fallback error: {fallback_exc}"
                        fix = f"Repair ownership and permissions for {self.overlay_state_path.parent} or {fallback.parent} so the logged-in user can write overlay state."
        elif name == "System daemon":
            if heartbeat_age is None:
                status = "degraded"
                failure_reason = "No monitor heartbeat recorded."
                fix = "Start the monitor or install the LaunchDaemon/LaunchAgent."
            elif heartbeat_age > 180:
                status = "failing"
                failure_reason = f"Heartbeat stale: {heartbeat_age}s."
                fix = "Restart the monitor and verify heartbeat writes."
        elif last_error:
            status = "degraded"
            failure_reason = last_error
            fix = "Review detector errors and rerun the monitor."
        elif detector_last_run and _age_seconds(detector_last_run) and (_age_seconds(detector_last_run) or 0) > 900:
            status = "degraded"
            failure_reason = "Detector run timestamp is stale."
            fix = "Restart background monitoring."
        return CoverageComponent(
            component=name,
            status=status,
            last_successful_run=detector_last_run,
            last_event=f"{last_event.timestamp} {last_event.event_type}" if last_event else "",
            last_error=last_error,
            heartbeat_age_seconds=heartbeat_age,
            permission_status="available" if status != "unsupported" else "unsupported",
            failure_reason=failure_reason,
            recommended_fix=fix,
        )

    def _points(self, status: str) -> int:
        return {"healthy": 4, "degraded": 2, "unsupported": 2, "disabled": 1, "failing": 0}.get(status, 0)


@dataclass
class ReleaseReadinessCheck:
    check: str
    status: str
    evidence: str = ""
    recommended_fix: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ReleaseReadinessReport:
    generated_at: str
    score: int
    status: str
    checks: list[ReleaseReadinessCheck]

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "ReleaseReadinessScore": self.score,
            "status": self.status,
            "checks": [item.to_dict() for item in self.checks],
        }


class ReleaseReadinessEngine:
    def __init__(self, db: AuditDatabase, repo_root: Path | None = None, pytest_python: str | Path | None = None) -> None:
        self.db = db
        self.repo_root = repo_root or Path(__file__).resolve().parent.parent
        self.pytest_python = str(pytest_python or os.environ.get("MSAA_RELEASE_PYTEST_PYTHON") or "python3")

    def build_report(self, *, run_expensive: bool = False) -> ReleaseReadinessReport:
        checks = [
            *self._documentation_checks(),
            self._pyproject_check(),
            self._python_runtime_check(),
            self._clean_install_check(),
            self._assets_check(),
            self._reports_export_check(),
            self._no_bundled_runtime_data_check(),
            self._production_ui_check(),
            self._broken_actions_check(),
            self._sqlite_check(),
            self._system_daemon_audit_check(),
            self._user_notifier_audit_check(),
            self._apple_exposure_check(),
            self._alert_pipeline_check(),
        ]
        if run_expensive:
            checks.append(self._record_release_gate_check("compileall_passes", self._compileall_check()))
            checks.append(self._record_release_gate_check("tests_pass", self._pytest_check()))
            checks.append(self._record_release_gate_check("python_m_build_passes", self._build_check()))
            checks.append(self._record_release_gate_check("twine_check_passes", self._twine_check()))
        else:
            checks.append(self._saved_release_gate_check("tests_pass", "tests pass", "Run pytest before release."))
            checks.append(self._saved_release_gate_check("compileall_passes", "compileall passes", "Run python -m compileall -q mac_audit_agent."))
            checks.append(self._saved_release_gate_check("python_m_build_passes", "python -m build passes", "Run python -m build before release."))
            checks.append(self._saved_release_gate_check("twine_check_passes", "twine check passes", "Run twine check dist/* before release."))
        score = round(sum(self._check_points(item.status) for item in checks) / (len(checks) * 2) * 100)
        status = "ready" if score >= 95 and all(item.status == "pass" for item in checks) else ("blocked" if any(item.status == "block" for item in checks) else "needs work")
        return ReleaseReadinessReport(utc_now_iso(), score, status, checks)

    def _file_check(self, name: str, path: Path) -> ReleaseReadinessCheck:
        return ReleaseReadinessCheck(name, "pass" if path.exists() else "block", str(path), "Add the missing release file.")

    def _file_contains(self, name: str, path: Path, needle: str) -> ReleaseReadinessCheck:
        text = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
        return ReleaseReadinessCheck(name, "pass" if needle.lower() in text.lower() else "block", str(path), f"Document {needle}.")

    def _documentation_checks(self) -> list[ReleaseReadinessCheck]:
        if (self.repo_root / "pyproject.toml").exists():
            return [
                self._file_check("README exists", self.repo_root / "README.md"),
                self._file_check("LICENSE exists", self.repo_root / "LICENSE"),
                self._file_check("SECURITY.md exists", self.repo_root / "SECURITY.md"),
                self._file_check("Privacy documentation exists", self.repo_root / "docs" / "PRIVACY.md"),
                self._file_contains("Uninstall instructions exist", self.repo_root / "README.md", "Uninstall"),
            ]
        try:
            metadata = importlib.metadata.metadata("macos-security-audit-agent")
        except Exception as exc:
            return [
                ReleaseReadinessCheck("README exists", "needs work", f"Installed package metadata unavailable: {exc}", "Run release readiness from the source tree."),
                ReleaseReadinessCheck("LICENSE exists", "needs work", f"Installed package metadata unavailable: {exc}", "Run release readiness from the source tree."),
                ReleaseReadinessCheck("SECURITY.md exists", "needs work", "Source-tree security policy is not packaged in the wheel.", "Run release readiness from the source tree."),
                ReleaseReadinessCheck("Privacy documentation exists", "needs work", "Source-tree privacy documentation is not packaged in the wheel.", "Run release readiness from the source tree."),
                ReleaseReadinessCheck("Uninstall instructions exist", "needs work", "Source-tree uninstall instructions are not packaged in the wheel.", "Run release readiness from the source tree."),
            ]
        has_readme = bool((metadata.get("Description") or "").strip())
        has_license = bool((metadata.get("License-Expression") or metadata.get("License") or "").strip())
        return [
            ReleaseReadinessCheck("README exists", "pass" if has_readme else "needs work", "package long description metadata" if has_readme else "No installed long description metadata.", "Run release readiness from the source tree before publishing."),
            ReleaseReadinessCheck("LICENSE exists", "pass" if has_license else "needs work", "package license metadata" if has_license else "No installed license metadata.", "Run release readiness from the source tree before publishing."),
            ReleaseReadinessCheck("SECURITY.md exists", "needs work", "Source-tree security policy is not packaged in the wheel.", "Run release readiness from the source tree before publishing."),
            ReleaseReadinessCheck("Privacy documentation exists", "needs work", "Source-tree privacy documentation is not packaged in the wheel.", "Run release readiness from the source tree before publishing."),
            ReleaseReadinessCheck("Uninstall instructions exist", "needs work", "Source-tree uninstall instructions are not packaged in the wheel.", "Run release readiness from the source tree before publishing."),
        ]

    def _pyproject_check(self) -> ReleaseReadinessCheck:
        pyproject = self.repo_root / "pyproject.toml"
        if pyproject.exists():
            text = pyproject.read_text(encoding="utf-8", errors="replace")
            ok = (
                'name = "macos-security-audit-agent"' in text
                and 'macos-security-audit-agent = "mac_audit_agent.cli:main"' in text
                and 'requires-python = ">=3.10"' in text
            )
            return ReleaseReadinessCheck("PyPI metadata valid", "pass" if ok else "block", "package name, Python requirement, and console command checked", "Fix pyproject.toml metadata.")
        try:
            metadata = importlib.metadata.metadata("macos-security-audit-agent")
            distribution = importlib.metadata.distribution("macos-security-audit-agent")
            commands = {
                entry_point.name: entry_point.value
                for entry_point in distribution.entry_points
                if entry_point.group == "console_scripts"
            }
            ok = (
                metadata.get("Name") == "macos-security-audit-agent"
                and metadata.get("Requires-Python") == ">=3.10"
                and commands.get("macos-security-audit-agent") == "mac_audit_agent.cli:main"
            )
            evidence = json.dumps(
                {
                    "source": "installed package metadata",
                    "name": metadata.get("Name", ""),
                    "requires_python": metadata.get("Requires-Python", ""),
                    "console_script": commands.get("macos-security-audit-agent", ""),
                },
                sort_keys=True,
            )
            return ReleaseReadinessCheck("PyPI metadata valid", "pass" if ok else "block", evidence, "Fix installed package metadata and console entry point.")
        except Exception as exc:
            return ReleaseReadinessCheck("PyPI metadata valid", "block", f"pyproject.toml unavailable and installed metadata check failed: {exc}", "Fix pyproject.toml metadata.")

    def _python_runtime_check(self) -> ReleaseReadinessCheck:
        version = sys.version_info
        current = f"{version.major}.{version.minor}.{version.micro}"
        ok = version >= (3, 10)
        return ReleaseReadinessCheck(
            "Python runtime supports package metadata",
            "pass" if ok else "block",
            f"current Python {current}; pyproject requires >=3.10",
            "Run release packaging and clean install checks with Python 3.10 or newer.",
        )

    def _clean_install_check(self) -> ReleaseReadinessCheck:
        payload = self._latest_clean_install_verification()
        if not payload:
            return ReleaseReadinessCheck(
                "clean wheel install verified",
                "needs work",
                "No clean install verification report saved.",
                "Run macos-security-audit-agent --verify-clean-install with Python 3.10 or newer.",
            )
        stages = payload.get("stages", []) if isinstance(payload, dict) else []
        if not isinstance(stages, list) or not stages:
            return ReleaseReadinessCheck("clean wheel install verified", "block", json.dumps(payload, sort_keys=True), "Rerun clean install verification; saved report is malformed.")
        by_id = {str(stage.get("check_id", "")): str(stage.get("status", "")).upper() for stage in stages if isinstance(stage, dict)}
        required = {"python_version", "wheel_exists", "venv_create", "wheel_install", "import_sweep", "resource_check", "console_help", "release_readiness_cli"}
        missing = sorted(required - set(by_id))
        failed = sorted(check_id for check_id, status in by_id.items() if status == "FAIL")
        ok = not missing and not failed and all(by_id.get(check_id) == "PASS" for check_id in required)
        status = "pass" if ok else "block"
        evidence = json.dumps({"python": payload.get("python", ""), "wheel": payload.get("wheel", ""), "missing": missing, "failed": failed, "stages": stages}, sort_keys=True)
        return ReleaseReadinessCheck("clean wheel install verified", status, evidence, "Run clean install verification in a Python 3.10+ venv and fix failing install/import/resource checks.")

    def _assets_check(self) -> ReleaseReadinessCheck:
        try:
            from mac_audit_agent.assets import get_asset_path

            assets = [get_asset_path("logo.png"), get_asset_path("app_icon.icns")]
        except Exception:
            assets = [self.repo_root / "mac_audit_agent" / "assets" / "logo.png", self.repo_root / "mac_audit_agent" / "assets" / "app_icon.icns"]
        missing = [str(path) for path in assets if not path.exists()]
        return ReleaseReadinessCheck("assets included", "pass" if not missing else "block", ", ".join(missing) or "required assets found", "Include package assets.")

    def _reports_export_check(self) -> ReleaseReadinessCheck:
        try:
            from mac_audit_agent.reporting import export_scan_result_html, export_scan_result_json

            sarif_path = Path(tempfile.gettempdir()) / "msaa-readiness.sarif"
            export_sarif([], sarif_path)
            sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
            sarif_path.unlink(missing_ok=True)
            ok = (
                callable(export_scan_result_html)
                and callable(export_scan_result_json)
                and sarif.get("version") == "2.1.0"
                and isinstance(sarif.get("runs"), list)
            )
        except Exception as exc:
            return ReleaseReadinessCheck("reports export", "block", str(exc), "Fix report export imports.")
        return ReleaseReadinessCheck("reports export", "pass" if ok else "block", "HTML, JSON, and SARIF exporters verified.", "Fix report exporters.")

    def _no_bundled_runtime_data_check(self) -> ReleaseReadinessCheck:
        candidates = list(self.repo_root.glob("**/*.sqlite*")) + list(self.repo_root.glob("**/*.db")) + list(self.repo_root.glob("**/*.log"))
        candidates = [path for path in candidates if ".git" not in path.parts and "dist" not in path.parts]
        return ReleaseReadinessCheck("no stale logs/DB bundled", "pass" if not candidates else "block", ", ".join(str(path) for path in candidates[:5]), "Remove runtime logs and databases from the source tree.")

    def _production_ui_check(self) -> ReleaseReadinessCheck:
        banned = re.compile(r"\b(demo|placeholder|coming soon|not implemented|simulated forecast|simulate|synthetic|mock)\b", re.IGNORECASE)
        control_call = re.compile(r"(QPushButton|QAction|make_forecast_button|setPlaceholderText|QLabel)\((?P<quote>['\"])(?P<label>.*?)(?P=quote)")
        matches: list[str] = []
        for path in (self.repo_root / "mac_audit_agent" / "ui").glob("*.py"):
            for line_no, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
                found = control_call.search(line)
                if not found:
                    continue
                label = found.group("label")
                if not banned.search(label):
                    continue
                if self._is_developer_only_control_line(line):
                    continue
                matches.append(f"{path.name}:{line_no}:{label}")
        evidence = ", ".join(matches[:10]) if matches else "static visible-label scan found no production demo/placeholder controls"
        return ReleaseReadinessCheck("no demo or placeholder production UI", "pass" if not matches else "block", evidence, "Hide developer-only UI and remove placeholder controls.")

    def _broken_actions_check(self) -> ReleaseReadinessCheck:
        text = (self.repo_root / "docs" / "UI_BUTTON_INVENTORY.md").read_text(encoding="utf-8", errors="replace") if (self.repo_root / "docs" / "UI_BUTTON_INVENTORY.md").exists() else ""
        ui_state_test = (self.repo_root / "mac_audit_agent" / "tests" / "test_ui_state_awareness.py")
        tests_text = ui_state_test.read_text(encoding="utf-8", errors="replace") if ui_state_test.exists() else ""
        required_tests = [
            "test_clean_install_disabled_visible_buttons_explain_why",
            "test_production_ui_hides_demo_test_and_synthetic_controls",
            "test_developer_mode_reveals_synthetic_controls_only_when_enabled",
        ]
        missing_tests = [name for name in required_tests if name not in tests_text]
        doc_ok = "No-op" not in text and "Broken" not in text
        ok = doc_ok and not missing_tests
        evidence = "UI inventory and state-awareness tests reviewed." if ok else json.dumps({"inventory_ok": doc_ok, "missing_tests": missing_tests}, sort_keys=True)
        return ReleaseReadinessCheck("no broken actions", "pass" if ok else "needs work", evidence, "Hide broken controls or add disabled reasons.")

    def _is_developer_only_control_line(self, line: str) -> bool:
        lowered = line.lower()
        return (
            "developer:" in lowered
            or "developer_only" in lowered
            or "developer_mode" in lowered
            or "_test_" in lowered
            or "test_" in lowered
            or "lockdown_dry_run" in lowered
        )

    def _sqlite_check(self) -> ReleaseReadinessCheck:
        try:
            quick = self.db.conn.execute("PRAGMA quick_check").fetchone()
            ok = str(quick[0] if quick else "").lower() == "ok"
        except Exception as exc:
            return ReleaseReadinessCheck("SQLite storage", "block", str(exc), "Fix database access.")
        return ReleaseReadinessCheck("SQLite storage", "pass" if ok else "block", "PRAGMA quick_check", "Repair the database.")

    def _system_daemon_audit_check(self) -> ReleaseReadinessCheck:
        return self._monitor_integrity_check("system daemon audit passes", "system")

    def _user_notifier_audit_check(self) -> ReleaseReadinessCheck:
        return self._monitor_integrity_check("user notifier audit passes", "user")

    def _monitor_integrity_check(self, name: str, scope: str) -> ReleaseReadinessCheck:
        try:
            from mac_audit_agent.launch_agent import verify_protected_monitor_integrity

            result = verify_protected_monitor_integrity(scope=scope)
        except Exception as exc:
            return ReleaseReadinessCheck(name, "block", str(exc), "Fix monitor integrity audit.")
        installed = bool(result.get("installed"))
        tamper_detected = bool(result.get("tamper_detected"))
        if installed and not tamper_detected:
            status = "pass"
        elif installed and tamper_detected:
            status = "block"
        else:
            status = "needs work"
        return ReleaseReadinessCheck(
            name,
            status,
            json.dumps({"installed": installed, "tamper_detected": tamper_detected, "evidence": result.get("evidence", [])[:3]}, sort_keys=True),
            "Install or repair the monitor, then rerun the readiness audit.",
        )

    def _apple_exposure_check(self) -> ReleaseReadinessCheck:
        try:
            from mac_audit_agent.config import AuditConfig
            from mac_audit_agent.cve_radar import AppleSecurityForecastEngine

            config = AuditConfig(logs_dir=self.db.logs_dir, cache_dir=self.repo_root / ".cache" / "msaa-readiness")
            state = AppleSecurityForecastEngine(self.db, config).load_cached_state()
            ok = bool(state.get("state_text")) and not state.get("simulated", False)
        except Exception as exc:
            return ReleaseReadinessCheck("Apple Exposure Assessment works or degrades cleanly", "block", str(exc), "Fix Apple Exposure cache and diagnostics handling.")
        return ReleaseReadinessCheck(
            "Apple Exposure Assessment works or degrades cleanly",
            "pass" if ok else "needs work",
            json.dumps({"state_text": state.get("state_text", ""), "last_error": state.get("last_error", ""), "card_count": state.get("card_count", 0)}, sort_keys=True),
            "Refresh Apple Exposure Assessment and verify Mac-focused active cards.",
        )

    def _alert_pipeline_check(self) -> ReleaseReadinessCheck:
        health = AlertPipelineInspector(self.db).build_health(limit=25)
        event_flow = self._latest_event_flow_verification()
        visible_alert_verification = self._latest_visible_alert_verification()
        policy_gaps = mandatory_alert_policy_gaps(self.db)
        successful_trace = any(
            trace.get("stored_success")
            and trace.get("notification_policy_checked")
            and (
                str(trace.get("overlay_dispatch_result", "")).upper() == "SUCCESS"
                or trace.get("alert_suppressed")
                or not trace.get("alert_required")
            )
            for trace in health.traces
        )
        event_flow_ok = self._event_flow_proves_visible_alert(event_flow)
        visible_alert_ok = self._visible_alert_verification_passed(visible_alert_verification)
        ok = (successful_trace or event_flow_ok or visible_alert_ok) and not policy_gaps and health.db_path_mismatch_status in {"match", "unknown"} and not health.last_failure_stage
        evidence = {"alert_pipeline_health": health.to_dict(), "deployment_event_flow": event_flow, "visible_alert_verification": visible_alert_verification, "mandatory_alert_policy_gaps": policy_gaps}
        return ReleaseReadinessCheck("alert pipeline passes synthetic event test", "pass" if ok else "needs work", json.dumps(evidence, sort_keys=True), "Run event flow verification and fix the first failing stage.")

    def _event_flow_proves_visible_alert(self, event_flow: dict[str, Any]) -> bool:
        stages = event_flow.get("stages", []) if isinstance(event_flow, dict) else []
        if not isinstance(stages, list) or not stages:
            return False
        by_id = {str(stage.get("check_id", "")): str(stage.get("status", "")).upper() for stage in stages if isinstance(stage, dict)}
        db_ok = by_id.get("shared_db_receives_event") == "PASS" or by_id.get("detector_writes_event") == "PASS" or by_id.get("daemon_wrote_event") == "PASS"
        notifier_ok = by_id.get("notifier_receives_event") == "PASS" or by_id.get("notifier_seen_event") == "PASS"
        visible_ok = by_id.get("visible_alert_delivery") == "PASS" or by_id.get("overlay_displays_event") == "PASS"
        failures = [status for status in by_id.values() if status == "FAIL"]
        return db_ok and notifier_ok and visible_ok and not failures

    def _visible_alert_verification_passed(self, payload: dict[str, Any]) -> bool:
        stages = payload.get("stages", []) if isinstance(payload, dict) else []
        if not isinstance(stages, list) or not stages:
            return False
        event_type = canonical_event_type(str(payload.get("event_type", "")))
        mandatory_types = {canonical_event_type(item) for item in MANDATORY_VISIBLE_ALERT_EVENT_TYPES}
        if event_type not in mandatory_types:
            return False
        by_id = {str(stage.get("check_id", "")): str(stage.get("status", "")).upper() for stage in stages if isinstance(stage, dict)}
        return (
            by_id.get("sqlite_store") == "PASS"
            and by_id.get("notifier_policy_checked") == "PASS"
            and by_id.get("overlay_dispatch") == "PASS"
            and by_id.get("visible_alert_delivery") == "PASS"
            and not any(status == "FAIL" for status in by_id.values())
        )

    def _latest_event_flow_verification(self) -> dict[str, Any]:
        raw = self.db.get_background_monitor_state("deployment_event_flow_last_report_json", "")
        if not raw:
            return {}
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {"status": "invalid", "error": "deployment_event_flow_last_report_json is not valid JSON"}
        return parsed if isinstance(parsed, dict) else {}

    def _latest_visible_alert_verification(self) -> dict[str, Any]:
        raw = self.db.get_background_monitor_state("visible_alert_verification_last_report_json", "")
        if not raw:
            return {}
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {"status": "invalid", "error": "visible_alert_verification_last_report_json is not valid JSON"}
        return parsed if isinstance(parsed, dict) else {}

    def _latest_clean_install_verification(self) -> dict[str, Any]:
        raw = self.db.get_background_monitor_state("clean_install_last_report_json", "")
        if not raw:
            return {}
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {"status": "invalid", "error": "clean_install_last_report_json is not valid JSON"}
        return parsed if isinstance(parsed, dict) else {}

    def _record_release_gate_check(self, key: str, check: ReleaseReadinessCheck) -> ReleaseReadinessCheck:
        payload = {"generated_at": utc_now_iso(), "check": asdict(check)}
        self.db.set_background_monitor_state(f"release_readiness_gate:{key}", json.dumps(payload, sort_keys=True))
        return check

    def _saved_release_gate_check(self, key: str, name: str, recommended_fix: str) -> ReleaseReadinessCheck:
        raw = self.db.get_background_monitor_state(f"release_readiness_gate:{key}", "")
        if not raw:
            return ReleaseReadinessCheck(name, "needs work", "No recent saved verification evidence.", recommended_fix)
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            return ReleaseReadinessCheck(name, "block", "Saved verification evidence is not valid JSON.", recommended_fix)
        if not isinstance(payload, dict) or not isinstance(payload.get("check"), dict):
            return ReleaseReadinessCheck(name, "block", "Saved verification evidence is malformed.", recommended_fix)
        generated_at = str(payload.get("generated_at", ""))
        age = _age_seconds(generated_at)
        if age is None:
            return ReleaseReadinessCheck(name, "block", "Saved verification evidence has no valid timestamp.", recommended_fix)
        if age > RELEASE_GATE_EVIDENCE_MAX_AGE_SECONDS:
            return ReleaseReadinessCheck(name, "needs work", f"Saved verification evidence is stale: {age} seconds old.", recommended_fix)
        saved = payload["check"]
        status = str(saved.get("status", "needs work"))
        if status != "pass":
            return ReleaseReadinessCheck(name, "block" if status == "block" else "needs work", json.dumps(payload, sort_keys=True), recommended_fix)
        evidence = json.dumps({"generated_at": generated_at, "age_seconds": age, "evidence": saved.get("evidence", "")}, sort_keys=True)
        return ReleaseReadinessCheck(name, "pass", evidence, recommended_fix)

    def _compileall_check(self) -> ReleaseReadinessCheck:
        with tempfile.TemporaryDirectory(prefix="msaa-compileall-cache-") as cache_dir:
            env = os.environ.copy()
            env["PYTHONPYCACHEPREFIX"] = cache_dir
            result = subprocess.run(
                [sys.executable, "-m", "compileall", "-q", "mac_audit_agent"],
                cwd=self.repo_root,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
                env=env,
            )
        evidence = (result.stdout + result.stderr)[-1000:] or "compileall -q mac_audit_agent"
        return ReleaseReadinessCheck("compileall passes", "pass" if result.returncode == 0 else "block", evidence, "Fix syntax/import errors.")

    def _pytest_check(self) -> ReleaseReadinessCheck:
        command = [self.pytest_python, "-m", "pytest", "mac_audit_agent/tests", "-q"]
        output = ""
        try:
            env = os.environ.copy()
            env.setdefault("QT_QPA_PLATFORM", "offscreen")
            env.pop("VIRTUAL_ENV", None)
            path_entries = env.get("PATH", "").split(os.pathsep)
            current_venv_bin = str(Path(sys.prefix) / "bin")
            env["PATH"] = os.pathsep.join(entry for entry in path_entries if entry and entry != current_venv_bin)
            with tempfile.NamedTemporaryFile("w+", encoding="utf-8", errors="replace") as output_file:
                result = subprocess.run(
                    command,
                    cwd=self.repo_root,
                    stdout=output_file,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=RELEASE_PYTEST_TIMEOUT_SECONDS,
                    check=False,
                    env=env,
                )
                output_file.seek(0)
                output = output_file.read()
        except Exception as exc:
            return ReleaseReadinessCheck("tests pass", "block", json.dumps({"command": command, "error": str(exc)}, sort_keys=True), "Install dev dependencies and rerun pytest.")
        evidence = json.dumps(
            {
                "command": command,
                "returncode": result.returncode,
                "output_head": output[:3000],
                "output_tail": output[-3000:],
            },
            sort_keys=True,
        )
        return ReleaseReadinessCheck("tests pass", "pass" if result.returncode == 0 else "block", evidence, "Fix failing tests before release.")

    def _build_check(self) -> ReleaseReadinessCheck:
        python = self._python_with_module("build")
        if not python:
            return ReleaseReadinessCheck("python -m build passes", "block", "No configured Python can import build.", "Install build tooling and rerun python -m build.")
        try:
            result = subprocess.run([python, "-m", "build"], cwd=self.repo_root, capture_output=True, text=True, timeout=300, check=False)
        except Exception as exc:
            return ReleaseReadinessCheck("python -m build passes", "block", str(exc), "Install build tooling and rerun python -m build.")
        mode = "isolated"
        combined = result.stdout + result.stderr
        if result.returncode != 0 and self._build_failure_looks_network_bound(combined):
            fallback_python = self._python_with_modules(["build", "setuptools.build_meta"])
            if fallback_python:
                fallback = subprocess.run([fallback_python, "-m", "build", "--no-isolation"], cwd=self.repo_root, capture_output=True, text=True, timeout=300, check=False)
                result = fallback
                combined = fallback.stdout + fallback.stderr
                python = fallback_python
                mode = "no-isolation fallback after isolated build dependency fetch failed"
            else:
                combined += "\nNo configured Python can import both build and setuptools.build_meta for no-isolation fallback."
        return ReleaseReadinessCheck(
            "python -m build passes",
            "pass" if result.returncode == 0 else "block",
            json.dumps({"python": python, "mode": mode, "output": combined[-1000:]}, sort_keys=True),
            "Fix package metadata, manifest, or build dependencies.",
        )

    def _build_failure_looks_network_bound(self, output: str) -> bool:
        markers = [
            "Failed to establish a new connection",
            "nodename nor servname provided",
            "Could not find a version that satisfies the requirement",
            "No matching distribution found",
        ]
        return any(marker in output for marker in markers)

    def _twine_check(self) -> ReleaseReadinessCheck:
        artifacts = sorted(str(path) for path in (self.repo_root / "dist").glob("*"))
        artifacts = [
            path
            for path in artifacts
            if path.endswith((".whl", ".tar.gz")) and f"-{APP_VERSION}" in Path(path).name
        ]
        if not artifacts:
            return ReleaseReadinessCheck("twine check passes", "block", "No dist artifacts found.", "Run python -m build first.")
        python = self._python_with_module("twine")
        if not python:
            return ReleaseReadinessCheck("twine check passes", "block", "No configured Python can import twine.", "Install twine and rerun twine check dist/*.")
        try:
            result = subprocess.run([python, "-m", "twine", "check", *artifacts], cwd=self.repo_root, capture_output=True, text=True, timeout=120, check=False)
        except Exception as exc:
            return ReleaseReadinessCheck("twine check passes", "block", str(exc), "Install twine and rerun twine check dist/*.")
        return ReleaseReadinessCheck(
            "twine check passes",
            "pass" if result.returncode == 0 else "block",
            json.dumps({"python": python, "output": (result.stdout + result.stderr)[-1000:]}, sort_keys=True),
            "Fix package metadata or README rendering errors.",
        )

    def _python_with_module(self, module: str) -> str:
        return self._python_with_modules([module])

    def _python_with_modules(self, modules: list[str]) -> str:
        candidates = [
            os.environ.get("MSAA_RELEASE_BUILD_PYTHON", ""),
            sys.executable,
            self.pytest_python,
            str(self.repo_root / ".venv-release" / "bin" / "python"),
            shutil.which("python3") or "",
        ]
        seen: set[str] = set()
        for candidate in candidates:
            if not candidate or candidate in seen:
                continue
            seen.add(candidate)
            try:
                result = subprocess.run(
                    [candidate, "-c", "; ".join(f"import {module}" for module in modules)],
                    cwd=self.repo_root,
                    capture_output=True,
                    text=True,
                    timeout=20,
                    check=False,
                )
            except Exception:
                continue
            if result.returncode == 0:
                return candidate
        return ""

    def _check_points(self, status: str) -> int:
        return {"pass": 2, "needs work": 1, "block": 0}.get(status, 0)


class TrustDecayEngine:
    PENALTIES = {
        "launchdaemon_added": 12,
        "launchagent_added": 8,
        "new_usb_device_detected": 10,
        "usb_device_connected": 4,
        "remote_login_enabled": 12,
        "screen_sharing_enabled": 10,
        "new_network_connection_detected": 5,
        "new_outbound_connection_detected": 5,
        "new_admin_user_detected": 14,
        "protected_monitor_tamper_detected": 20,
        "heartbeat_stale": 8,
        "notifier_not_running": 10,
    }

    def __init__(self, db: AuditDatabase) -> None:
        self.db = db

    def build_report(self, limit: int = 100) -> dict[str, Any]:
        previous = int(self.db.get_background_monitor_state("trust_score_current", "100") or "100")
        events = list(reversed(self.db.latest_monitor_events(limit=limit)))
        score = 100
        changes: list[dict[str, Any]] = []
        for event in events:
            penalty = self.PENALTIES.get(event.event_type, 0)
            if penalty <= 0:
                continue
            before = score
            score = max(0, score - penalty)
            changes.append(
                {
                    "timestamp": event.timestamp,
                    "event_id": event.event_id,
                    "event_type": event.event_type,
                    "previous_score": before,
                    "current_score": score,
                    "delta": score - before,
                    "cause": event.evidence or event.event_type,
                    "recommended_action": event.recommendation or "Review the related event and preserve evidence before remediation.",
                }
            )
        delta = score - previous
        trend = "stable" if delta == 0 else ("improving" if delta > 0 else "declining")
        history = self._history()
        if delta != 0:
            history.append(
                {
                    "created_at": utc_now_iso(),
                    "previous_score": previous,
                    "current_score": score,
                    "delta": delta,
                    "trend": trend,
                    "causes": [item.get("cause", item.get("event_type", "")) for item in changes[-10:]],
                    "related_events": [
                        {
                            "event_id": item.get("event_id", ""),
                            "event_type": item.get("event_type", ""),
                            "timestamp": item.get("timestamp", ""),
                        }
                        for item in changes[-10:]
                    ],
                    "recommended_action": self._recommended_action(changes),
                }
            )
            history = history[-100:]
            self.db.set_background_monitor_state("trust_score_history_json", json.dumps(history, sort_keys=True))
        self.db.set_background_monitor_state("trust_score_previous", str(previous))
        self.db.set_background_monitor_state("trust_score_current", str(score))
        return {
            "generated_at": utc_now_iso(),
            "current_score": score,
            "previous_score": previous,
            "delta": delta,
            "trend": trend,
            "causes": changes[-10:],
            "event_impacts": changes,
            "score_history": history,
            "timeline": changes,
        }

    def _history(self) -> list[dict[str, Any]]:
        raw = self.db.get_background_monitor_state("trust_score_history_json", "[]")
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return []
        return [item for item in parsed if isinstance(item, dict)] if isinstance(parsed, list) else []

    def _recommended_action(self, changes: list[dict[str, Any]]) -> str:
        if not changes:
            return "Review monitoring coverage and recent events."
        severe = [item for item in changes if int(item.get("delta", 0)) <= -10]
        if severe:
            return "Review high-impact events, preserve evidence, and verify whether changes were authorized."
        return "Review related events and confirm whether the trust score change was expected."


class ConfigurationDriftEngine:
    TRACKED = {
        "remote_login": "Remote Login / SSH",
        "screen_sharing": "Screen Sharing",
        "file_sharing": "File Sharing",
        "firewall": "Firewall",
        "filevault": "FileVault",
        "gatekeeper": "Gatekeeper",
        "sip": "SIP",
        "dns_servers": "DNS servers",
        "vpn_state": "VPN state",
        "proxy_settings": "Proxy settings",
        "admin_users": "Admin users",
        "launchagents": "LaunchAgents",
        "launchdaemons": "LaunchDaemons",
        "login_items": "Login Items",
        "profiles_mdm": "Profiles/MDM indicators",
    }

    def __init__(self, db: AuditDatabase) -> None:
        self.db = db

    def update_snapshot(self, values: dict[str, Any], *, source_detector: str = "configuration_snapshot") -> dict[str, Any]:
        changes = []
        now = utc_now_iso()
        for key, label in self.TRACKED.items():
            if key not in values:
                continue
            raw_value = json_safe(values.get(key, ""))
            current = json.dumps(raw_value, sort_keys=True)
            previous = self.db.get_background_monitor_state(f"config_drift:{key}", "")
            if not previous and self._is_unknown_value(raw_value):
                continue
            if previous and previous != current:
                change = {
                    "change_id": f"{now}:{key}",
                    "setting": label,
                    "key": key,
                    "previous_value": self._display_value(previous),
                    "current_value": self._display_value(current),
                    "previous_value_json": previous,
                    "current_value_json": current,
                    "first_seen": self.db.get_background_monitor_state(f"config_drift_first_seen:{key}", now),
                    "last_seen": now,
                    "source_detector": source_detector,
                    "confidence": "low" if self._is_unknown_value(raw_value) else "medium",
                    "severity": self._severity_for(key),
                    "why_it_matters": self._why_it_matters(key),
                    "recommended_verification": self._recommended_verification(key),
                }
                changes.append(change)
                self.db.set_background_monitor_state(f"config_drift_change:{now}:{key}", json.dumps(change, sort_keys=True))
            if not previous:
                self.db.set_background_monitor_state(f"config_drift_first_seen:{key}", now)
            self.db.set_background_monitor_state(f"config_drift:{key}", current)
        return {"generated_at": now, "changes": changes}

    def timeline(self, limit: int = 100) -> dict[str, Any]:
        rows = self.db.conn.execute(
            "SELECT key, value FROM background_monitor_state WHERE key LIKE 'config_drift_change:%' ORDER BY key DESC LIMIT ?",
            (limit,),
        ).fetchall()
        changes = []
        for row in rows:
            try:
                changes.append(json.loads(row["value"]))
            except json.JSONDecodeError:
                continue
        return {"generated_at": utc_now_iso(), "changes": changes}

    def _is_unknown_value(self, value: Any) -> bool:
        return value in ("", None, [], {})

    def _display_value(self, encoded_value: str) -> str:
        try:
            value = json.loads(encoded_value)
        except json.JSONDecodeError:
            value = encoded_value
        if self._is_unknown_value(value):
            return "unknown/unobserved"
        if isinstance(value, list):
            return ", ".join(str(item) for item in value) if value else "unknown/unobserved"
        if isinstance(value, dict):
            return json.dumps(value, sort_keys=True)
        if isinstance(value, bool):
            return "Enabled" if value else "Disabled"
        return str(value)

    def _severity_for(self, key: str) -> str:
        return "high" if key in {"remote_login", "screen_sharing", "admin_users", "launchdaemons", "profiles_mdm"} else "medium"

    def _why_it_matters(self, key: str) -> str:
        return f"{self.TRACKED[key]} changes can alter access, persistence, or exposure for this Mac."

    def _recommended_verification(self, key: str) -> str:
        return f"Review the current {self.TRACKED[key]} setting in System Settings or with the source detector evidence."


class IncidentModeManager:
    def __init__(self, db: AuditDatabase) -> None:
        self.db = db

    def enabled(self) -> bool:
        return self.db.get_background_monitor_state("incident_mode", "0") == "1"

    def set_enabled(self, enabled: bool) -> dict[str, Any]:
        self.db.set_background_monitor_state("incident_mode", "1" if enabled else "0")
        self.db.set_background_monitor_state("incident_mode_updated_at", utc_now_iso())
        return self.status()

    def status(self) -> dict[str, Any]:
        active = self.enabled()
        snapshots = self._records("incident_mode_evidence_snapshots_json")
        case_packages = self._records("incident_mode_case_packages_json")
        notes = self._records("incident_mode_notes_json")
        return {
            "active": active,
            "banner": "Incident Mode Active - Preserve evidence before cleanup or remediation." if active else "",
            "cleanup_blocked": active,
            "cleanup_actions_require_confirmation": active,
            "evidence_snapshot_encouraged": active,
            "report_export_suggested": active,
            "notes_panel_opened": bool(notes),
            "high_critical_alerts_persistent": active,
            "evidence_snapshot_count": len(snapshots),
            "last_evidence_snapshot": snapshots[-1] if snapshots else {},
            "case_package_count": len(case_packages),
            "last_case_package": case_packages[-1] if case_packages else {},
            "investigation_note_count": len(notes),
            "last_investigation_note": notes[-1] if notes else {},
            "recommended_actions": [
                "Create Evidence Snapshot",
                "Open Timeline",
                "Export Case Package",
                "Add Investigation Note",
                "Review High Priority Events",
            ]
            if active
            else [],
        }

    def record_evidence_snapshot(self, path: str | Path, *, reason: str = "manual") -> dict[str, Any]:
        record = {
            "created_at": utc_now_iso(),
            "path": str(path),
            "reason": reason,
            "action": "Create Evidence Snapshot",
        }
        return self._append_record("incident_mode_evidence_snapshots_json", record)

    def record_case_package_export(self, path: str | Path, *, format: str = "html") -> dict[str, Any]:
        record = {
            "created_at": utc_now_iso(),
            "path": str(path),
            "format": format,
            "action": "Export Case Package",
        }
        return self._append_record("incident_mode_case_packages_json", record)

    def record_note_panel_opened(self) -> dict[str, Any]:
        record = {
            "created_at": utc_now_iso(),
            "action": "Add Investigation Note",
            "note": "Investigation notes panel opened.",
        }
        return self._append_record("incident_mode_notes_json", record)

    def cleanup_allowed(self, *, confirmed: bool = False) -> tuple[bool, str]:
        if not self.enabled():
            return True, ""
        if confirmed:
            return True, "Incident Mode active; cleanup requires explicit confirmation and preserved evidence."
        return False, "Incident Mode active; cleanup is blocked until evidence is preserved and the action is explicitly confirmed."

    def _records(self, key: str) -> list[dict[str, Any]]:
        raw = self.db.get_background_monitor_state(key, "[]")
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return []
        return [item for item in parsed if isinstance(item, dict)] if isinstance(parsed, list) else []

    def _append_record(self, key: str, record: dict[str, Any]) -> dict[str, Any]:
        records = self._records(key)
        records.append(record)
        records = records[-20:]
        self.db.set_background_monitor_state(key, json.dumps(records, sort_keys=True))
        return record


def export_sarif(findings: list[Finding | dict[str, Any]], path: Path, *, redact_paths: bool = True) -> Path:
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for finding in findings:
        payload = finding.to_dict() if hasattr(finding, "to_dict") else dict(finding)
        rule_id = str(payload.get("rule_id") or payload.get("id") or "msaa.finding")
        severity = str(payload.get("severity", "warning"))
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": str(payload.get("rule_name") or payload.get("title") or rule_id),
                "shortDescription": {"text": str(payload.get("title") or rule_id)},
                "help": {"text": str(payload.get("recommended_next_steps") or payload.get("remediation_suggestion") or "Review this finding in MSAA.")},
            },
        )
        related_path = str(payload.get("related_path") or "")
        location = {}
        if related_path:
            uri = "[redacted-path]" if redact_paths else related_path
            location = {"physicalLocation": {"artifactLocation": {"uri": uri}}}
        description = _sarif_text(payload.get("description") or payload.get("evidence") or payload.get("title") or rule_id, redact_paths=redact_paths)
        evidence = _sarif_text(payload.get("evidence", ""), redact_paths=redact_paths)
        recommendation = _sarif_text(payload.get("recommended_next_steps") or payload.get("remediation_suggestion") or "", redact_paths=redact_paths)
        source_detector = _sarif_text(payload.get("trigger_source") or payload.get("source_detector") or payload.get("command_used") or "", redact_paths=redact_paths)
        results.append(
            {
                "ruleId": rule_id,
                "level": _sarif_level(severity),
                "message": {"text": description},
                "locations": [location] if location else [],
                "properties": {
                    "severity": severity,
                    "confidence": str(payload.get("confidence", "")),
                    "MITRE mapping": payload.get("mitre_mapping", payload.get("mitre", "")),
                    "evidence": evidence,
                    "recommendation": recommendation,
                    "source_detector": source_detector,
                },
            }
        )
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "macOS Security Audit Agent", "informationUri": "https://github.com/fuzzlove/macOS-Security-Audit-Agent", "rules": list(rules.values())}},
                "results": results,
            }
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(sarif, indent=2, sort_keys=True), encoding="utf-8")
    return path


def _sarif_text(value: object, *, redact_paths: bool) -> str:
    return redact_text(
        str(value or ""),
        redact_paths=redact_paths,
        redact_url_secrets=True,
        redact_usernames=redact_paths,
        redact_ips=redact_paths,
        redact_hostnames=redact_paths,
        redact_macs=redact_paths,
    )


def _sarif_level(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"


def mandatory_alert_policy_gaps(db: AuditDatabase) -> list[str]:
    manager = NotificationManager(db)
    settings = manager.settings()
    gaps: list[str] = []
    if not bool(settings.get("show_visible_alerts", True)):
        gaps.append("global:visible_alerts_disabled")
    category_setting_by_name = {
        "physical_session": "show_physical_session_alerts",
        "device": "show_usb_bluetooth_alerts",
        "network": "show_network_change_alerts",
        "persistence_admin": "show_admin_persistence_alerts",
        "advisory": "show_apple_forecast_alerts",
    }
    for event_type in sorted({canonical_event_type(item) for item in MANDATORY_VISIBLE_ALERT_EVENT_TYPES}):
        category = manager._alert_category_for_event(event_type)
        category_setting = category_setting_by_name.get(category)
        if category_setting and not bool(settings.get(category_setting, True)):
            gaps.append(f"{event_type}:category_disabled:{category}")
        preference = manager.preference_for(event_type)
        if preference.get("enabled") is False:
            gaps.append(f"{event_type}:disabled_by_preference")
        if preference.get("notify") is False:
            gaps.append(f"{event_type}:notify_false")
        if str(preference.get("notification_mode", "")).lower() == "none":
            gaps.append(f"{event_type}:notification_mode_none")
    return sorted(set(gaps))
