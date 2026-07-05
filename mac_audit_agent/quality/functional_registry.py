from __future__ import annotations

from mac_audit_agent.quality.audit_models import FunctionalCheck


FEATURES: list[tuple[str, str, str, str, str]] = [
    ("core.app_startup", "Core", "app startup", "Application modules import and main UI can be constructed.", "critical"),
    ("core.database_rw", "Core", "database open/read/write", "SQLite database opens and background state can be written and read.", "blocker"),
    ("core.settings_load_save", "Core", "settings load/save", "MonitorSettings defaults, save, reload, and versioning work.", "blocker"),
    ("core.assessment_builder", "Core", "assessment builder", "Security assessment builds from real local data structures.", "high"),
    ("core.report_storage", "Core", "report storage", "Report directory is writable.", "high"),
    ("scan.safe_scan", "Scans", "Safe Scan", "Safe scan can run without destructive actions.", "critical"),
    ("scan.localhost_ports", "Scans", "localhost port scan", "Port parser returns structured listening/connection data or explicit unavailable reason.", "high"),
    ("scan.network", "Scans", "network scan", "Network collection returns structured data or exact failure.", "high"),
    ("scan.admin_persistence", "Scans", "admin/persistence scan", "LaunchAgents, LaunchDaemons, admin users, and sudoers are handled safely.", "high"),
    ("persistence.registry", "Persistence Intelligence", "scanner registry loads", "Persistence scanner registry is explicit and loadable.", "blocker"),
    ("persistence.launchd_scanner", "Persistence Intelligence", "launchd scanner works", "LaunchAgents and LaunchDaemons are parsed safely.", "critical"),
    ("persistence.workflow", "Persistence Intelligence", "scan/baseline/timeline/chain/report workflow", "Persistence workflow produces scan report, baseline comparison, timeline, chain view, and JSON report.", "blocker"),
    ("persistence.safety", "Persistence Intelligence", "safe read-only defaults", "No destructive persistence remediation actions are exposed.", "blocker"),
    ("network_intelligence.collectors", "Network Intelligence", "collector normalization", "Network Sentinel collector logic normalizes into MSAA models.", "high"),
    ("network_intelligence.storage_events", "Network Intelligence", "storage and event routing", "Network Intelligence snapshots write to MSAA DB and findings become monitor events.", "high"),
    ("network_intelligence.reports", "Network Intelligence", "report payload", "Network Intelligence data appears in MSAA report payloads.", "medium"),
    ("network_intelligence.no_standalone_runtime", "Network Intelligence", "no standalone Sentinel runtime", "MSAA does not run the old Sentinel app, CLI, or database.", "blocker"),
    ("scan.physical_devices", "Scans", "physical devices scan", "USB/Bluetooth inventory is parsed or permissions failure is explicit.", "high"),
    ("scan.apple_exposure", "Scans", "Apple Exposure Assessment", "Freshness metadata exists and stale cache is not misrepresented.", "high"),
    ("scan.visibility_integrity", "Scans", "visibility integrity scan", "Visibility integrity check returns component statuses.", "medium"),
    ("scan.baseline_drift", "Scans", "baseline drift scan", "Baseline drift engine can compare scan state.", "medium"),
    ("daemon.user_launch_agent", "Monitor/Daemon", "user LaunchAgent status", "User monitor LaunchAgent status is inspectable.", "high"),
    ("daemon.system_launch_daemon", "Monitor/Daemon", "system LaunchDaemon status", "System LaunchDaemon status is inspectable when enabled.", "critical"),
    ("daemon.protected_monitor", "Monitor/Daemon", "protected monitor status", "Protected monitor integrity is inspectable when enabled.", "critical"),
    ("daemon.heartbeat", "Monitor/Daemon", "daemon heartbeat", "Daemon heartbeat freshness is visible.", "critical"),
    ("daemon.notifier_heartbeat", "Monitor/Daemon", "notifier heartbeat", "User notifier heartbeat and status are visible.", "blocker"),
    ("daemon.settings_version_match", "Monitor/Daemon", "settings version match", "UI/runtime settings versions are not stale.", "critical"),
    ("daemon.event_db_writes", "Monitor/Daemon", "event database writes", "Monitor event database write path works.", "blocker"),
    ("alert.overlay_manager", "Alerts", "AlertOverlayManager", "Overlay manager can be initialized and reports delivery state.", "blocker"),
    ("alert.bottom_right_rendering", "Alerts", "bottom-right alert rendering", "Bottom-right alert path has render/suppression trace.", "blocker"),
    ("alert.severity_threshold", "Alerts", "severity threshold logic", "Minimum severity policy suppresses lower severity with reason.", "high"),
    ("alert.usb_path", "Alerts", "USB alert path", "USB diagnostic event policy and trace are recorded.", "high"),
    ("alert.bluetooth_path", "Alerts", "Bluetooth alert path", "Bluetooth diagnostic event policy and trace are recorded.", "high"),
    ("alert.network_path", "Alerts", "network alert path", "Network diagnostic event policy and trace are recorded.", "high"),
    ("alert.admin_path", "Alerts", "admin/persistence alert path", "Admin/persistence diagnostic event policy and trace are recorded.", "high"),
    ("alert.suppression_reasons", "Alerts", "alert suppression reasons", "Suppressed alerts include exact reason.", "critical"),
    ("alert.delivery_trace", "Alerts", "AlertDeliveryTrace", "Alert-worthy events create delivery trace.", "blocker"),
    ("settings.enforcement", "Settings", "settings enforcement", "Critical settings persist, reload, and appear in diagnostics.", "blocker"),
    ("exports.html", "Exports", "HTML export", "HTML export creates non-empty report with limitations.", "critical"),
    ("exports.json", "Exports", "JSON export", "JSON export creates valid JSON metadata.", "critical"),
    ("exports.word", "Exports", "Word .docx export", "Word export creates readable .docx when dependency is present.", "high"),
    ("exports.excel", "Exports", "Excel .xlsx export", "Excel export creates workbook with expected sheets.", "high"),
    ("exports.assessment", "Exports", "assessment export", "Assessment HTML/JSON/Markdown exports create files.", "high"),
    ("exports.evidence_package", "Exports", "evidence package export", "Evidence package includes manifest and avoids secrets.", "medium"),
    ("framework.mapping", "Framework Mapping", "framework mapping integrity", "Framework IDs are valid and wording avoids unsupported claims.", "blocker"),
    ("freshness.timestamps", "Freshness", "data freshness", "Freshness timestamps are timezone-aware or explicitly unavailable.", "critical"),
    ("ui.controls", "Reports/UI", "UI control audit", "Visible controls are enabled/connected or explained.", "blocker"),
]


def build_registry() -> list[FunctionalCheck]:
    checks: list[FunctionalCheck] = []
    for check_id, area, name, description, severity in FEATURES:
        test_type = check_id.split(".", 1)[0]
        if test_type == "scan":
            test_type = "smoke"
        checks.append(
            FunctionalCheck(
                check_id=check_id,
                feature_area=area,
                name=name,
                description=description,
                severity_if_failed=severity,
                test_type=test_type,
                expected_result="Behavior verified by automated pre-UAT audit.",
            )
        )
    return checks
