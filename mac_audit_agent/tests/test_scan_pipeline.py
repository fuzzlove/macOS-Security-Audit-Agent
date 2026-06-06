from pathlib import Path

from mac_audit_agent.models import CommandExecutionResult, Finding, ScanResult, ScanSummary
from mac_audit_agent.collectors import CollectorSuite
from mac_audit_agent.config import AuditConfig
from mac_audit_agent.reporting import export_scan_result_html, export_scan_result_json
from mac_audit_agent.runner import RunnerConfig, SafeCommandRunner
from mac_audit_agent.storage import AuditDatabase
from mac_audit_agent.debug_collectors import collect_debug_snapshot
from mac_audit_agent.ui.main_window import MainWindow, NetworkDiscoveryWorker, deduplicate_findings_for_display, finding_to_dict, normalize_findings, normalize_finding


def make_suite() -> CollectorSuite:
    return CollectorSuite(SafeCommandRunner(RunnerConfig(dry_run=True)), AuditConfig(dry_run=True))


def make_summary(scan_id: str = "scan-1") -> ScanSummary:
    return ScanSummary(
        scan_id=scan_id,
        started_at="2026-04-23T00:00:00Z",
        completed_at="2026-04-23T00:01:00Z",
        findings_count=1,
        security_score=80,
        notes="test",
        new_items_count=0,
    )


class FakeCollectorRunner:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def execute(self, command):
        self.calls.append(command.id)
        if command.id in {"runtime.network.lsof_tcp", "debug.ports.lsof_tcp"}:
            return CommandExecutionResult(
                command_id=command.id,
                command_preview=command.preview,
                executed_at="2026-04-23T00:00:00Z",
                stdout="COMMAND     PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\nControlCe  642 m      10u  IPv4 0x1  0t0  TCP 127.0.0.1:7000 (LISTEN)\n",
                stderr="",
                exit_code=0,
                timed_out=False,
                truncated=False,
                dry_run=False,
            )
        if command.id in {"runtime.processes.ps_axo", "debug.processes.ps_axo"}:
            return CommandExecutionResult(
                command_id=command.id,
                command_preview=command.preview,
                executed_at="2026-04-23T00:00:00Z",
                stdout="m 123 1 /usr/bin/python3 /usr/bin/python3 server.py\n",
                stderr="",
                exit_code=0,
                timed_out=False,
                truncated=False,
                dry_run=False,
            )
        return CommandExecutionResult(
            command_id=command.id,
            command_preview=command.preview,
            executed_at="2026-04-23T00:00:00Z",
            stdout="",
            stderr="",
            exit_code=0,
            timed_out=False,
            truncated=False,
            dry_run=False,
        )


class FakeTableItem:
    def __init__(self, text: str) -> None:
        self._text = text
        self.background = None
        self.foreground = None

    def text(self) -> str:
        return self._text

    def setBackground(self, value) -> None:
        self.background = value

    def setForeground(self, value) -> None:
        self.foreground = value


class FakeTable:
    def __init__(self) -> None:
        self.rows = []
        self.current_row = -1

    def setRowCount(self, _count: int) -> None:
        self.rows = []
        self.current_row = -1

    def rowCount(self) -> int:
        return len(self.rows)

    def insertRow(self, _row: int) -> None:
        self.rows.append([])

    def setItem(self, row: int, column: int, item) -> None:
        while len(self.rows[row]) <= column:
            self.rows[row].append(None)
        self.rows[row][column] = item

    def resizeRowsToContents(self) -> None:
        return None

    def selectRow(self, row: int) -> None:
        self.current_row = row

    def currentRow(self) -> int:
        return self.current_row


class FakeValue:
    def __init__(self) -> None:
        self.text = ""

    def setText(self, value: str) -> None:
        self.text = value


class FakeButton:
    def __init__(self) -> None:
        self.enabled = True

    def setEnabled(self, value: bool) -> None:
        self.enabled = value


class FakeStatusBar:
    def __init__(self) -> None:
        self.messages: list[tuple[str, int]] = []

    def showMessage(self, message: str, timeout: int = 0) -> None:
        self.messages.append((message, timeout))


class FakeComboBox:
    def __init__(self, value: str = "") -> None:
        self.items: list[str] = []
        self.value = value

    def clear(self) -> None:
        self.items = []
        self.value = ""

    def addItem(self, value: str) -> None:
        self.items.append(value)
        if not self.value:
            self.value = value

    def count(self) -> int:
        return len(self.items)

    def currentText(self) -> str:
        return self.value or (self.items[0] if self.items else "")


class FakeClipboard:
    def __init__(self) -> None:
        self.text = ""

    def setText(self, value: str) -> None:
        self.text = value


class FakeRemediationDb:
    def __init__(self) -> None:
        self.actions: list[dict] = []
        self.approvals: list[tuple[str, str, str]] = []
        self.command_logs = []

    def record_remediation_action(self, **kwargs) -> None:
        self.actions.append(kwargs)

    def record_user_approval(self, command_id: str, approved_at: str, approval_text: str) -> None:
        self.approvals.append((command_id, approved_at, approval_text))

    def record_command_log(self, scan_id: str, result) -> None:
        self.command_logs.append((scan_id, result))


def test_run_safe_scan_returns_non_empty_scan_result() -> None:
    suite = make_suite()
    result = suite.run_safe_scan()
    assert isinstance(result, ScanResult)
    assert result.scan_id
    assert result.timestamp
    assert result.hostname
    assert result.current_user
    assert result.findings
    assert "system_info" in result.collected_artifacts


def test_raw_logs_are_populated() -> None:
    suite = make_suite()
    result = suite.run_safe_scan()
    assert result.raw_logs
    assert all(entry.collector_name for entry in result.raw_logs)
    assert all(entry.timestamp for entry in result.raw_logs)


def test_baseline_diff_works() -> None:
    suite = make_suite()
    previous = suite.run_safe_scan()
    current = suite.run_safe_scan(previous)
    assert isinstance(current.baseline_diff, dict)
    assert "resolved_findings" in current.baseline_diff
    assert "drift_score" in current.baseline_diff
    assert "drift_label" in current.baseline_diff


def test_failed_collector_does_not_crash_scan(monkeypatch) -> None:
    suite = make_suite()

    def boom(_command_results):
        raise RuntimeError("collector exploded")

    monkeypatch.setattr(suite, "_collect_ports", boom)
    result = suite.run_safe_scan()
    assert result.scan_id
    assert result.errors
    assert any(error.collector_name == "ports" for error in result.errors)
    assert any(finding.title.startswith("Collector Failed") for finding in result.findings)
    assert "ports" in result.collected_artifacts
    assert result.collected_artifacts["ports"] == {"listening": [], "active_connections": [], "suspicious_review_needed": [], "errors": []}
    assert result.raw_logs


def test_collectors_always_return_artifacts_findings_and_errors(monkeypatch) -> None:
    suite = make_suite()

    def fail_users(_command_results):
        raise RuntimeError("users broke")

    monkeypatch.setattr(suite, "_collect_users", fail_users)
    result = suite.run_safe_scan()

    assert "users" in result.collected_artifacts
    assert isinstance(result.collected_artifacts["users"], list)
    assert isinstance(result.findings, list)
    assert isinstance(result.errors, list)
    assert any(error.collector_name == "users" for error in result.errors)
    assert any(log.collector_name == "users" for log in result.raw_logs)


def test_ports_artifact_keys_exist() -> None:
    suite = make_suite()
    result = suite.run_safe_scan()
    assert set(result.collected_artifacts["ports"].keys()) == {"listening", "active_connections", "suspicious_review_needed", "errors"}


def test_processes_artifact_keys_exist() -> None:
    suite = make_suite()
    result = suite.run_safe_scan()
    assert set(result.collected_artifacts["processes"].keys()) == {"all", "suspicious", "errors"}


def test_ports_and_processes_collectors_parse_sample_stdout() -> None:
    suite = CollectorSuite(FakeCollectorRunner(), AuditConfig())
    ports_result = suite._collect_ports([])
    processes_result = suite._collect_processes([])
    assert ports_result.artifacts["ports"]["listening"]
    assert processes_result.artifacts["processes"]["all"]
    assert ports_result.artifacts["ports"]["listening"][0].port == 7000
    assert processes_result.artifacts["processes"]["all"][0].pid == 123


def test_debug_collectors_snapshot_uses_sample_stdout() -> None:
    snapshot = collect_debug_snapshot(runner=FakeCollectorRunner(), config=AuditConfig())
    assert snapshot["ports"].parsed_count == 1
    assert snapshot["processes"].parsed_count == 1
    assert snapshot["artifacts"]["ports"]["listening"]
    assert snapshot["artifacts"]["processes"]["all"]


def test_scan_result_json_export_creates_valid_file(tmp_path) -> None:
    suite = make_suite()
    result = suite.run_safe_scan()
    path = export_scan_result_json(result, tmp_path / "report.json")
    assert path.exists()
    content = path.read_text(encoding="utf-8")
    assert result.scan_id in content
    assert '"raw_logs"' in content


def test_scan_result_html_export_creates_valid_file(tmp_path) -> None:
    suite = make_suite()
    result = suite.run_safe_scan()
    path = export_scan_result_html(result, tmp_path / "report.html")
    assert path.exists()
    content = path.read_text(encoding="utf-8")
    assert "Raw Logs" in content
    assert "Baseline Comparison" in content
    assert "History Indicators" in content


def make_finding(severity: str) -> Finding:
    return Finding(
        id=f"f-{severity}",
        category="Test",
        title=severity,
        severity=severity,  # type: ignore[arg-type]
        description="d",
        evidence="e",
        command_used="c",
        remediation_suggestion="r",
        warning="w",
    )


def test_security_score_no_findings_is_100() -> None:
    suite = make_suite()
    assert suite.compute_security_score([]) == 100


def test_security_score_medium_high_findings() -> None:
    suite = make_suite()
    score = suite.compute_security_score([make_finding("medium"), make_finding("high")])
    assert score == 78


def test_security_score_clamped_at_zero() -> None:
    suite = make_suite()
    score = suite.compute_security_score([make_finding("critical") for _ in range(10)])
    assert score == 0


def test_scan_failure_score_unavailable_not_zero() -> None:
    suite = make_suite()
    assert suite.compute_security_score(None) is None


def test_high_finding_defaults_include_remediation_steps() -> None:
    suite = make_suite()
    finding = suite._finding(
        category="Test",
        title="High Severity",
        severity="high",
        description="desc",
        evidence="evidence",
        evidence_summary="summary",
        raw_evidence_ref="ref",
        why_this_matters="matters",
        false_positive_notes="notes",
        recommended_next_steps="Disable the unexpected service after verifying ownership.",
        what_can_go_wrong="May break expected software.",
        command_used="/usr/sbin/lsof -nP -iTCP -sTCP:LISTEN",
    )
    assert finding.remediation_steps
    assert finding.remediation_steps[0] == "Disable the unexpected service after verifying ownership."


def test_localhost_scan_target_is_always_127001() -> None:
    suite = make_suite()
    assert suite._resolve_localhost_scan_target() == "127.0.0.1"


def test_localhost_scan_target_override_is_rejected() -> None:
    suite = make_suite()
    try:
        suite._collect_localhost_port_scan("safe", "tcp", "192.168.1.1")
    except ValueError as exc:
        assert "127.0.0.1" in str(exc)
    else:
        raise AssertionError("expected localhost target override rejection")


def test_safe_mode_scans_only_approved_common_ports() -> None:
    suite = make_suite()
    scanned_ports: list[int] = []

    def fake_tcp(target: str, port: int, timeout: float = 0.2) -> bool:
        assert target == "127.0.0.1"
        scanned_ports.append(port)
        return False

    suite._scan_localhost_port_tcp = fake_tcp  # type: ignore[method-assign]
    artifact = suite._collect_localhost_port_scan("safe", "tcp")
    assert artifact["scanned_port_count"] == 12
    assert scanned_ports == [22, 80, 443, 445, 5900, 8000, 8080, 8443, 9000, 9001, 9200, 27017]


def test_mismatch_between_localhost_scan_and_lsof_creates_high_finding() -> None:
    suite = make_suite()
    ports_artifact = {"listening": []}
    localhost_scan_artifact = {
        "target": "127.0.0.1",
        "mode": "safe",
        "protocol": "tcp",
        "open_ports": [8080],
        "missing_from_enumeration": [],
        "errors": [],
        "scanned_port_count": 1,
    }
    findings = suite._findings_for_localhost_scan(ports_artifact, localhost_scan_artifact)
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].category == "Localhost Port Scan"
    assert localhost_scan_artifact["missing_from_enumeration"] == [8080]


def test_no_network_hosts_besides_localhost_are_scanned() -> None:
    suite = make_suite()
    seen_targets: list[tuple[str, int, str]] = []

    def fake_tcp(target: str, port: int, timeout: float = 0.2) -> bool:
        seen_targets.append((target, port, "tcp"))
        return False

    def fake_udp(target: str, port: int, timeout: float = 0.2) -> bool:
        seen_targets.append((target, port, "udp"))
        return False

    suite._scan_localhost_port_tcp = fake_tcp  # type: ignore[method-assign]
    suite._scan_localhost_port_udp = fake_udp  # type: ignore[method-assign]
    suite._collect_localhost_port_scan("safe", "both")
    assert seen_targets
    assert {target for target, _port, _proto in seen_targets} == {"127.0.0.1"}


def test_localhost_scan_both_protocols_option_scans_tcp_and_udp() -> None:
    suite = make_suite()
    seen_protocols: list[str] = []

    def fake_tcp(target: str, port: int, timeout: float = 0.2) -> bool:
        assert target == "127.0.0.1"
        seen_protocols.append("tcp")
        return port == 8080

    def fake_udp(target: str, port: int, timeout: float = 0.2) -> bool:
        assert target == "127.0.0.1"
        seen_protocols.append("udp")
        return port == 9000

    suite._scan_localhost_port_tcp = fake_tcp  # type: ignore[method-assign]
    suite._scan_localhost_port_udp = fake_udp  # type: ignore[method-assign]
    artifact = suite._collect_localhost_port_scan("safe", "both")
    assert artifact["protocol"] == "both"
    assert artifact["open_ports"] == {"tcp": [8080], "udp": [9000]}
    assert "tcp" in seen_protocols
    assert "udp" in seen_protocols


def test_full_localhost_port_scan_target_is_always_127001() -> None:
    suite = make_suite()
    artifact = suite.collect_full_localhost_port_scan(tcp_ports=[], udp_ports=[])
    assert artifact["target"] == "127.0.0.1"


def test_full_localhost_port_scan_target_override_is_rejected() -> None:
    suite = make_suite()
    try:
        suite.collect_full_localhost_port_scan(target_override="localhost", tcp_ports=[], udp_ports=[])
    except ValueError as exc:
        assert "127.0.0.1" in str(exc)
    else:
        raise AssertionError("expected localhost target override rejection")


def test_full_localhost_port_scan_scans_only_localhost_and_counts_ports() -> None:
    suite = make_suite()
    seen_targets: list[tuple[str, int, str]] = []

    def fake_tcp(target: str, port: int, timeout: float = 0.05) -> bool:
        seen_targets.append((target, port, "tcp"))
        return port == 2

    def fake_udp(target: str, port: int, timeout: float = 0.05) -> bool:
        seen_targets.append((target, port, "udp"))
        return port == 4

    suite._scan_localhost_port_tcp = fake_tcp  # type: ignore[method-assign]
    suite._scan_localhost_port_udp = fake_udp  # type: ignore[method-assign]
    artifact = suite.collect_full_localhost_port_scan(tcp_ports=[1, 2, 3], udp_ports=[4, 5])
    assert artifact["tcp_open_ports"] == [2]
    assert artifact["udp_responsive_or_unknown_ports"] == [4]
    assert artifact["tcp_banners"] == {}
    assert artifact["scanned_tcp_count"] == 3
    assert artifact["scanned_udp_count"] == 2
    assert {target for target, _port, _proto in seen_targets} == {"127.0.0.1"}


def test_full_localhost_port_scan_captures_tcp_banners() -> None:
    suite = make_suite()

    def fake_tcp(target: str, port: int, timeout: float = 0.05) -> bool:
        return port == 80

    def fake_udp(target: str, port: int, timeout: float = 0.05) -> bool:
        return False

    def fake_banner(target: str, port: int, timeout: float = 0.1) -> str:
        assert target == "127.0.0.1"
        return "HTTP/1.1 200 OK" if port == 80 else ""

    suite._scan_localhost_port_tcp = fake_tcp  # type: ignore[method-assign]
    suite._scan_localhost_port_udp = fake_udp  # type: ignore[method-assign]
    suite._grab_localhost_tcp_banner = fake_banner  # type: ignore[method-assign]
    artifact = suite.collect_full_localhost_port_scan(tcp_ports=[80], udp_ports=[])
    assert artifact["tcp_open_ports"] == [80]
    assert artifact["tcp_banners"] == {80: "HTTP/1.1 200 OK"}


def test_full_localhost_port_scan_does_not_depend_on_process_enumeration(monkeypatch) -> None:
    suite = make_suite()

    def fail_ports(_command_results):
        raise AssertionError("full localhost scan must not call process/listening enumeration")

    monkeypatch.setattr(suite, "_collect_ports", fail_ports)
    suite._scan_localhost_port_tcp = lambda target, port, timeout=0.05: False  # type: ignore[method-assign]
    suite._scan_localhost_port_udp = lambda target, port, timeout=0.05: False  # type: ignore[method-assign]
    artifact = suite.collect_full_localhost_port_scan(tcp_ports=[1], udp_ports=[1])
    assert artifact["scanned_tcp_count"] == 1
    assert artifact["scanned_udp_count"] == 1


def test_reset_clears_current_scan_but_not_db(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    summary = make_summary("db-scan")
    db.record_scan(summary)

    window = MainWindow.__new__(MainWindow)
    window.db = db
    window.current_scan_result = object()
    window.current_scan_summary = summary
    window.current_payload = {"findings": [{"severity": "high"}]}
    window.current_scan_active = True
    window.last_ui_debug = {"x": 1}
    window.findings_table = FakeTable()
    window.ports_table = FakeTable()
    window.localhost_scan_table = FakeTable()
    window.localhost_full_scan_table = FakeTable()
    window.catalog_status_table = FakeTable()
    window.cve_findings_table = FakeTable()
    window.best_practice_findings_table = FakeTable()
    window.review_needed_findings_table = FakeTable()
    window.processes_table = FakeTable()
    window.users_table = FakeTable()
    window.history_table = FakeTable()
    window.files_table = FakeTable()
    window.comparison_table = FakeTable()
    window.logs_table = FakeTable()
    window.dashboard_cards = {"a": FakeValue()}
    window.severity_cards = {severity: FakeValue() for severity in ["info", "low", "medium", "high", "critical"]}
    window.export_json_button = FakeButton()
    window.export_html_button = FakeButton()
    status_bar = FakeStatusBar()
    window.statusBar = lambda: status_bar
    window.score_label = FakeValue()
    window.summary_label = FakeValue()
    window._populate_findings = lambda findings: window.findings_table.setRowCount(0)
    window._refresh_dashboard = MainWindow._refresh_dashboard.__get__(window, MainWindow)

    window.reset_scan_state()

    assert window.current_scan_result is None
    assert window.current_scan_summary is None
    assert window.current_payload is None
    assert window.current_scan_active is False
    assert window.ports_table.rows == []
    assert window.localhost_scan_table.rows == []
    assert window.export_json_button.enabled is False
    assert window.export_html_button.enabled is False
    assert db.latest_scan()["scan_id"] == "db-scan"


def test_network_discovery_table_uses_likely_hostname_and_column_order(monkeypatch) -> None:
    window = MainWindow.__new__(MainWindow)
    window.network_discovery_summary_table = FakeTable()
    window.network_discovery_hosts_table = FakeTable()
    window.network_discovery_device_details_table = FakeTable()
    window.network_discovery_debug_table = FakeTable()
    window.network_discovery_changes_table = FakeTable()
    window.network_discovery_suspicious_table = FakeTable()
    window.findings_table = FakeTable()
    window.ports_table = FakeTable()
    window.localhost_scan_table = FakeTable()
    window.localhost_full_scan_table = FakeTable()
    window.packet_capture_table = FakeTable()
    window.catalog_status_table = FakeTable()
    window.cve_findings_table = FakeTable()
    window.best_practice_findings_table = FakeTable()
    window.review_needed_findings_table = FakeTable()
    window.processes_table = FakeTable()
    window.users_table = FakeTable()
    window.history_table = FakeTable()
    window.files_table = FakeTable()
    window.comparison_table = FakeTable()
    window.logs_table = FakeTable()
    window._populate_findings = lambda findings: None
    window.refresh_investigation_notes_page = lambda: None
    window._apply_severity_style = lambda items, severity: None
    window.statusBar = lambda: type("StatusBar", (), {"showMessage": lambda self, message, timeout=0: None})()
    monkeypatch.setattr("mac_audit_agent.ui.main_window.QTableWidgetItem", FakeTableItem)

    payload = {
        "findings": [],
        "ports": {"listening": [], "active_connections": [], "suspicious_review_needed": [], "errors": []},
        "localhost_scan": {"target": "127.0.0.1", "mode": "safe", "protocol": "tcp", "open_ports": [], "missing_from_enumeration": [], "errors": [], "scanned_port_count": 0},
        "localhost_full_port_scan": {"target": "127.0.0.1", "tcp_open_ports": [], "tcp_banners": {}, "udp_responsive_or_unknown_ports": [], "scanned_tcp_count": 0, "scanned_udp_count": 0, "errors": []},
        "packet_captures": [],
        "network_discovery": {
            "interface": "en0",
            "subnet": "192.168.1.0/24",
            "gateway_ip": "192.168.1.1",
            "gateway_mac": "aa:bb:cc:dd:ee:ff",
            "scope": "private",
            "host_count": 1,
            "review_needed_count": 0,
            "methods_used": ["arp -a"],
            "devices": [
                {
                    "ip_address": "192.168.1.20",
                    "likely_hostname": "Johns-MacBook-Pro.local",
                    "hostname": "",
                    "mac_address": "11:22:33:44:55:66",
                    "vendor": "Apple",
                    "device_type": "MacBook Pro",
                    "confidence": "high",
                    "discovery_methods": ["arp", "mdns"],
                    "review_flags": [],
                    "baseline_status": "matched baseline",
                }
            ],
            "comparison": {},
            "debug_logs": ["arp rows parsed: 1", "mdns names found: 1", "reverse dns count: 1", "merged device count: 1"],
            "errors": [],
        },
        "processes": {"all": [], "suspicious": [], "errors": []},
        "users": [],
        "history_indicators": [],
        "permission_snapshots": [],
        "file_issues": [],
        "raw_logs": [],
        "baseline_diff": {},
        "dashboard": {},
    }

    window.current_payload = payload
    window.current_scan_result = type("ScanHolder", (), {"artifacts": {"network_discovery": payload["network_discovery"]}, "raw_logs": []})()
    window._populate_scan_results(payload)

    assert window.network_discovery_hosts_table.rows[0][1].text() == "Johns-MacBook-Pro.local"
    assert window.network_discovery_hosts_table.rows[0][5].text() == "high"
    assert window.network_discovery_hosts_table.rows[0][6].text() == "arp, mdns"
    assert window.network_discovery_device_details_table.rows[0][0].text() == "Likely Hostname"
    assert window.network_discovery_device_details_table.rows[0][1].text() == "Johns-MacBook-Pro.local"


def test_network_discovery_worker_emits_signals() -> None:
    class FakeCollector:
        def collect_network_discovery(self, **kwargs):
            kwargs["progress_callback"]({"stage": "merge", "completed": 1, "total": 1, "message": "merged"})
            return ("scan-result", ["finding"], {"scan_id": "scan-1"})

    worker = NetworkDiscoveryWorker(FakeCollector(), {"interface": "en0", "scan_profile": "quick", "confirm_public": True}, {"hosts": []})
    progress_events = []
    completed_events = []
    failed_events = []
    worker.discovery_progress.connect(progress_events.append)
    worker.discovery_completed.connect(completed_events.append)
    worker.discovery_failed.connect(failed_events.append)

    worker.run()

    assert progress_events[0]["message"] == "merged"
    assert completed_events[0][0] == "scan-result"
    assert not failed_events


def test_copy_remediation_command_copies_to_clipboard_and_logs(monkeypatch) -> None:
    window = MainWindow.__new__(MainWindow)
    clipboard = FakeClipboard()
    monkeypatch.setattr("mac_audit_agent.ui.main_window.QApplication.clipboard", lambda: clipboard)
    window.db = FakeRemediationDb()
    window.current_scan_result = type("ScanHolder", (), {"scan_id": "scan-1"})()
    window.current_selected_finding = {
        "id": "finding-1",
        "title": "Test finding",
        "recommended_next_steps": "Review the service.",
        "remediation_commands": ["launchctl print system/service"],
    }
    window.remediation_command_selector = FakeComboBox("launchctl print system/service")
    window.remediation_command_selector.addItem("launchctl print system/service")
    status_bar = FakeStatusBar()
    window.statusBar = lambda: status_bar

    window.copy_remediation_command()

    assert clipboard.text == "launchctl print system/service"
    assert window.db.actions[-1]["action_type"] == "copy"
    assert window.db.actions[-1]["result_text"] == "copied to clipboard"


def test_dangerous_remediation_requires_confirmation(monkeypatch) -> None:
    window = MainWindow.__new__(MainWindow)
    window.db = FakeRemediationDb()
    window.current_scan_result = type("ScanHolder", (), {"scan_id": "scan-1", "raw_logs": []})()
    window.current_selected_finding = {
        "id": "finding-1",
        "title": "Remove file",
        "recommended_next_steps": "Delete the file only if ownership is confirmed.",
        "what_can_go_wrong": "Could break software.",
        "remediation_risk": "dangerous",
        "requires_admin": False,
    }
    window.remediation_command_selector = FakeComboBox("rm /tmp/test")
    window.remediation_command_selector.addItem("rm /tmp/test")
    executed = {"called": False}
    window.runner = type("Runner", (), {"execute": lambda *args, **kwargs: executed.__setitem__("called", True)})()
    monkeypatch.setattr(window, "_confirm_remediation_command", lambda finding, command: (False, ""))

    window.run_remediation_command()

    assert executed["called"] is False
    assert window.db.actions[-1]["action_type"] == "run_cancelled"


def test_populate_findings_accepts_list_of_finding(monkeypatch) -> None:
    window = MainWindow.__new__(MainWindow)
    window.findings_table = FakeTable()
    window._apply_severity_style = lambda items, severity: None
    monkeypatch.setattr("mac_audit_agent.ui.main_window.QTableWidgetItem", FakeTableItem)
    window._populate_findings([make_finding("high")])
    assert len(window.findings_table.rows) == 1
    assert window.findings_table.rows[0][0].text() == "high"


def test_populate_findings_accepts_list_of_dict(monkeypatch) -> None:
    window = MainWindow.__new__(MainWindow)
    window.findings_table = FakeTable()
    window._apply_severity_style = lambda items, severity: None
    monkeypatch.setattr("mac_audit_agent.ui.main_window.QTableWidgetItem", FakeTableItem)
    window._populate_findings([make_finding("low").to_dict()])
    assert len(window.findings_table.rows) == 1
    assert window.findings_table.rows[0][0].text() == "low"


def test_populate_findings_accepts_mixed_finding_dict_list(monkeypatch) -> None:
    window = MainWindow.__new__(MainWindow)
    window.findings_table = FakeTable()
    window._apply_severity_style = lambda items, severity: None
    monkeypatch.setattr("mac_audit_agent.ui.main_window.QTableWidgetItem", FakeTableItem)
    window._populate_findings([make_finding("critical"), make_finding("medium").to_dict()])
    assert len(window.findings_table.rows) == 2
    assert window.findings_table.rows[0][0].text() == "critical"
    assert window.findings_table.rows[1][0].text() == "medium"


def test_scan_duplicate_findings_are_grouped_with_occurrence_count(monkeypatch) -> None:
    window = MainWindow.__new__(MainWindow)
    window.findings_table = FakeTable()
    window._apply_severity_style = lambda items, severity: None
    window._clear_selected_finding_panel = lambda: None
    monkeypatch.setattr("mac_audit_agent.ui.main_window.QTableWidgetItem", FakeTableItem)
    first = make_finding("high").to_dict()
    second = {**first, "id": "duplicate-finding-2"}

    window._populate_findings([first, second])

    assert len(window.findings_table.rows) == 1
    assert window.current_visible_findings[0]["occurrence_count"] == 2
    assert window.current_visible_findings[0]["duplicate_count"] == 1
    assert window.current_visible_findings[0]["duplicate_category"] == "duplicate_burst"
    assert "Repeated 2 times (duplicate burst)" in window.findings_table.rows[0][3].text()


def test_high_volume_scan_duplicate_findings_are_categorized() -> None:
    base = make_finding("medium").to_dict()
    findings = [{**base, "id": f"finding-{index}"} for index in range(12)]

    grouped = deduplicate_findings_for_display(findings)

    assert len(grouped) == 1
    assert grouped[0]["occurrence_count"] == 12
    assert grouped[0]["duplicate_count"] == 11
    assert grouped[0]["duplicate_category"] == "high_volume_duplicate"


def test_populate_findings_missing_severity_defaults_to_info(monkeypatch) -> None:
    window = MainWindow.__new__(MainWindow)
    window.findings_table = FakeTable()
    window._apply_severity_style = lambda items, severity: None
    monkeypatch.setattr("mac_audit_agent.ui.main_window.QTableWidgetItem", FakeTableItem)
    window._populate_findings([{"category": "Test", "title": "Title", "description": "desc", "evidence": "evidence"}])
    assert window.findings_table.rows[0][0].text() == "info"


def test_findings_sort_defaults_to_critical_first(monkeypatch) -> None:
    window = MainWindow.__new__(MainWindow)
    window.findings_table = FakeTable()
    window._apply_severity_style = lambda items, severity: None
    window._clear_selected_finding_panel = lambda: None
    window.findings_sort_order = "critical_to_low"
    monkeypatch.setattr("mac_audit_agent.ui.main_window.QTableWidgetItem", FakeTableItem)
    window._populate_findings([make_finding("low"), make_finding("critical"), make_finding("medium")])
    assert [row[0].text() for row in window.findings_table.rows] == ["critical", "medium", "low"]


def test_findings_sort_can_switch_to_low_first(monkeypatch) -> None:
    window = MainWindow.__new__(MainWindow)
    window.findings_table = FakeTable()
    window._apply_severity_style = lambda items, severity: None
    window._clear_selected_finding_panel = lambda: None
    window.findings_sort_order = "low_to_critical"
    monkeypatch.setattr("mac_audit_agent.ui.main_window.QTableWidgetItem", FakeTableItem)
    window._populate_findings([make_finding("high"), make_finding("low"), make_finding("critical")])
    assert [row[0].text() for row in window.findings_table.rows] == ["low", "high", "critical"]


def test_finding_to_dict_handles_model_and_dict() -> None:
    finding = make_finding("info")
    assert finding_to_dict(finding)["title"] == finding.title
    assert finding_to_dict({"title": "dict-title"})["title"] == "dict-title"


def test_normalize_finding_handles_mixed_inputs() -> None:
    finding = make_finding("low")
    assert normalize_finding(finding)["severity"] == "low"
    assert normalize_finding({"severity": "high"})["severity"] == "high"
    assert normalize_findings([finding, {"severity": "critical"}])[1]["severity"] == "critical"


def test_normalize_findings_empty_list() -> None:
    assert normalize_findings([]) == []


def test_render_finding_details_shows_privilege_and_impact_context() -> None:
    window = MainWindow.__new__(MainWindow)
    text = MainWindow._render_finding_details(
        window,
        {
            "title": "Sudoers Rule Review: admin",
            "severity": "high",
            "category": "Accounts & Privileges",
            "evidence_summary": "admin has broad sudo",
            "why_this_matters": "Broad sudo access increases impact.",
            "false_positive_notes": "Could be legitimate.",
            "privilege_escalation_context": "Privilege escalation means a user or process gains more access than intended.",
            "business_impact": "Could expose business data.",
            "local_network_impact": "Could affect shared credentials.",
            "references": ["CIS Apple macOS Benchmark"],
        },
    )
    assert "Privilege Escalation:" in text
    assert "Business Impact:" in text
    assert "Local Network Impact:" in text
    assert "CIS Apple macOS Benchmark" in text


def test_render_remediation_details_shows_impact_sections() -> None:
    window = MainWindow.__new__(MainWindow)
    text = MainWindow._render_remediation_details(
        window,
        {
            "remediation_steps": ["Review the rule."],
            "verification_steps": ["Re-run the scan."],
            "remediation_risk": "sensitive",
            "estimated_impact": "high",
            "requires_admin": True,
            "reversible": False,
            "what_can_go_wrong": "May break admin workflows.",
            "business_impact": "Could expose business data.",
            "local_network_impact": "Could affect nearby services.",
            "remediation_references": ["Apple Platform Security"],
        },
    )
    assert "Business Impact:" in text
    assert "Local Network Impact:" in text
    assert "Apple Platform Security" in text
