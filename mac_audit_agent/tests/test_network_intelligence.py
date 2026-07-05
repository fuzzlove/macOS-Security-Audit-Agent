import subprocess
from pathlib import Path

from mac_audit_agent.network_intelligence.baseline import compare_network_baseline
from mac_audit_agent.network_intelligence.collector import NetworkIntelligenceCollector
from mac_audit_agent.network_intelligence.connection_parser import parse_lsof_connections, parse_lsof_listeners
from mac_audit_agent.network_intelligence.diagnostics import build_network_intelligence_diagnostics
from mac_audit_agent.network_intelligence.dns_gateway import parse_route_default, parse_scutil_dns
from mac_audit_agent.network_intelligence.models import (
    ListeningPort,
    NetworkConnection,
    NetworkIntelligenceSnapshot,
    NetworkPosture,
)
from mac_audit_agent.network_intelligence.risk_scoring import score_connections, score_listeners, score_posture
from mac_audit_agent.network_intelligence.sentinel_adapter import sentinel_scan_to_snapshot
from mac_audit_agent.network_intelligence.timeline import snapshot_to_events
from mac_audit_agent.network_intelligence.vpn_proxy import parse_ifconfig_vpn, parse_proxy_state
from mac_audit_agent.storage import AuditDatabase


LSOF_CONNECTIONS = """COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
Safari    101 alice  42u  IPv4 0xabc      0t0  TCP 192.168.1.5:53111->93.184.216.34:443 (ESTABLISHED)
nc        202 alice   3u  IPv4 0xdef      0t0  TCP 192.168.1.5:4444->8.8.8.8:9001 (ESTABLISHED)
"""

LSOF_LISTENERS = """COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
sshd      303 root    5u  IPv4 0xaaa      0t0  TCP *:22 (LISTEN)
node      404 alice  11u  IPv4 0xbbb      0t0  TCP 127.0.0.1:3000 (LISTEN)
"""


def test_lsof_connections_are_normalized_to_msaa_models() -> None:
    connections = parse_lsof_connections(LSOF_CONNECTIONS, timestamp="2026-07-02T00:00:00Z")
    assert len(connections) == 2
    assert connections[0].process_name == "Safari"
    assert connections[0].remote_address == "93.184.216.34"
    assert connections[0].remote_port == "443"
    assert connections[0].source_collector == "lsof"


def test_lsof_listeners_are_normalized_to_msaa_models() -> None:
    listeners = parse_lsof_listeners(LSOF_LISTENERS, timestamp="2026-07-02T00:00:00Z")
    assert len(listeners) == 2
    assert listeners[0].local_address == "*"
    assert listeners[0].port == "22"
    assert listeners[0].service_guess == "SSH / Remote Login"


def test_posture_parsers_extract_dns_gateway_vpn_and_proxy() -> None:
    route = parse_route_default("gateway: 192.168.1.1\ninterface: en0\n")
    dns = parse_scutil_dns("nameserver[0] : 1.1.1.1\nnameserver[1] : 9.9.9.9\n")
    vpn_active, vpn_name = parse_ifconfig_vpn("utun3: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST>\n")
    proxy_enabled, proxy_details = parse_proxy_state("Enabled: Yes\nServer: proxy.local\n")
    assert route["gateway"] == "192.168.1.1"
    assert dns == ["1.1.1.1", "9.9.9.9"]
    assert vpn_active is True
    assert vpn_name == "utun3"
    assert proxy_enabled is True
    assert "Enabled: Yes" in proxy_details


def test_risk_engine_flags_suspicious_external_connection_and_exposed_listener() -> None:
    connections = [
        NetworkConnection(
            process_name="nc",
            remote_address="8.8.8.8",
            remote_port="9001",
            evidence="nc reverse shell indicator",
        )
    ]
    listeners = [ListeningPort(process_name="sshd", local_address="*", port="22", baseline_status="new", evidence="*:22")]
    findings = [*score_connections(connections), *score_listeners(listeners)]
    assert connections[0].risk_level == "critical"
    assert listeners[0].risk_level == "high"
    assert {finding.severity for finding in findings} == {"critical", "high"}


def test_posture_baseline_drift_creates_findings() -> None:
    baseline = NetworkPosture(gateway="192.168.1.1", dns_servers=["1.1.1.1"], vpn_active=True)
    current = NetworkPosture(gateway="192.168.1.254", dns_servers=["9.9.9.9"], vpn_active=False)
    findings = score_posture(current, baseline)
    assert [finding.title for finding in findings] == [
        "Gateway changed since baseline",
        "DNS servers changed since baseline",
        "VPN state changed since baseline",
    ]


def test_collector_respects_network_activity_disabled_setting() -> None:
    def runner(command):
        raise AssertionError(f"collector should not run command when disabled: {command}")

    snapshot = NetworkIntelligenceCollector(runner=runner).collect(settings={"network_activity_monitoring_enabled": False})
    assert snapshot.connections == []
    assert snapshot.listeners == []
    assert snapshot.diagnostics["disabled_by_settings"] is True
    assert "Network Activity monitoring is disabled" in snapshot.diagnostics["errors"][0]


def test_collector_uses_read_only_commands_and_normalizes_snapshot() -> None:
    commands = []

    def runner(command):
        commands.append(command)
        if command == ["/usr/sbin/lsof", "-nP", "-iTCP", "-sTCP:LISTEN"]:
            return subprocess.CompletedProcess(command, 0, LSOF_LISTENERS, "")
        if command[:3] == ["/usr/sbin/lsof", "-nP", "-iTCP"]:
            return subprocess.CompletedProcess(command, 0, LSOF_CONNECTIONS, "")
        if command == ["/sbin/route", "-n", "get", "default"]:
            return subprocess.CompletedProcess(command, 0, "gateway: 192.168.1.1\ninterface: en0\n", "")
        if command == ["/usr/sbin/scutil", "--dns"]:
            return subprocess.CompletedProcess(command, 0, "nameserver[0] : 1.1.1.1\n", "")
        if command == ["/sbin/ifconfig"]:
            return subprocess.CompletedProcess(command, 0, "", "")
        if command == ["/usr/sbin/networksetup", "-getwebproxy", "Wi-Fi"]:
            return subprocess.CompletedProcess(command, 0, "Enabled: No\n", "")
        return subprocess.CompletedProcess(command, 1, "", "unexpected")

    snapshot = NetworkIntelligenceCollector(runner=runner).collect(settings={"network_activity_monitoring_enabled": True})
    assert len(snapshot.connections) == 2
    assert len(snapshot.listeners) == 2
    assert snapshot.posture.gateway == "192.168.1.1"
    assert all(command[0] in {"/usr/sbin/lsof", "/sbin/route", "/usr/sbin/scutil", "/sbin/ifconfig", "/usr/sbin/networksetup"} for command in commands)


def test_baseline_compare_marks_new_connection_and_listener() -> None:
    previous = NetworkIntelligenceSnapshot(
        connections=[NetworkConnection(process_name="Safari", remote_address="93.184.216.34", remote_port="443")],
        listeners=[ListeningPort(process_name="node", local_address="127.0.0.1", port="3000")],
    )
    current = NetworkIntelligenceSnapshot(
        connections=[
            NetworkConnection(process_name="Safari", remote_address="93.184.216.34", remote_port="443"),
            NetworkConnection(process_name="curl", remote_address="198.51.100.7", remote_port="443"),
        ],
        listeners=[
            ListeningPort(process_name="node", local_address="127.0.0.1", port="3000"),
            ListeningPort(process_name="sshd", local_address="*", port="22"),
        ],
    )
    comparison = compare_network_baseline(current, previous)
    assert comparison["new_connections"] == 1
    assert comparison["new_listeners"] == 1
    assert current.connections[1].baseline_status == "new"
    assert current.listeners[1].baseline_status == "new"


def test_network_findings_route_to_msaa_monitor_events() -> None:
    snapshot = NetworkIntelligenceSnapshot(
        findings=score_listeners([ListeningPort(process_name="sshd", local_address="*", port="22", baseline_status="new", evidence="*:22")])
    )
    events = snapshot_to_events(snapshot)
    assert len(events) == 1
    assert events[0].event_type == "new_listening_port"
    assert events[0].severity == "high"


def test_network_diagnostics_builder_accepts_snapshot_only_and_extra() -> None:
    snapshot = NetworkIntelligenceSnapshot(
        connections=[NetworkConnection(process_name="Safari")],
        listeners=[ListeningPort(process_name="node")],
    )

    base = build_network_intelligence_diagnostics(snapshot)
    with_extra = build_network_intelligence_diagnostics(
        snapshot,
        extra={"db_write_success": "pending", "normalized_event_count": 3},
    )

    assert base["collector_counts"]["connections"] == 1
    assert with_extra["db_write_success"] == "pending"
    assert with_extra["normalized_event_count"] == 3


def test_network_diagnostics_builder_ignores_unknown_kwargs_safely() -> None:
    diagnostics = build_network_intelligence_diagnostics(
        NetworkIntelligenceSnapshot(),
        unsupported_future_kwarg=True,
    )

    assert diagnostics["module_loaded"] is True
    assert diagnostics["ui_tab_loading_success"] is True


def test_storage_writes_and_reads_latest_network_snapshot(tmp_path) -> None:
    db = AuditDatabase(tmp_path / "msaa.sqlite")
    snapshot = NetworkIntelligenceSnapshot(
        posture=NetworkPosture(gateway="192.168.1.1", dns_servers=["1.1.1.1"]),
        connections=[NetworkConnection(process_name="Safari", remote_address="93.184.216.34", remote_port="443")],
        listeners=[ListeningPort(process_name="node", local_address="127.0.0.1", port="3000")],
        findings=score_listeners([ListeningPort(process_name="sshd", local_address="*", port="22", baseline_status="new", evidence="*:22")]),
    )
    db.record_network_intelligence_snapshot(snapshot)
    latest = db.latest_network_intelligence_snapshot()
    assert latest is not None
    assert latest["posture"]["gateway"] == "192.168.1.1"
    assert len(latest["connections"]) == 1
    assert len(latest["listeners"]) == 1
    assert len(latest["findings"]) == 1


def test_network_intelligence_refresh_uses_fallback_when_diagnostics_fail(tmp_path: Path, monkeypatch) -> None:
    import os

    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication
    import mac_audit_agent.ui.main_window as main_window

    app = QApplication.instance() or QApplication([])

    class FakeCollector:
        def collect(self, baseline=None, settings=None):
            return NetworkIntelligenceSnapshot(
                connections=[NetworkConnection(process_name="Safari", remote_address="93.184.216.34")],
            )

    monkeypatch.setattr(main_window, "NetworkIntelligenceCollector", FakeCollector)
    monkeypatch.setattr(main_window, "build_network_intelligence_diagnostics", lambda *args, **kwargs: (_ for _ in ()).throw(TypeError("boom")))

    window = main_window.MainWindow(tmp_path / "audit.sqlite")
    window.refresh_network_intelligence()

    diagnostics = window.current_payload["network_intelligence"]["diagnostics"]
    assert diagnostics["failure_stage"] == "diagnostics_builder"
    assert diagnostics["last_error"] == "Diagnostics failed to generate. See logs."
    assert "Diagnostics failed to generate" in window.network_intelligence_panel.diagnostics_text.toPlainText()

    window.close()
    app.processEvents()


def test_sentinel_adapter_absorbs_payload_without_standalone_runtime() -> None:
    snapshot = sentinel_scan_to_snapshot(
        {
            "timestamp": "2026-07-02T00:00:00Z",
            "connections": [{"process": "curl", "remote_address": "93.184.216.34", "remote_port": "443", "protocol": "TCP"}],
            "listeners": [{"process": "node", "address": "127.0.0.1", "port": "3000", "protocol": "TCP"}],
            "routes": {"default_route": {"gateway": "192.168.1.1", "interface": "en0"}},
            "dns_entries": [{"nameserver": "1.1.1.1"}],
            "findings": [{"title": "Network drift", "severity": "medium", "evidence": "dns changed"}],
        }
    )
    assert snapshot.connections[0].source_collector == "network_sentinel"
    assert snapshot.listeners[0].source_collector == "network_sentinel"
    assert snapshot.posture.gateway == "192.168.1.1"
    assert snapshot.findings[0].source == "network_sentinel"
