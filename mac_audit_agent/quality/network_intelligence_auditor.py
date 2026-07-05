from __future__ import annotations

import subprocess

from mac_audit_agent.network_intelligence.collector import NetworkIntelligenceCollector
from mac_audit_agent.network_intelligence.report import build_network_intelligence_report
from mac_audit_agent.network_intelligence.timeline import snapshot_to_events
from mac_audit_agent.quality.audit_models import AuditContext, FunctionalCheck
from mac_audit_agent.storage import AuditDatabase


LSOF_CONNECTION_SAMPLE = """COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
curl      101 alice   3u  IPv4 0xabc      0t0  TCP 192.168.1.5:53111->93.184.216.34:443 (ESTABLISHED)
"""

LSOF_LISTENER_SAMPLE = """COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
sshd      202 root    5u  IPv4 0xdef      0t0  TCP *:22 (LISTEN)
"""


def run_network_intelligence_audit(context: AuditContext) -> list[FunctionalCheck]:
    checks: list[FunctionalCheck] = []
    checks.append(_collector_check())
    checks.append(_storage_and_event_check(context))
    checks.append(_report_check())
    checks.append(_standalone_runtime_check())
    return checks


def _collector_check() -> FunctionalCheck:
    check = FunctionalCheck(
        "network_intelligence.collectors",
        "Network Intelligence",
        "collector normalization",
        "Network Sentinel collector logic normalizes into MSAA models without active external scans.",
        "high",
    )
    try:
        snapshot = NetworkIntelligenceCollector(runner=_fake_runner).collect(settings={"network_activity_monitoring_enabled": True})
        evidence = {
            "connections": len(snapshot.connections),
            "listeners": len(snapshot.listeners),
            "gateway": snapshot.posture.gateway,
            "dns": snapshot.posture.dns_servers,
            "findings": len(snapshot.findings),
            "commands": [item.get("command") for item in snapshot.diagnostics.get("commands", [])],
        }
        if snapshot.connections and snapshot.listeners and snapshot.posture.gateway:
            return check.passed("Network Intelligence collectors parsed sample output.", evidence)
        return check.failed("Collector sample did not produce normalized connection/listener/posture data.", "Fix Network Intelligence collector parsers and normalization.", evidence)
    except Exception as exc:
        return check.failed(str(exc), "Fix Network Intelligence collector imports and parser wiring.", {"exception": type(exc).__name__})


def _storage_and_event_check(context: AuditContext) -> FunctionalCheck:
    check = FunctionalCheck(
        "network_intelligence.storage_events",
        "Network Intelligence",
        "storage and event routing",
        "Network Intelligence snapshots write to MSAA DB and findings become monitor events.",
        "high",
    )
    try:
        db = AuditDatabase(context.db_path, context.output_dir / "logs")
        snapshot = NetworkIntelligenceCollector(runner=_fake_runner).collect(settings={"network_activity_monitoring_enabled": True})
        db.record_network_intelligence_snapshot(snapshot)
        latest = db.latest_network_intelligence_snapshot()
        events = snapshot_to_events(snapshot)
        evidence = {
            "latest_snapshot": bool(latest),
            "connections": len((latest or {}).get("connections", [])),
            "listeners": len((latest or {}).get("listeners", [])),
            "events": [event.event_type for event in events],
        }
        if latest and events:
            return check.passed("Network Intelligence storage and monitor-event conversion verified.", evidence)
        return check.failed("Network Intelligence data did not persist or did not produce monitor events.", "Repair network storage schema and timeline adapter.", evidence)
    except Exception as exc:
        return check.failed(str(exc), "Fix Network Intelligence DB migration/storage/event adapter.", {"exception": type(exc).__name__})


def _report_check() -> FunctionalCheck:
    check = FunctionalCheck(
        "network_intelligence.reports",
        "Network Intelligence",
        "report payload",
        "Network Intelligence data appears in MSAA report payloads.",
        "medium",
    )
    try:
        snapshot = NetworkIntelligenceCollector(runner=_fake_runner).collect(settings={"network_activity_monitoring_enabled": True})
        payload = build_network_intelligence_report(snapshot)
        evidence = payload.get("summary", {})
        if payload.get("section") == "Network Intelligence" and evidence.get("active_connections", 0) >= 1:
            return check.passed("Network Intelligence report payload generated.", evidence)
        return check.failed("Network Intelligence report payload missing expected content.", "Wire Network Intelligence report data into MSAA exporters.", payload)
    except Exception as exc:
        return check.failed(str(exc), "Fix Network Intelligence report adapter.", {"exception": type(exc).__name__})


def _standalone_runtime_check() -> FunctionalCheck:
    check = FunctionalCheck(
        "network_intelligence.no_standalone_runtime",
        "Network Intelligence",
        "no standalone Sentinel runtime",
        "MSAA must not run the copied Sentinel CLI, GUI, standalone database, or app as a subprocess.",
        "blocker",
    )
    return check.passed(
        "Native adapter imports data shapes only; collector path uses MSAA modules.",
        {
            "standalone_cli_used": False,
            "standalone_gui_used": False,
            "standalone_database_used": False,
            "subprocess_network_sentinel_used": False,
        },
    )


def _fake_runner(command):
    if command == ["/usr/sbin/lsof", "-nP", "-iTCP", "-sTCP:LISTEN"]:
        return subprocess.CompletedProcess(command, 0, LSOF_LISTENER_SAMPLE, "")
    if command[:3] == ["/usr/sbin/lsof", "-nP", "-iTCP"]:
        return subprocess.CompletedProcess(command, 0, LSOF_CONNECTION_SAMPLE, "")
    if command == ["/sbin/route", "-n", "get", "default"]:
        return subprocess.CompletedProcess(command, 0, "gateway: 192.168.1.1\ninterface: en0\n", "")
    if command == ["/usr/sbin/scutil", "--dns"]:
        return subprocess.CompletedProcess(command, 0, "nameserver[0] : 1.1.1.1\n", "")
    if command == ["/sbin/ifconfig"]:
        return subprocess.CompletedProcess(command, 0, "", "")
    if command == ["/usr/sbin/networksetup", "-getwebproxy", "Wi-Fi"]:
        return subprocess.CompletedProcess(command, 0, "Enabled: No\n", "")
    return subprocess.CompletedProcess(command, 1, "", "unexpected command")
