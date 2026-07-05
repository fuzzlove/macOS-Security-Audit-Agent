import json
from datetime import datetime
from pathlib import Path

import pytest
import ipaddress
from PySide6.QtGui import QColor

from mac_audit_agent.models import Finding, RawLogEntry, ScanResult, ScanSummary
from mac_audit_agent.reporting import (
    SEVERITY_COLOR_MAP,
    default_html_report_path,
    default_json_report_path,
    export_html_report,
    export_scan_result_html,
    export_scan_result_json,
    export_json_report,
    get_reports_dir,
    summarize_findings_by_severity,
)
from mac_audit_agent.ui.main_window import severity_qcolors


def make_finding(finding_id: str, severity: str, title: str, evidence: str = "127.0.0.1:8888") -> Finding:
    return Finding(
        id=finding_id,
        category="Network<script>",
        title=title,
        severity=severity,  # type: ignore[arg-type]
        description='desc <b>unsafe</b>',
        evidence=evidence,
        command_used='lsof && echo "<bad>"',
        remediation_suggestion='review "carefully"',
        warning='be careful <script>',
        evidence_summary="Port 8888 listening",
        raw_evidence_ref="log-1",
        why_this_matters="Unexpected listeners expand attack surface.",
        false_positive_notes="Could be a local dev service.",
        recommended_next_steps="Verify owning process and whether the service is expected.",
        what_can_go_wrong="Stopping the wrong process may interrupt legitimate work.",
        remediation_references=["Apple Platform Security: Network security and service exposure hardening guidance"],
    )


def make_summary() -> ScanSummary:
    return ScanSummary(
        scan_id="scan-1",
        started_at="2026-04-23T00:00:00Z",
        completed_at="2026-04-23T00:10:00Z",
        findings_count=2,
        security_score=85,
        notes="test",
    )


def make_scan_result() -> ScanResult:
    return ScanResult(
        scan_id="scan-1",
        timestamp="2026-04-23T00:10:00Z",
        hostname="macbook.local",
        current_user="m",
        findings=[make_finding("finding-1", "medium", "Concerning Port")],
        raw_logs=[RawLogEntry("ports", "lsof", "2026-04-23T00:10:00Z", 0, "", "safe summary")],
        collected_artifacts={
            "history_indicators": [{"shell_type": "zsh", "pattern_id": "curl_pipe_sh", "match_count": 1, "snippet": "curl ... | sh"}],
            "ports": {
                "listening": [{"process_name": "ControlCe", "pid": 642, "local_address": "127.0.0.1:7000", "port": 7000, "protocol": "TCP", "state": "LISTEN", "concern": "Review needed", "severity": "low", "recommended_next_checks": "Verify"}],
                "active_connections": [],
                "suspicious_review_needed": [{"process_name": "ControlCe", "pid": 642, "local_address": "127.0.0.1:7000", "port": 7000, "protocol": "TCP", "state": "LISTEN", "concern": "Review needed", "severity": "low", "recommended_next_checks": "Verify"}],
                "errors": [],
            },
            "localhost_scan": {
                "target": "127.0.0.1",
                "mode": "safe",
                "protocol": "both",
                "open_ports": {"tcp": [7000], "udp": [5353]},
                "missing_from_enumeration": [5353],
                "errors": [],
                "scanned_port_count": 12,
                "engine": "nmap",
                "nmap": {
                    "installed": True,
                    "path": "/opt/homebrew/bin/nmap",
                    "profile": "Localhost TCP Quick",
                    "target": "127.0.0.1",
                    "command_used": ["nmap -sT -Pn -n --top-ports 1000 127.0.0.1 -oX -"],
                    "ports": [
                        {
                            "host": "127.0.0.1",
                            "port": 7000,
                            "protocol": "tcp",
                            "state": "open",
                            "service": "http",
                            "product": "dev server",
                            "version": "1",
                            "reason": "syn-ack",
                            "confidence": "high",
                        }
                    ],
                    "warnings": [],
                    "errors": [],
                    "sudo_required": False,
                    "fallback_used": False,
                },
            },
            "packet_captures": [
                {
                    "capture_id": "capture-1",
                    "status": "completed",
                    "interface": "en0",
                    "duration_seconds": 30,
                    "filter": "tcp",
                    "pcap_path": "evidence/packet_capture_1.pcap",
                    "pcap_sha256": "abc123",
                    "file_size_bytes": 64,
                    "command_used": ["/usr/sbin/tcpdump", "-i", "en0"],
                }
            ],
            "network_discovery": {
                "interface": "en0",
                "subnet": "192.168.1.0/24",
                "gateway_ip": "192.168.1.1",
                "gateway_mac": "aa:bb:cc:dd:ee:ff",
                "scope": "private",
                "host_count": 1,
                "review_needed_count": 0,
                "methods_used": ["arp -a", "dns-sd"],
                "devices": [
                    {
                        "ip_address": "192.168.1.20",
                        "mac_address": "11:22:33:44:55:66",
                        "hostname": "",
                        "likely_hostname": "Johns-MacBook-Pro.local",
                        "reverse_dns": "Johns-MacBook-Pro.local",
                        "mdns_name": "Johns-MacBook-Pro.local",
                        "netbios_name": "",
                        "vendor": "Apple",
                        "device_type": "MacBook Pro",
                        "confidence": "high",
                        "discovery_methods": ["arp", "mdns"],
                        "review_flags": [],
                        "first_seen": "2026-04-26T00:00:00Z",
                        "last_seen": "2026-04-26T00:01:00Z",
                        "baseline_status": "matched baseline",
                    }
                ],
                "comparison": {},
                "debug_logs": ["arp rows parsed: 1", "mDNS names found: 1", "reverse dns count: 1", "merged device count: 1"],
                "errors": [],
            },
            "processes": {
                "all": [{"pid": 642, "ppid": 1, "user": "m", "command_path": "/Applications/Test.app/Contents/MacOS/Test", "process_name": "Test", "signed_status": "signed", "trust_level": "review", "trust_score": 72, "trust_summary": "Nonstandard executable path without stronger risk indicators.", "reasons": ["nonstandard_process_path"]}],
                "suspicious": [{"pid": 642, "ppid": 1, "user": "m", "command_path": "/Applications/Test.app/Contents/MacOS/Test", "process_name": "Test", "signed_status": "signed", "trust_level": "review", "trust_score": 72, "trust_summary": "Nonstandard executable path without stronger risk indicators.", "reasons": ["nonstandard_process_path"]}],
                "errors": [],
            },
        },
        baseline_diff={
            "new_ports": [{"item_key": "port", "details": "new port"}],
            "resolved_findings": [],
            "drift_score": 22,
            "drift_label": "moderate drift",
            "drift_summary": "1 total changes, 0 high-risk changes, drift score 22/100.",
            "high_risk_change_count": 0,
        },
        errors=[],
    )


def test_report_export(tmp_path: Path) -> None:
    summary = make_summary()
    finding = make_finding("finding-1", "medium", "Concerning Port")
    json_path = tmp_path / "report.json"
    html_path = tmp_path / "report.html"
    export_json_report(summary, [finding], json_path, dashboard={"new_since_last_scan": 1})
    saved_path = export_html_report(summary, [finding], html_path, dashboard={"new_since_last_scan": 1})
    assert json_path.exists()
    assert html_path.exists()
    assert saved_path == html_path
    assert "Concerning Port" in html_path.read_text(encoding="utf-8")
    assert '"new_since_last_scan": 1' in json_path.read_text(encoding="utf-8")
    assert "Drift score: 0/100" in html_path.read_text(encoding="utf-8")
    assert "Report Summary" in html_path.read_text(encoding="utf-8")
    assert "macOS Security Audit Report" not in html_path.read_text(encoding="utf-8")


def test_html_report_file_is_created_at_default_path(tmp_path: Path, monkeypatch) -> None:
    summary = make_summary()
    finding = make_finding("finding-1", "medium", "Concerning Port")
    monkeypatch.setattr("mac_audit_agent.reporting.Path.home", lambda: tmp_path)
    saved_path = export_html_report(summary, [finding], None, dashboard={}, comparison=None)
    assert saved_path.exists()
    assert saved_path.name.startswith("mac_audit_report_")
    assert saved_path.suffix == ".html"
    saved_path.unlink()


def test_html_contains_escaped_content(tmp_path: Path) -> None:
    summary = make_summary()
    finding = make_finding("finding-1", "high", 'Bad <script>alert(1)</script>', evidence='<img src=x onerror=1>')
    html_path = tmp_path / "report.html"
    export_html_report(summary, [finding], html_path)
    content = html_path.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in content
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in content
    assert "&lt;img src=x onerror=1&gt;" in content
    assert '&lt;bad&gt;' in content


def test_severity_css_classes_exist(tmp_path: Path) -> None:
    summary = make_summary()
    findings = [make_finding(f"finding-{severity}", severity, severity.title()) for severity in SEVERITY_COLOR_MAP]
    html_path = tmp_path / "report.html"
    export_html_report(summary, findings, html_path)
    content = html_path.read_text(encoding="utf-8")
    for severity in SEVERITY_COLOR_MAP:
        assert f".severity-{severity}" in content
        assert f'class="severity-badge severity-{severity}"' in content
    assert "rgba(" not in content


def test_all_findings_appear_in_report(tmp_path: Path) -> None:
    summary = make_summary()
    findings = [
        make_finding("finding-1", "info", "First"),
        make_finding("finding-2", "critical", "Second"),
    ]
    html_path = tmp_path / "report.html"
    export_html_report(summary, findings, html_path)
    content = html_path.read_text(encoding="utf-8")
    assert "First" in content
    assert "Second" in content


def test_invalid_output_path_fails_gracefully(tmp_path: Path) -> None:
    summary = make_summary()
    finding = make_finding("finding-1", "medium", "Concerning Port")
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")
    with pytest.raises(OSError):
        export_html_report(summary, [finding], blocker / "report.html")


def test_color_mapping_supports_all_severities() -> None:
    assert set(SEVERITY_COLOR_MAP.keys()) == {"info", "low", "medium", "high", "critical"}
    assert SEVERITY_COLOR_MAP["info"] == {"bg": "#344054", "fg": "#FFFFFF"}
    assert SEVERITY_COLOR_MAP["low"] == {"bg": "#175CD3", "fg": "#FFFFFF"}
    assert SEVERITY_COLOR_MAP["medium"] == {"bg": "#B54708", "fg": "#FFFFFF"}
    assert SEVERITY_COLOR_MAP["high"] == {"bg": "#B42318", "fg": "#FFFFFF"}
    assert SEVERITY_COLOR_MAP["critical"] == {"bg": "#7A0000", "fg": "#FFFFFF"}


def test_no_color_uses_transparency() -> None:
    for colors in SEVERITY_COLOR_MAP.values():
        for value in colors.values():
            assert value.startswith("#")
            assert len(value) == 7


def test_ui_mapping_function_returns_valid_qcolor() -> None:
    for severity, colors in SEVERITY_COLOR_MAP.items():
        bg, fg = severity_qcolors(severity)
        assert isinstance(bg, QColor)
        assert isinstance(fg, QColor)
        assert bg.isValid()
        assert fg.isValid()
        assert bg.name().upper() == colors["bg"]
        assert fg.name().upper() == colors["fg"]


def test_summary_counts_by_severity() -> None:
    findings = [
        make_finding("f1", "info", "a"),
        make_finding("f2", "high", "b"),
        make_finding("f3", "high", "c"),
    ]
    counts = summarize_findings_by_severity(findings)
    assert counts["info"] == 1
    assert counts["high"] == 2
    assert counts["critical"] == 0


def test_report_functions_accept_mixed_finding_payloads(tmp_path: Path) -> None:
    summary = make_summary()
    mixed_findings = [
        make_finding("finding-1", "medium", "Concerning Port"),
        make_finding("finding-2", "high", "Another").to_dict(),
    ]
    json_path = export_json_report(summary, mixed_findings, tmp_path / "mixed.json")
    html_path = export_html_report(summary, mixed_findings, tmp_path / "mixed.html")
    assert json_path.exists()
    assert html_path.exists()
    assert "Concerning Port" in html_path.read_text(encoding="utf-8")


def test_default_html_report_path_format(tmp_path: Path) -> None:
    path = default_html_report_path(tmp_path, datetime(2026, 4, 23, 10, 11, 12))
    assert path == tmp_path / "reports" / "mac_audit_report_20260423_101112.html"


def test_default_json_report_path_format(tmp_path: Path) -> None:
    path = default_json_report_path(tmp_path, datetime(2026, 4, 23, 10, 11, 12))
    assert path == tmp_path / "reports" / "mac_audit_report_20260423_101112.json"


def test_reports_dir_defaults_to_application_support(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("mac_audit_agent.reporting.Path.home", lambda: tmp_path)
    reports_dir = get_reports_dir()
    assert reports_dir == tmp_path / "Library" / "Application Support" / "MacAuditAgent" / "reports"
    assert reports_dir.exists()


def test_default_report_exports_use_application_support_when_no_output_path(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("mac_audit_agent.reporting.Path.home", lambda: tmp_path)
    summary = make_summary()
    finding = make_finding("finding-1", "medium", "Concerning Port")
    json_path = export_json_report(summary, [finding], None)
    html_path = export_html_report(summary, [finding], None)
    assert json_path.parent == tmp_path / "Library" / "Application Support" / "MacAuditAgent" / "reports"
    assert html_path.parent == tmp_path / "Library" / "Application Support" / "MacAuditAgent" / "reports"
    assert json_path.exists()
    assert html_path.exists()


def test_scan_result_exports_include_logs_and_history(tmp_path: Path) -> None:
    scan_result = make_scan_result()
    scan_result.collected_artifacts["network_discovery"] = {
        "interface": "en0",
        "subnet": ipaddress.IPv4Network("192.168.1.0/24"),
        "gateway_ip": ipaddress.IPv4Address("192.168.1.1"),
        "gateway_mac": "aa:bb:cc:dd:ee:ff",
        "scope": "private",
        "host_count": 1,
        "review_needed_count": 0,
        "methods_used": ["arp -a", "dns-sd"],
        "devices": [
            {
                "ip_address": ipaddress.IPv4Address("192.168.1.20"),
                "mac_address": "11:22:33:44:55:66",
                "hostname": "",
                "likely_hostname": "Johns-MacBook-Pro.local",
                "reverse_dns": "Johns-MacBook-Pro.local",
                "mdns_name": "Johns-MacBook-Pro.local",
                "netbios_name": "",
                "vendor": "Apple",
                "device_type": "MacBook Pro",
                "confidence": "high",
                "discovery_methods": ["arp", "mdns"],
                "review_flags": [],
                "first_seen": "2026-04-26T00:00:00Z",
                "last_seen": "2026-04-26T00:01:00Z",
                "baseline_status": "matched baseline",
            }
        ],
        "comparison": {},
        "debug_logs": ["arp rows parsed: 1", "mDNS names found: 1", "reverse dns count: 1", "merged device count: 1"],
        "errors": [],
    }
    json_path = export_scan_result_json(scan_result, tmp_path / "scan.json")
    html_path = export_scan_result_html(scan_result, tmp_path / "scan.html")
    json_content = json_path.read_text(encoding="utf-8")
    html_content = html_path.read_text(encoding="utf-8")
    assert '"raw_logs"' in json_content
    assert '"security_score"' in json_content
    assert '"localhost_scan"' in json_content
    assert '"execution_evidence"' in json_content
    assert "Raw Logs" in html_content
    assert "History Indicators" in html_content
    assert "Baseline Comparison" in html_content
    assert "Execution Evidence" in html_content
    assert "Localhost Port Scan" in html_content
    assert "References:" in html_content
    assert 'class="report-logo"' in html_content
    assert "Report Summary" in html_content
    assert "macOS Security Audit Report" not in html_content
    assert "Johns-MacBook-Pro.local" in html_content
    assert '"nmap_scan"' in json_content
    assert "Nmap Project" in json_content
    assert "Nmap Local Scan" in html_content
    assert "https://nmap.org/" in html_content
    assert "likely_hostname" in json_content
    assert "Johns-MacBook-Pro.local" in json_content
    assert '"subnet": "192.168.1.0/24"' in json_content


def test_html_report_includes_logo_when_available(tmp_path: Path) -> None:
    summary = make_summary()
    finding = make_finding("finding-1", "medium", "Concerning Port")
    html_path = tmp_path / "report.html"
    export_html_report(summary, [finding], html_path)
    content = html_path.read_text(encoding="utf-8")
    assert "data:image/png;base64," in content
    assert 'class="report-logo"' in content


def test_html_report_works_without_logo(tmp_path: Path, monkeypatch) -> None:
    summary = make_summary()
    finding = make_finding("finding-1", "medium", "Concerning Port")
    html_path = tmp_path / "report.html"
    monkeypatch.setattr("mac_audit_agent.reporting.get_asset_data_uri", lambda name: None)
    export_html_report(summary, [finding], html_path)
    content = html_path.read_text(encoding="utf-8")
    assert "Concerning Port" in content
    assert 'class="report-logo"' not in content


def test_notes_included_in_reports_only_when_selected(tmp_path: Path) -> None:
    scan_result = make_scan_result()
    notes = [{"updated_at": "2026-04-26T00:00:00Z", "title": "Case note", "status": "open", "priority": "high", "linked_finding_id": "finding-1", "body": "Investigate listener."}]
    audit_trail = [{"timestamp": "2026-04-26T00:01:00Z", "action_type": "note created", "details": "Case note", "previous_status": "", "new_status": ""}]
    json_without = export_scan_result_json(scan_result, tmp_path / "without.json")
    html_without = export_scan_result_html(scan_result, tmp_path / "without.html")
    json_with = export_scan_result_json(
        scan_result,
        tmp_path / "with.json",
        include_investigation_notes=True,
        investigation_notes=notes,
        investigation_audit_trail=audit_trail,
    )
    html_with = export_scan_result_html(
        scan_result,
        tmp_path / "with.html",
        include_investigation_notes=True,
        investigation_notes=notes,
        investigation_audit_trail=audit_trail,
    )
    assert "investigation_notes" not in json_without.read_text(encoding="utf-8")
    assert "Investigation Notes" not in html_without.read_text(encoding="utf-8")
    assert "investigation_notes" in json_with.read_text(encoding="utf-8")
    assert "Case note" in html_with.read_text(encoding="utf-8")


def test_reports_include_ports_and_processes(tmp_path: Path) -> None:
    scan_result = make_scan_result()
    json_path = export_scan_result_json(scan_result, tmp_path / "scan.json")
    html_path = export_scan_result_html(scan_result, tmp_path / "scan.html")
    json_content = json_path.read_text(encoding="utf-8")
    html_content = html_path.read_text(encoding="utf-8")
    assert '"ports"' in json_content
    assert '"processes"' in json_content
    assert '"localhost_scan"' in json_content
    assert "Ports" in html_content
    assert "Processes" in html_content
    assert ">72<" in html_content
    assert "Listening Ports" in html_content
    assert "127.0.0.1" in html_content


def test_reports_include_alert_provenance(tmp_path: Path) -> None:
    scan_result = make_scan_result()
    scan_result.findings[0].rule_id = "localhost_hidden_port_detected"
    scan_result.findings[0].trigger_source = "network_detector"
    scan_result.findings[0].trigger_subsource = "lsof_listener"
    scan_result.findings[0].correlation_id = "corr-123"
    scan_result.findings[0].previous_state = "closed"
    scan_result.findings[0].current_state = "listening"
    scan_result.findings[0].false_positive_hints = ["dev server"]
    scan_result.findings[0].recommended_verification_steps = ["inspect process"]
    json_path = export_scan_result_json(scan_result, tmp_path / "scan.json")
    html_path = export_scan_result_html(scan_result, tmp_path / "scan.html")
    json_content = json_path.read_text(encoding="utf-8")
    html_content = html_path.read_text(encoding="utf-8")
    assert '"rule_id": "localhost_hidden_port_detected"' in json_content
    assert "Alert Provenance" in html_content
    assert "corr-123" in html_content


def test_reports_include_apple_security_forecast_section(tmp_path: Path) -> None:
    scan_result = make_scan_result()
    scan_result.collected_artifacts["apple_security_forecast"] = {
        "generated_at": "2026-06-01T00:00:00+00:00",
        "level": "elevated",
        "sources_used": ["NVD CVE API", "CISA KEV", "FIRST EPSS"],
        "cve_count": 2,
        "kev_count": 1,
        "display_cards": [
            {
                "card_id": "card-1",
                "title": "CVE-2026-0001",
                "cves": ["CVE-2026-0001"],
                "cve_ids": ["CVE-2026-0001"],
                "source": "apple",
                "forecast_level": "elevated",
                "applicability_confidence": "high",
                "kev": True,
                "apple_related": True,
                "recommended_action": "Open System Settings > General > Software Update.",
                "status": "new",
                "why_shown_to_you": "Git is installed and matches the affected range.",
            }
        ],
        "cards": [
            {
                "card_id": "card-1",
                "title": "CVE-2026-0001",
                "forecast_level": "elevated",
                "applicability_confidence": "high",
                "kev": True,
                "apple_related": True,
                "source": "apple",
                "cves": ["CVE-2026-0001"],
                "recommended_action": "Open System Settings > General > Software Update.",
                "status": "new",
                "why_it_matters": "Git issue.",
            }
        ],
    }
    json_path = export_scan_result_json(scan_result, tmp_path / "scan.json")
    html_path = export_scan_result_html(scan_result, tmp_path / "scan.html")
    json_content = json_path.read_text(encoding="utf-8")
    html_content = html_path.read_text(encoding="utf-8")
    assert '"apple_security_forecast"' in json_content
    assert "Apple Exposure Assessment" in html_content
    assert "CVE-2026-0001" in html_content
    assert "Sources Used" in html_content


def test_reports_exclude_demo_stale_and_unrelated_forecast_cards(tmp_path: Path) -> None:
    scan_result = make_scan_result()
    scan_result.collected_artifacts["apple_security_forecast"] = {
        "generated_at": "2026-06-01T00:00:00+00:00",
        "level": "elevated",
        "display_cards": [
            {
                "card_id": "prod",
                "title": "macOS Security Update Available",
                "forecast_level": "elevated",
                "source": "apple",
                "affected_local_product": "macOS",
                "cves": ["CVE-2026-0001"],
                "recommended_action": "Review Software Update.",
            },
            {
                "card_id": "demo",
                "title": "Demo Forecast",
                "forecast_level": "urgent",
                "source": "apple",
                "simulated": True,
                "cves": ["DEMO-CVE"],
            },
            {
                "card_id": "ios",
                "title": "iOS Security Update",
                "forecast_level": "urgent",
                "source": "apple",
                "affected_local_product": "iOS",
                "affected_products": ["iOS"],
                "cves": ["CVE-2026-IOS"],
            },
            {
                "card_id": "review",
                "title": "Review Needed",
                "forecast_level": "watch",
                "source": "apple",
                "applicability": "review_needed",
                "cves": ["CVE-2026-REVIEW"],
            },
        ],
    }

    json_path = export_scan_result_json(scan_result, tmp_path / "scan.json")
    html_path = export_scan_result_html(scan_result, tmp_path / "scan.html")
    json_content = json_path.read_text(encoding="utf-8")
    html_content = html_path.read_text(encoding="utf-8")

    assert "macOS Security Update Available" in html_content
    assert "Demo Forecast" not in html_content
    assert "iOS Security Update" not in html_content
    assert "CVE-2026-REVIEW" not in html_content
    assert "Demo Forecast" not in json_content
    assert "CVE-2026-IOS" not in json_content


def test_reports_include_investigation_priorities_section(tmp_path: Path) -> None:
    scan_result = make_scan_result()
    json_path = export_scan_result_json(scan_result, tmp_path / "scan.json")
    html_path = export_scan_result_html(scan_result, tmp_path / "scan.html")
    json_content = json_path.read_text(encoding="utf-8")
    html_content = html_path.read_text(encoding="utf-8")
    assert '"investigation_priorities"' in json_content
    assert "Investigation Priorities" in html_content
    assert "Top Priorities" in html_content


def test_html_report_includes_integrity_manifest_mismatch_diagnostics(tmp_path: Path) -> None:
    scan_result = make_scan_result()
    scan_result.collected_artifacts["application_integrity"] = {
        "overall_status": "stale",
        "manifest_path": "/tmp/msaa_integrity_manifest.json",
        "source_type": "source_tree",
        "current_install_mode": "source_tree",
        "manifest_app_version": "0.9.4",
        "current_app_version": "0.9.5",
        "manifest_build_id": "old",
        "current_build_id": "new",
        "manifest_git_commit": "abc",
        "current_git_commit": "def",
        "manifest_package_version": "0.9.4",
        "current_package_version": "0.9.5",
        "manifest_root_path": "/tmp/old",
        "current_root_path": "/tmp/current",
        "manifest_created_at": "2026-06-01T00:00:00+00:00",
        "manifest_hash": "hash",
        "verification_result_id": "verify-1",
        "verified_at": "2026-07-01T00:00:00+00:00",
        "cached_result": False,
        "cache_valid": True,
        "cache_invalidated_reason": "bypassed",
        "matched_count": 10,
        "mismatched_count": 0,
        "missing_count": 0,
        "extra_count": 0,
        "exact_mismatch_reason": "Manifest version 0.9.4 differs from current app version 0.9.5.",
        "recommended_actions": ["Create new trusted manifest after verifying update."],
        "ignored_manifests": [{"path": "/tmp/integrity_manifest.json", "reason": "source_type does not match active install mode"}],
    }

    html_path = export_scan_result_html(scan_result, tmp_path / "scan.html")
    html_content = html_path.read_text(encoding="utf-8")

    assert "Integrity Verification" in html_content
    assert "Manifest version 0.9.4 differs from current app version 0.9.5." in html_content
    assert "The integrity manifest was generated for a different MSAA build. This does not by itself prove tampering." in html_content
    assert "Cache Invalidated Reason" in html_content
    assert "bypassed" in html_content
    assert "/tmp/integrity_manifest.json" in html_content


def test_professional_html_report_is_navigable_compact_and_mode_aware(tmp_path: Path) -> None:
    long_evidence = "\n".join([f"raw evidence line {index}" for index in range(1, 12)])
    scan_result = make_scan_result()
    scan_result.findings = [make_finding("finding-long", "high", "Long Evidence Finding", evidence=long_evidence)]
    scan_result.raw_logs = [RawLogEntry("collector", "command", "2026-04-23T00:10:00Z", 0, "", "RAW-LOG-SECRET-LINE")]

    executive_path = export_scan_result_html(scan_result, tmp_path / "executive.html", detail_level="executive")
    executive = executive_path.read_text(encoding="utf-8")

    for required in [
        'aria-label="Report navigation"',
        'id="executive-summary"',
        'id="risk-overview"',
        'id="top-priorities"',
        'id="findings"',
        'id="recommended-fixes"',
        'id="appendices"',
        'class="finding-card"',
        "<summary>",
        "@media print",
        "Back to top",
        "severity-high",
    ]:
        assert required in executive
    assert "cdn." not in executive.lower()
    assert "RAW-LOG-SECRET-LINE" not in executive
    main_before_appendix = executive.split('id="appendices"')[0]
    assert "raw evidence line 11" not in main_before_appendix
    assert "raw evidence line 11" in executive
    assert "&lt;b&gt;unsafe&lt;/b&gt;" in executive

    technical_path = export_scan_result_html(scan_result, tmp_path / "technical.html", detail_level="full_technical")
    technical = technical_path.read_text(encoding="utf-8")
    assert "RAW-LOG-SECRET-LINE" in technical


def test_reports_include_reliability_trust_and_drift_sections(tmp_path: Path) -> None:
    scan_result = make_scan_result()
    reliability = {
        "alert_pipeline": {
            "last_failure_stage": "policy",
            "suppressed_count": 2,
            "no_policy_match_count": 1,
            "db_path_mismatch": False,
        },
        "monitoring_coverage": {
            "score": 82,
            "components": [
                {
                    "name": "Bluetooth detector",
                    "status": "degraded",
                    "last_successful_run": "2026-06-16T10:00:00+00:00",
                    "last_event": "bluetooth_inventory_changed",
                    "last_error": "stale heartbeat",
                    "heartbeat_age_seconds": 999,
                    "permission_status": "available",
                    "failure_reason": "Heartbeat age exceeded threshold",
                    "recommended_fix": "Restart monitoring.",
                }
            ],
        },
        "release_readiness": {"ReleaseReadinessScore": 74, "status": "needs work", "checks": []},
        "trust_decay": {
            "previous_score": 89,
            "current_score": 71,
            "delta": -18,
            "trend": "declining",
            "score_history": [
                {
                    "created_at": "2026-06-16T10:05:00+00:00",
                    "previous_score": 89,
                    "current_score": 71,
                    "delta": -18,
                    "causes": ["New LaunchDaemon", "Unknown USB"],
                    "related_events": [{"event_id": "event-1", "event_type": "launchdaemon_added"}],
                    "recommended_action": "Review persistence and device inventory.",
                }
            ],
            "timeline": [
                {
                    "created_at": "2026-06-16T10:05:00+00:00",
                    "previous_score": 89,
                    "current_score": 71,
                    "delta": -18,
                    "causes": ["New LaunchDaemon", "Unknown USB"],
                    "recommended_action": "Review persistence and device inventory.",
                }
            ],
        },
        "configuration_drift": {
            "changes": [
                {
                    "setting": "Remote Login",
                    "previous_value": "Disabled",
                    "current_value": "Enabled",
                    "first_seen": "2026-06-16T10:00:00+00:00",
                    "last_seen": "2026-06-16T10:05:00+00:00",
                    "source_detector": "session",
                    "confidence": "medium",
                    "severity": "high",
                    "why_it_matters": "SSH access is now available.",
                    "recommended_verification": "Review Sharing settings.",
                }
            ]
        },
        "incident_mode": {"active": True},
    }
    scan_result.collected_artifacts["reliability"] = reliability

    json_path = export_scan_result_json(scan_result, tmp_path / "scan.json")
    html_path = export_scan_result_html(scan_result, tmp_path / "scan.html")
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    html_content = html_path.read_text(encoding="utf-8")

    assert payload["report_summary"]["reliability_summary"]["monitoring_coverage_score"] == 82
    assert payload["report_summary"]["reliability_summary"]["incident_mode_active"] is True
    assert payload["reliability"]["trust_decay"]["delta"] == -18
    assert payload["reliability"]["trust_decay"]["score_history"][0]["related_events"][0]["event_id"] == "event-1"
    assert "Reliability and Trust" in html_content
    assert "Monitoring Coverage Dashboard" in html_content
    assert "Trust Timeline" in html_content
    assert "New LaunchDaemon" in html_content
    assert "Configuration Drift Timeline" in html_content
    assert "Incident Mode Active" in html_content
    assert "Heartbeat Age" in html_content
    assert "999" in html_content
    assert "available" in html_content
    assert "Remote Login" in html_content
    assert "Confidence" in html_content
    assert "medium" in html_content


def test_reports_include_empty_apple_security_forecast_section(tmp_path: Path) -> None:
    scan_result = make_scan_result()
    json_path = export_scan_result_json(scan_result, tmp_path / "scan.json")
    html_path = export_scan_result_html(scan_result, tmp_path / "scan.html")
    json_content = json_path.read_text(encoding="utf-8")
    html_content = html_path.read_text(encoding="utf-8")
    assert '"apple_security_forecast_summary"' in json_content
    assert "Apple Exposure Assessment: no applicable cards at report time." in html_content


def test_packet_capture_metadata_included_but_contents_not_embedded(tmp_path: Path) -> None:
    scan_result = make_scan_result()
    pcap_path = tmp_path / "capture.pcap"
    pcap_path.write_text("SUPER-SECRET-PACKET-CONTENT", encoding="utf-8")
    scan_result.collected_artifacts["packet_captures"][0]["pcap_path"] = str(pcap_path)
    json_path = export_scan_result_json(scan_result, tmp_path / "scan.json")
    html_path = export_scan_result_html(scan_result, tmp_path / "scan.html")
    json_content = json_path.read_text(encoding="utf-8")
    html_content = html_path.read_text(encoding="utf-8")
    assert '"packet_captures"' in json_content
    assert "Packet Capture Snapshot" in html_content
    assert str(pcap_path) in html_content
    assert "SUPER-SECRET-PACKET-CONTENT" not in html_content


def test_apple_exposure_reports_include_update_guidance(tmp_path: Path) -> None:
    scan_result = make_scan_result()
    scan_result.collected_artifacts["apple_security_forecast"] = {
        "generated_at": "2026-06-01T00:00:00+00:00",
        "level": "urgent",
        "display_cards": [
            {
                "card_id": "card-guidance",
                "title": "Safari/WebKit Security Update",
                "forecast_level": "urgent",
                "source": "apple",
                "affected_local_product": "Safari/WebKit",
                "detected_version": "17.0",
                "fixed_version": "17.1",
                "recommended_action": "Install available Apple updates.",
                "references": ["https://support.apple.com/en-us/100100"],
            }
        ],
    }
    json_path = export_scan_result_json(scan_result, tmp_path / "scan.json")
    html_path = export_scan_result_html(scan_result, tmp_path / "scan.html")
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    card = payload["report_summary"]["apple_security_forecast_summary"]["cards"][0]
    html_content = html_path.read_text(encoding="utf-8")

    assert card["update_guidance"]["title"] == "Safari / WebKit Security Update Guidance"
    assert card["update_guidance"]["recommended_actions"]
    assert card["update_guidance"]["verification_steps"]
    assert card["update_guidance"]["evidence_preservation_notes"]
    assert "Update Guidance Summary" in html_content
    assert "Evidence Preservation" in html_content
    assert "Re-run Apple Exposure Assessment" in html_content
