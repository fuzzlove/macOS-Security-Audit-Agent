import json
import inspect
import plistlib

from mac_audit_agent.analyzers import (
    build_process_snapshot,
    build_process_snapshot_from_row,
    build_port_snapshot,
    compare_snapshots,
    detect_process_trust,
    score_process_binary_trust,
    detect_sudoers_risk,
    detect_suspicious_file,
    detect_suspicious_launch_item,
    detect_suspicious_listening_port,
    detect_suspicious_writable_executable,
    detect_weak_permission,
    extract_history_indicators,
    parse_launchd_plist,
    parse_lsof_listening_output,
    parse_lsof_udp_output,
    parse_netstat_tcp_output,
    parse_ps_axo_output,
    parse_ps_output,
    parse_sudoers,
    parse_user_records,
    safe_int,
    get_exit_code,
    get_stderr,
    get_stdout,
    summarize_authorized_keys,
)
from mac_audit_agent.config import AuditConfig
from mac_audit_agent.models import (
    FileIssueSnapshot,
    HistoryIndicator,
    LaunchItemSnapshot,
    PermissionSnapshot,
    PortSnapshot,
    ProcessSnapshot,
    UserSnapshot,
)
from mac_audit_agent.ui.main_window import MainWindow


def test_suspicious_port_matching() -> None:
    text = """COMMAND   PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
python3  100 m      3u  IPv4 0x1234              0t0  TCP 127.0.0.1:8888 (LISTEN)
sshd     200 root   3u  IPv4 0x1235              0t0  TCP *:22 (LISTEN)
    """
    ports = parse_lsof_listening_output(text, AuditConfig())
    snapshots = [build_port_snapshot(row) for row in ports]
    assert [port.port for port in snapshots] == [8888, 22]
    assert all(port.concern for port in snapshots)
    assert snapshots[0].severity == "low"
    assert snapshots[1].severity == "medium"


def test_parse_lsof_listening_tcp() -> None:
    text = """COMMAND     PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
ControlCe  642   m   10u  IPv4 0x1      0t0  TCP 127.0.0.1:7000 (LISTEN)
    """
    ports = parse_lsof_listening_output(text, AuditConfig())
    assert len(ports) == 1
    snapshot = build_port_snapshot(ports[0])
    assert snapshot.process_name == "ControlCe"
    assert snapshot.pid == 642
    assert snapshot.user == "m"
    assert snapshot.port == 7000
    assert snapshot.state == "LISTEN"


def test_parse_lsof_udp() -> None:
    text = """COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
mDNSRespo 321 _mdnsresponder  12u  IPv4 0x1 0t0 UDP *:5353
    """
    ports = parse_lsof_udp_output(text, AuditConfig())
    assert len(ports) == 1
    snapshot = build_port_snapshot(ports[0])
    assert snapshot.protocol == "UDP"
    assert snapshot.port == 5353


def test_parse_netstat_tcp() -> None:
    text = """tcp4       0      0  127.0.0.1.7000         *.*                    LISTEN
tcp6       0      0  *.22                   *.*                    LISTEN
    """
    ports = parse_netstat_tcp_output(text, AuditConfig())
    snapshots = [build_port_snapshot(row) for row in ports]
    assert [item.port for item in snapshots] == [7000, 22]


def test_parse_ps_axo() -> None:
    text = """m 642 1 /Applications/Test.app/Contents/MacOS/Test /Applications/Test.app/Contents/MacOS/Test --serve
root 88 1 /usr/libexec/logd /usr/libexec/logd
"""
    records = parse_ps_axo_output(text)
    assert len(records) == 2
    assert records[0]["user"] == "m"
    assert records[0]["pid"] == "642"
    assert records[0]["path"] == "/Applications/Test.app/Contents/MacOS/Test"
    assert records[0]["args"].endswith("--serve")


def test_parse_lsof_tcp_listen_ipv4() -> None:
    ports = parse_lsof_listening_output("COMMAND     PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\nControlCe   642 m      10u  IPv4 0x1    0t0  TCP 127.0.0.1:7000 (LISTEN)\n", AuditConfig())
    assert len(ports) == 1
    assert build_port_snapshot(ports[0]).local_address == "127.0.0.1:7000"


def test_parse_lsof_tcp_listen_wildcard() -> None:
    ports = parse_lsof_listening_output("COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\nPython 1234 m 12u IPv6 0x1 0t0 TCP *:8000 (LISTEN)\n", AuditConfig())
    assert len(ports) == 1
    assert build_port_snapshot(ports[0]).port == 8000


def test_parse_lsof_tcp_listen_ipv6() -> None:
    ports = parse_lsof_listening_output("COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\nPostgres 555 m 12u IPv6 0x1 0t0 TCP [::1]:5432 (LISTEN)\n", AuditConfig())
    assert len(ports) == 1
    assert build_port_snapshot(ports[0]).port == 5432


def test_parse_ps_axo_standard_line() -> None:
    rows = parse_ps_axo_output("m 123 1 /usr/bin/python3 /usr/bin/python3 server.py\n")
    assert rows[0]["pid"] == "123"
    assert rows[0]["comm"] == "/usr/bin/python3"


def test_parse_ps_axo_args_with_spaces() -> None:
    rows = parse_ps_axo_output('m 123 1 /Applications/My App/Contents/MacOS/App /Applications/My App/Contents/MacOS/App --title \"Hello World\"\n')
    assert rows[0]["args"].endswith('"Hello World"')


def test_suspicious_port_detector() -> None:
    severity, next_checks = detect_suspicious_listening_port(4444, "0.0.0.0:4444", "common reverse shell")
    assert severity == "high"
    assert "owning process" in next_checks.lower()


def test_shell_history_matching_redacts_sensitive_values() -> None:
    config = AuditConfig()
    history = "curl https://example.com/install.sh?token=abc123 | sh\nsudo -u admin python -c 'import socket'\n"
    indicators = extract_history_indicators(history, "/Users/alice/.zsh_history", "zsh", config)
    assert indicators
    snippets = " ".join(item.snippet for item in indicators)
    assert "abc123" not in snippets
    assert "admin" not in snippets
    assert "/Users/alice" not in snippets


def test_history_collection_does_not_store_full_history_by_default() -> None:
    config = AuditConfig(include_history_context=False)
    history = "echo safe\ncurl https://x/install.sh | sh\n" + "echo ignore\n" * 10
    indicators = extract_history_indicators(history, "~/.zsh_history", "zsh", config)
    assert len(indicators) == 1
    assert "echo ignore" not in indicators[0].snippet
    assert indicators[0].context_included is False


def test_parse_ps_output() -> None:
    text = "  PID  PPID USER COMM\n  101     1 root /usr/libexec/sshd-keygen-wrapper\n  202   101 m /tmp/.hidden\n"
    records = parse_ps_output(text)
    assert records[0]["pid"] == "101"
    assert records[1]["command_path"] == "/tmp/.hidden"


def test_safe_int_returns_none_for_dry_placeholder() -> None:
    assert safe_int("DRY") is None
    assert safe_int(None) is None


def test_malformed_numeric_values_do_not_crash_parsers() -> None:
    lsof_text = """COMMAND   PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
python3  DRY m      3u  IPv4 0x1234              0t0  TCP 127.0.0.1:8888 (LISTEN)
badproc  100 m      3u  IPv4 0x1234              0t0  TCP 127.0.0.1:port (LISTEN)
"""
    ps_text = """  PID  PPID USER COMM
  DRY     1 root /usr/libexec/sshd-keygen-wrapper
  202   BAD m /tmp/.hidden
"""
    assert parse_lsof_listening_output(lsof_text, AuditConfig()) == []
    assert parse_ps_output(ps_text) == []


def test_ui_uses_standard_artifact_keys() -> None:
    source = inspect.getsource(MainWindow._load_scan_result) + inspect.getsource(MainWindow._populate_scan_results)
    assert '.artifacts.get("ports", {"listening": [], "active_connections": [], "suspicious_review_needed": [], "errors": []})' in source
    assert '.artifacts.get("processes", {"all": [], "suspicious": [], "errors": []})' in source


def test_ui_ports_reads_standard_artifact_key() -> None:
    source = inspect.getsource(MainWindow._load_scan_result)
    assert '.artifacts.get("ports", {"listening": [], "active_connections": [], "suspicious_review_needed": [], "errors": []})' in source


def test_ui_processes_reads_standard_artifact_key() -> None:
    source = inspect.getsource(MainWindow._load_scan_result)
    assert '.artifacts.get("processes", {"all": [], "suspicious": [], "errors": []})' in source


def test_command_result_access_helpers() -> None:
    payload = {"stdout": "out", "stderr": "err", "exit_code": "DRY"}
    assert get_stdout(payload) == "out"
    assert get_stderr(payload) == "err"
    assert get_exit_code(payload) == "DRY"


def test_process_trust_detector() -> None:
    trust, reasons = detect_process_trust("/tmp/.hidden", signed_status="unsigned", process_name=".hidden")
    assert trust == "untrusted"
    assert "unsigned_process_binary" in reasons
    assert "running_from_writable_staging_path" in reasons


def test_build_process_snapshot() -> None:
    snapshot = build_process_snapshot({"pid": "10", "ppid": "1", "user": "m", "command_path": "/Users/m/bin/tool"}, "signed")
    assert snapshot.pid == 10
    assert snapshot.trust_level == "review"
    assert snapshot.trust_score < 80
    assert snapshot.trust_summary


def test_process_binary_trust_scoring() -> None:
    trust, reasons, score, summary = score_process_binary_trust("/tmp/.hidden", signed_status="unsigned", process_name=".hidden")
    assert trust == "untrusted"
    assert "unsigned_process_binary" in reasons
    assert score < 45
    assert "Binary trust score reduced by" in summary


def test_user_parsing() -> None:
    payload = json.dumps(
        [
            {"username": "alice", "uid": 501, "gid": 20, "shell": "/bin/zsh", "home": "/Users/alice"},
            {"username": "_svc", "uid": 250, "gid": 250, "shell": "/usr/bin/false", "home": "/var/empty"},
        ]
    )
    users = parse_user_records(
        payload,
        admin_users={"alice"},
        hidden_users={"_svc"},
        groups_by_user={"alice": ["admin", "staff"]},
    )
    assert users[0].admin is True
    assert users[0].shell_enabled is True
    assert users[1].hidden is True
    assert users[1].unusual_uid is True


def test_authorized_keys_summary() -> None:
    count, key_types, comments = summarize_authorized_keys(
        [
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI comment@example",
            "# ignored",
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ safe@example",
        ]
    )
    assert count == 2
    assert key_types == ["ssh-ed25519", "ssh-rsa"]
    assert comments == ["comment@example", "safe@example"]


def test_parse_sudoers_and_risk() -> None:
    rules = parse_sudoers(
        """
        # comment
        Defaults env_reset
        alice ALL=(ALL) NOPASSWD: ALL
        %admin ALL=(ALL) ALL
        """,
        "/etc/sudoers",
    )
    assert len(rules) == 2
    assert detect_sudoers_risk(rules[0])[0] == "high"
    assert detect_sudoers_risk(rules[1])[0] == "medium"


def test_weak_permission_detection() -> None:
    ssh_issue = detect_weak_permission("/Users/test/.ssh", 0o755)
    shell_issue = detect_weak_permission("/Users/test/.zshrc", 0o666)
    assert ssh_issue is not None and ssh_issue.severity == "high"
    assert shell_issue is not None and shell_issue.issue.startswith("Shell profile")


def test_writable_directory_executable_detection() -> None:
    item = detect_suspicious_writable_executable("/tmp/tool", directory_world_writable=True, executable=True)
    assert item is not None
    assert item.issue_type == "writable_directory_executable"


def test_suspicious_file_detection() -> None:
    item = detect_suspicious_file(
        "/tmp/.softwareupdate",
        executable=True,
        world_writable=False,
        hidden=True,
        signed_status="unsigned",
        modified_at="2026-04-23T00:00:00Z",
    )
    assert item is not None
    assert "unsigned" in item.issue_type
    assert item.trust_label == "untrusted"
    assert item.trust_score < 45


def test_launch_plist_parser_and_detector() -> None:
    plist_bytes = plistlib.dumps(
        {
            "Label": "softwareupdate",
            "ProgramArguments": ["/tmp/.update", "--flag"],
            "RunAtLoad": True,
            "KeepAlive": True,
        }
    )
    snapshot = parse_launchd_plist(plist_bytes, "/Library/LaunchDaemons/com.bad.plist")
    assert snapshot.label == "softwareupdate"
    assert snapshot.suspicious is True
    assert "launch_program_in_writable_path" in snapshot.reasons


def test_launch_item_detector() -> None:
    suspicious, reasons = detect_suspicious_launch_item(
        path="/Library/LaunchDaemons/com.bad.plist",
        label="softwareupdate",
        program="/Users/test/.bin/run.sh",
        program_arguments=["/usr/bin/osascript", "LaunchAgents"],
    )
    assert suspicious is True
    assert "launch_program_in_user_space" in reasons
    assert "launch_uses_osascript" in reasons


def test_baseline_comparison() -> None:
    comparison = compare_snapshots(
        previous_ports=[PortSnapshot("python3", 100, "127.0.0.1:8000", 8000, "TCP", "LISTEN")],
        current_ports=[PortSnapshot("python3", 100, "127.0.0.1:8000", 8000, "TCP", "LISTEN"), PortSnapshot("ruby", 101, "127.0.0.1:4444", 4444, "TCP", "LISTEN")],
        previous_users=[UserSnapshot("alice", 501, 20, "/bin/zsh", "/Users/alice", admin=False)],
        current_users=[UserSnapshot("alice", 501, 20, "/bin/zsh", "/Users/alice", admin=True), UserSnapshot("mallory", 502, 20, "/bin/zsh", "/Users/mallory")],
        previous_permissions=[PermissionSnapshot("/Users/test/.ssh", "0700", "ok", "info")],
        current_permissions=[PermissionSnapshot("/Users/test/.ssh", "0755", "SSH directory is too permissive.", "high")],
        previous_history=[],
        current_history=[HistoryIndicator("~/.zsh_history", "zsh", "curl_pipe_sh", 1, "curl ... | sh", "warn")],
        previous_files=[],
        current_files=[FileIssueSnapshot("/tmp/.hidden", "hidden,unsigned", "2026-04-23T00:00:00Z", True, False, True, "unsigned")],
        previous_launch_items={"com.apple.safe.plist"},
        current_launch_items={"com.apple.safe.plist", "com.bad.agent.plist"},
        previous_processes=[],
        current_processes=[ProcessSnapshot(10, 1, "m", "/tmp/.hidden", ".hidden", "unsigned", "untrusted", ["unsigned_process_binary"])],
        previous_launch_snapshots=[],
        current_launch_snapshots=[LaunchItemSnapshot("/Library/LaunchDaemons/com.bad.plist", "bad", "/tmp/run.sh", suspicious=True, reasons=["launch_program_in_writable_path"])],
    )
    assert len(comparison.new_ports) == 1
    assert len(comparison.new_users) == 1
    assert comparison.drift_score > 0
    assert comparison.drift_label in {"moderate drift", "high drift"}
    assert comparison.drift_summary
    assert len(comparison.new_admin_users) == 1
    assert len(comparison.changed_permissions) == 1
    assert len(comparison.new_history_indicators) == 1
    assert len(comparison.new_suspicious_files) == 1
    assert len(comparison.new_launch_items) == 1
    assert len(comparison.new_suspicious_processes) == 1
    assert len(comparison.new_suspicious_launch_items) == 1
