from __future__ import annotations

import subprocess

from mac_audit_agent.network_activity_monitor import NetworkActivityMonitor


LSOF = """COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
curl 100 alice 3u IPv4 0x0 0t0 TCP 192.168.1.10:50000->203.0.113.10:443 (ESTABLISHED)
"""
LISTEN = """COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
python 200 alice 4u IPv6 0x0 0t0 TCP [::1]:8080 (LISTEN)
"""


def runner(command):
    if command[:3] == ["/usr/sbin/lsof", "-nP", "-iTCP"] and "-sTCP:LISTEN" not in command:
        return subprocess.CompletedProcess(command, 0, LSOF, "")
    if command[:3] == ["/usr/sbin/lsof", "-nP", "-iTCP"] and "-sTCP:LISTEN" in command:
        return subprocess.CompletedProcess(command, 0, LISTEN, "")
    if command[:3] == ["/bin/ps", "-p", "100"]:
        return subprocess.CompletedProcess(command, 0, "/usr/bin/curl\n", "")
    if command[:3] == ["/bin/ps", "-p", "200"]:
        return subprocess.CompletedProcess(command, 0, "/Users/alice/project/.venv/bin/python\n", "")
    return subprocess.CompletedProcess(command, 1, "", "unavailable in fixture")


def test_process_grouped_network_activity_inventory():
    snapshot = NetworkActivityMonitor(runner).collect()
    curl = next(group for group in snapshot.groups if group.pid == 100)
    python = next(group for group in snapshot.groups if group.pid == 200)
    assert curl.process_path == "/usr/bin/curl"
    assert curl.connections[0].remote_address == "203.0.113.10"
    assert python.listeners[0].port == "8080"
    assert snapshot.connection_count == 1
    assert snapshot.listener_count == 1
