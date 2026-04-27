from __future__ import annotations

import inspect
import time

import pytest

import mac_audit_agent.network_discovery as nd
from mac_audit_agent.models import NetworkHostSnapshot


class FakeCompleted:
    def __init__(self, *, stdout: str = "", stderr: str = "", returncode: int = 0) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def test_subnet_detection_works_for_rfc1918_networks(monkeypatch) -> None:
    def fake_run(argv, capture_output=True, text=True, timeout=None, check=False):
        if argv[0] == "ifconfig":
            return FakeCompleted(
                stdout=(
                    "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n"
                    "\tinet 192.168.1.20 netmask 0xffffff00 broadcast 192.168.1.255\n"
                )
            )
        if argv[0] == "netstat":
            return FakeCompleted(stdout="default            192.168.1.1        UGSc           en0\n")
        return FakeCompleted(stdout="")

    monkeypatch.setattr(nd.subprocess, "run", fake_run)
    scope = nd.detect_network_scope("en0")
    assert scope["subnet"] == "192.168.1.0/24"
    assert scope["scope"] == "private"


def test_public_ip_scan_requires_explicit_confirmation(monkeypatch) -> None:
    monkeypatch.setattr(nd, "detect_network_scope", lambda interface: {"interface": interface, "subnet": "8.8.8.0/30", "gateway": "8.8.8.1", "scope": "public"})
    with pytest.raises(ValueError):
        nd.discover_local_network(interface="en0")


def test_arp_parser_works() -> None:
    rows = nd.parse_arp_table(
        "router (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]\n"
        "? (192.168.1.20) at 11:22:33:44:55:66 on en0 ifscope [ethernet]\n"
    )
    assert rows[0]["ip_address"] == "192.168.1.1"
    assert rows[0]["mac_address"] == "aa:bb:cc:dd:ee:ff"
    assert rows[1]["hostname"] == ""


def test_parse_active_interfaces_detects_up_running_ipv4_interfaces() -> None:
    text = (
        "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384\n"
        "\tinet 127.0.0.1 netmask 0xff000000\n"
        "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n"
        "\tinet 192.168.1.20 netmask 0xffffff00 broadcast 192.168.1.255\n"
        "en5: flags=8822<BROADCAST,SMART,SIMPLEX,MULTICAST> mtu 1500\n"
    )
    assert nd.parse_active_interfaces(text) == ["lo0", "en0"]


def test_reverse_dns_resolves_hostname(monkeypatch) -> None:
    monkeypatch.setattr(nd.socket, "gethostbyaddr", lambda ip: ("device.local", ["alias.local"], [ip]))
    hostname, aliases = nd._lookup_reverse_dns("192.168.1.20")
    assert hostname == "device.local"
    assert aliases == ["alias.local"]


def test_reverse_dns_timeout_does_not_crash(monkeypatch) -> None:
    def slow_lookup(_ip):
        time.sleep(0.5)
        return ("device.local", ["alias.local"], [_ip])

    monkeypatch.setattr(nd.socket, "gethostbyaddr", slow_lookup)
    hostname, aliases = nd._lookup_reverse_dns("192.168.1.20")
    assert hostname == ""
    assert aliases == []


def test_vendor_lookup_returns_expected_vendor() -> None:
    assert nd._vendor_guess("f4:f5:e8:12:34:56") == "Apple"


def test_mdns_parsing_returns_local_name(monkeypatch) -> None:
    monkeypatch.setattr(nd.socket, "getaddrinfo", lambda host, port=None: [(None, None, None, None, None)] if host == "device.local" else (_ for _ in ()).throw(OSError("not found")))
    assert nd._probe_local_name("device") == "device.local"


def test_mdns_service_parser_works() -> None:
    text = (
        "Timestamp  A/R    Flags  if Domain               Service Type         Instance Name\n"
        "12:00:00.000  Add  2 3 Living Room Apple TV _airplay._tcp.\n"
        "12:00:00.001  Add  2 3 printer-room _ssh._tcp.\n"
    )
    service_map = nd._parse_mdns_service_map(text)
    assert "_airplay._tcp" in service_map["living room apple tv"]
    assert "_ssh._tcp" in service_map["printer-room"]


def test_discovered_hosts_normalize_correctly() -> None:
    left = NetworkHostSnapshot(ip_address="192.168.1.20", mac_address="aa:bb:cc:dd:ee:ff", hostname="", vendor_guess="", interface="en0", discovery_methods=["arp"], confidence="low")
    right = NetworkHostSnapshot(ip_address="192.168.1.20", mac_address="", hostname="laptop.local", vendor_guess="", interface="en0", discovery_methods=["ping"], confidence="medium")
    merged = nd._merge_host(left, right)
    assert merged.discovery_methods == ["arp", "ping"]
    assert merged.hostname == "laptop.local"
    assert merged.confidence == "medium"


def test_hosts_unify_by_mac_before_ip() -> None:
    hosts: list[NetworkHostSnapshot] = []
    nd._upsert_host(
        hosts,
        NetworkHostSnapshot(
            ip_address="192.168.1.20",
            mac_address="aa:bb:cc:dd:ee:ff",
            hostname="printer",
            vendor_guess="HP",
            interface="en0",
            discovery_methods=["arp"],
            confidence="medium",
        ),
    )
    nd._upsert_host(
        hosts,
        NetworkHostSnapshot(
            ip_address="192.168.1.21",
            mac_address="aa:bb:cc:dd:ee:ff",
            hostname="printer.local",
            vendor_guess="HP",
            interface="en0",
            discovery_methods=["mdns"],
            confidence="high",
        ),
    )
    assert len(hosts) == 1
    assert hosts[0].ip_address == "192.168.1.20"
    assert hosts[0].hostname == "printer"
    assert hosts[0].discovery_methods == ["arp", "mdns"]


def test_hosts_unify_by_hostname_third() -> None:
    hosts: list[NetworkHostSnapshot] = []
    nd._upsert_host(
        hosts,
        NetworkHostSnapshot(
            ip_address="192.168.1.40",
            mac_address="",
            hostname="living-room.local",
            interface="en0",
            discovery_methods=["mdns"],
            confidence="medium",
        ),
    )
    nd._upsert_host(
        hosts,
        NetworkHostSnapshot(
            ip_address="192.168.1.41",
            mac_address="",
            hostname="living-room.local",
            interface="en0",
            discovery_methods=["ping"],
            confidence="low",
        ),
    )
    assert len(hosts) == 1
    assert hosts[0].discovery_methods == ["mdns", "ping"]


def test_multiple_sources_merge_correctly(monkeypatch) -> None:
    monkeypatch.setattr(nd, "_lookup_reverse_dns", lambda ip: ("appletv", ["alias"]))
    monkeypatch.setattr(nd, "_resolve_arp_entry", lambda ip: {"ip_address": ip, "mac_address": "f4:f5:e8:12:34:56", "hostname": "router", "interface": "en0", "raw": ""})
    monkeypatch.setattr(nd, "_lookup_smb_name", lambda ip: "appletv")
    monkeypatch.setattr(nd, "_probe_local_name", lambda candidate: f"{candidate}.local" if candidate == "appletv" else "")
    host = NetworkHostSnapshot(ip_address="192.168.1.20", mac_address="", hostname="", vendor_guess="", interface="en0", discovery_methods=["ping"], confidence="low", notes="Responded to ping sweep.")
    enriched = nd._enrich_host_identity(host, mdns_catalog=["_airplay._tcp"], dhcp_cache={"192.168.1.20": {"hostname": "appletv", "mac_address": "", "source": "lease"}})
    assert enriched.mac_address == "f4:f5:e8:12:34:56"
    assert enriched.hostname == "appletv.local"
    assert "AirPlay" in enriched.service_names
    assert enriched.device_type == "Apple TV"
    assert enriched.hostname_source == "reverse_dns"
    assert enriched.confidence == "high"


def test_confidence_medium_for_mac_and_vendor_only() -> None:
    confidence = nd._confidence_for_host(
        NetworkHostSnapshot(
            ip_address="192.168.1.55",
            mac_address="f4:f5:e8:12:34:56",
            vendor_guess="Apple",
            interface="en0",
            discovery_methods=["arp"],
            confidence="low",
        )
    )
    assert confidence == "medium"


def test_confidence_scoring_works(monkeypatch) -> None:
    monkeypatch.setattr(nd, "_lookup_reverse_dns", lambda ip: ("device", []))
    monkeypatch.setattr(nd, "_resolve_arp_entry", lambda ip: {"ip_address": ip, "mac_address": "aa:bb:cc:dd:ee:ff", "hostname": "", "interface": "en0", "raw": ""})
    monkeypatch.setattr(nd, "_lookup_smb_name", lambda ip: "")
    monkeypatch.setattr(nd, "_probe_local_name", lambda candidate: f"{candidate}.local")
    host = NetworkHostSnapshot(ip_address="192.168.1.21", mac_address="", hostname="", vendor_guess="", interface="en0", discovery_methods=["ping"], confidence="low")
    enriched = nd._enrich_host_identity(host, mdns_catalog=["_ssh._tcp"], dhcp_cache={})
    assert enriched.confidence == "high"
    assert enriched.mac_source == "arp"


def test_neighbor_table_hosts_are_merged(monkeypatch) -> None:
    def fake_run(argv, capture_output=True, text=True, timeout=None, check=False):
        if argv[0] == "ifconfig":
            return FakeCompleted(stdout="en0: flags=8863<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\tinet 192.168.1.20 netmask 0xffffff00 broadcast 192.168.1.255\n")
        if argv[0] == "netstat":
            return FakeCompleted(stdout="default            192.168.1.1        UGSc           en0\n")
        if argv[0] == "arp" and argv[1:] == ["-a"]:
            return FakeCompleted(stdout="router (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]\n")
        if argv[0] == "arp" and argv[1:] == ["-anl"]:
            return FakeCompleted(stdout="printer (192.168.1.40) at 11:22:33:44:55:66 on en0 ifscope [ethernet]\n")
        return FakeCompleted(stdout="")

    monkeypatch.setattr(nd.subprocess, "run", fake_run)
    result, findings, payload = nd.discover_local_network(interface="en0", scan_profile="quick")
    assert any(item["ip_address"] == "192.168.1.40" for item in payload["hosts"])


def test_baseline_detects_new_host() -> None:
    previous = [NetworkHostSnapshot(ip_address="192.168.1.10", mac_address="aa:bb:cc:dd:ee:01", hostname="old", vendor_guess="", interface="en0")]
    current = [NetworkHostSnapshot(ip_address="192.168.1.10", mac_address="aa:bb:cc:dd:ee:01", hostname="old", vendor_guess="", interface="en0"), NetworkHostSnapshot(ip_address="192.168.1.11", mac_address="aa:bb:cc:dd:ee:02", hostname="new", vendor_guess="", interface="en0")]
    comparison = nd._compare_hosts(previous, current, "192.168.1.1", "aa:bb:cc:dd:ee:ff", "192.168.1.1", "aa:bb:cc:dd:ee:ff", "192.168.1.0/24", "192.168.1.0/24")
    assert comparison.new_devices
    assert comparison.new_devices[0]["ip_address"] == "192.168.1.11"


def test_baseline_detects_changed_gateway_mac() -> None:
    comparison = nd._compare_hosts([], [], "192.168.1.1", "aa:bb:cc:dd:ee:ff", "192.168.1.1", "11:22:33:44:55:66", "192.168.1.0/24", "192.168.1.0/24")
    assert comparison.gateway_changed
    assert comparison.gateway_changed[0]["previous_gateway_mac"] == "11:22:33:44:55:66"
    assert comparison.gateway_changed[0]["current_gateway_mac"] == "aa:bb:cc:dd:ee:ff"


def test_unknown_vendor_is_review_needed_not_malicious() -> None:
    host = NetworkHostSnapshot(
        ip_address="192.168.1.50",
        mac_address="aa:bb:cc:dd:ee:ff",
        hostname="",
        vendor_guess="",
        interface="en0",
        discovery_methods=["arp"],
        confidence="low",
    )
    flagged = nd._mark_review_needed_hosts([host], nd.NetworkDiscoveryComparison(), gateway_ip="192.168.1.1", gateway_mac="")
    assert flagged[0].review_needed is True
    assert "unknown MAC vendor" in flagged[0].review_flags


def test_gateway_mac_change_marks_gateway_review_needed() -> None:
    host = NetworkHostSnapshot(
        ip_address="192.168.1.1",
        mac_address="aa:bb:cc:dd:ee:ff",
        hostname="router.local",
        vendor_guess="Cisco",
        vendor="Cisco",
        interface="en0",
        discovery_methods=["arp"],
        confidence="high",
    )
    comparison = nd.NetworkDiscoveryComparison(
        gateway_changed=[
            {
                "previous_gateway": "192.168.1.1",
                "current_gateway": "192.168.1.1",
                "previous_gateway_mac": "11:22:33:44:55:66",
                "current_gateway_mac": "aa:bb:cc:dd:ee:ff",
            }
        ]
    )
    flagged = nd._mark_review_needed_hosts([host], comparison, gateway_ip="192.168.1.1", gateway_mac="aa:bb:cc:dd:ee:ff")
    assert flagged[0].review_needed is True
    assert "gateway MAC changed" in flagged[0].review_flags


def test_ping_sweep_is_rate_limited(monkeypatch) -> None:
    sleep_calls: list[float] = []

    def fake_sleep(seconds):
        sleep_calls.append(seconds)

    def fake_run(argv, capture_output=True, text=True, timeout=None, check=False):
        if argv[0] == "ifconfig":
            return FakeCompleted(stdout="en0: flags=8863<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\tinet 192.168.1.20 netmask 0xfffffffc broadcast 192.168.1.23\n")
        if argv[0] == "netstat":
            return FakeCompleted(stdout="default            192.168.1.1        UGSc           en0\n")
        if argv[0] == "arp":
            return FakeCompleted(stdout="router (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]\n")
        if argv[0] == "ping":
            return FakeCompleted(stdout=f"64 bytes from {argv[-1]}: icmp_seq=0 ttl=64 time=0.5 ms\n", returncode=0)
        return FakeCompleted(stdout="")

    monkeypatch.setattr(nd.time, "sleep", fake_sleep)
    monkeypatch.setattr(nd.subprocess, "run", fake_run)
    monkeypatch.setattr(nd.socket, "gethostbyaddr", lambda ip: (f"host-{ip.split('.')[-1]}", [], [ip]))
    result, findings, payload = nd.discover_local_network(interface="en0", previous_hosts=[], previous_gateway="192.168.1.1", previous_gateway_mac="11:22:33:44:55:66", previous_subnet="192.168.1.0/24")
    assert payload["host_count"] == 2
    assert sleep_calls
    assert len(sleep_calls) >= 2


def test_quick_scan_uses_arp_only(monkeypatch) -> None:
    ping_calls: list[list[str]] = []

    def fake_run(argv, capture_output=True, text=True, timeout=None, check=False):
        if argv[0] == "ifconfig":
            return FakeCompleted(stdout="en0: flags=8863<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\tinet 192.168.1.20 netmask 0xffffff00 broadcast 192.168.1.255\n")
        if argv[0] == "netstat":
            return FakeCompleted(stdout="default            192.168.1.1        UGSc           en0\n")
        if argv[0] == "arp":
            return FakeCompleted(stdout="router (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]\nprinter (192.168.1.40) at 11:22:33:44:55:66 on en0 ifscope [ethernet]\n")
        if argv[0] == "ping":
            ping_calls.append(argv)
            return FakeCompleted(returncode=0)
        return FakeCompleted(stdout="")

    monkeypatch.setattr(nd.subprocess, "run", fake_run)
    result, findings, payload = nd.discover_local_network(interface="en0", scan_profile="quick")
    assert not ping_calls
    assert payload["scan_profile"] == "quick"
    assert len(payload["hosts"]) == 2


def test_network_discovery_cancellation_stops_scan(monkeypatch) -> None:
    def fake_run(argv, capture_output=True, text=True, timeout=None, check=False):
        if argv[0] == "ifconfig":
            return FakeCompleted(stdout="en0: flags=8863<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\tinet 192.168.1.20 netmask 0xffffff00 broadcast 192.168.1.255\n")
        if argv[0] == "netstat":
            return FakeCompleted(stdout="default            192.168.1.1        UGSc           en0\n")
        if argv[0] == "arp":
            return FakeCompleted(stdout="")
        return FakeCompleted(stdout="")

    progress_events: list[dict[str, object]] = []

    def cancel_after_arp() -> bool:
        return any(event.get("stage") == "passive" and int(event.get("completed", 0)) >= 1 for event in progress_events)

    monkeypatch.setattr(nd.subprocess, "run", fake_run)
    with pytest.raises(RuntimeError, match="cancelled"):
        nd.discover_local_network(
            interface="en0",
            scan_profile="standard",
            progress_callback=progress_events.append,
            cancel_check=cancel_after_arp,
        )


def test_no_exploit_or_credential_commands_exist() -> None:
    source = inspect.getsource(nd)
    for blocked in ["sshpass", "hydra", "metasploit", "crackmapexec", "password=", "sudo "]:
        assert blocked not in source.lower()
