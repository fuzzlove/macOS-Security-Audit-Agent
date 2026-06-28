import subprocess
from pathlib import Path

import pytest

from mac_audit_agent import nmap_wrapper
from mac_audit_agent.nmap_wrapper import (
    DEFAULT_SCAN_PROFILE,
    NMAP_INSTALL_MESSAGE,
    command_for_profile,
    parse_nmap_xml,
    run_nmap_scan,
    validate_target,
)


TCP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="9.9"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


UDP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="udp" portid="5353">
        <state state="open|filtered" reason="no-response"/>
        <service name="zeroconf"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_find_nmap_binary_checks_known_paths_and_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(nmap_wrapper.Path, "is_file", lambda self: False)
    monkeypatch.setattr(nmap_wrapper.os, "access", lambda path, mode: False)
    monkeypatch.setattr(nmap_wrapper.shutil, "which", lambda name: "/custom/bin/nmap")
    assert nmap_wrapper.find_nmap_binary() == "/custom/bin/nmap"


def test_missing_nmap_degrades_gracefully(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(nmap_wrapper, "find_nmap_binary", lambda: None)
    result = run_nmap_scan()
    assert result.fallback_used is True
    assert NMAP_INSTALL_MESSAGE in result.errors


def test_command_args_are_list_based_and_localhost_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(nmap_wrapper.os, "geteuid", lambda: 0)
    command = command_for_profile(DEFAULT_SCAN_PROFILE, "/opt/homebrew/bin/nmap")
    assert isinstance(command, list)
    assert "127.0.0.1" in command
    assert "-oX" in command


def test_subprocess_run_uses_shell_false(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {}

    def fake_run(command, **kwargs):
        calls["command"] = command
        calls["shell"] = kwargs["shell"]
        return subprocess.CompletedProcess(command, 0, TCP_XML, "")

    monkeypatch.setattr(nmap_wrapper, "find_nmap_binary", lambda: "/opt/homebrew/bin/nmap")
    monkeypatch.setattr(nmap_wrapper.subprocess, "run", fake_run)
    result = run_nmap_scan()
    assert calls["shell"] is False
    assert isinstance(calls["command"], list)
    assert result.ports[0].port == 22


def test_non_localhost_requires_advanced_confirmation() -> None:
    with pytest.raises(ValueError):
        validate_target("192.168.1.5")
    assert validate_target("192.168.1.5", advanced_authorized=True) == "192.168.1.5"


def test_non_localhost_command_requires_advanced_confirmation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(nmap_wrapper.os, "geteuid", lambda: 0)
    with pytest.raises(ValueError):
        command_for_profile(DEFAULT_SCAN_PROFILE, "/opt/homebrew/bin/nmap", target="192.168.1.5")
    command = command_for_profile(
        DEFAULT_SCAN_PROFILE,
        "/opt/homebrew/bin/nmap",
        target="192.168.1.5",
        advanced_authorized=True,
    )
    assert "192.168.1.5" in command


def test_xml_parser_parses_tcp_open_port() -> None:
    ports = parse_nmap_xml(TCP_XML, scan_profile="Localhost TCP Quick", command_used_redacted="nmap ...")
    assert ports[0].host == "127.0.0.1"
    assert ports[0].protocol == "tcp"
    assert ports[0].port == 22
    assert ports[0].state == "open"
    assert ports[0].service == "ssh"
    assert ports[0].product == "OpenSSH"


def test_xml_parser_parses_udp_open_filtered_state() -> None:
    ports = parse_nmap_xml(UDP_XML, scan_profile="Localhost UDP Quick", command_used_redacted="sudo nmap ...")
    assert ports[0].protocol == "udp"
    assert ports[0].port == 5353
    assert ports[0].state == "open|filtered"
    assert ports[0].reason == "no-response"


def test_timeout_handled(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs["timeout"], output="<nmaprun>")

    monkeypatch.setattr(nmap_wrapper, "find_nmap_binary", lambda: "/opt/homebrew/bin/nmap")
    monkeypatch.setattr(nmap_wrapper.subprocess, "run", fake_run)
    result = run_nmap_scan(timeout_seconds=1)
    assert result.timed_out is True
    assert result.errors


def test_credits_include_nmap() -> None:
    root = Path(__file__).resolve().parents[2]
    assert "https://nmap.org/" in (root / "README.md").read_text(encoding="utf-8")
    assert "Nmap Project" in (root / "docs" / "ACKNOWLEDGEMENTS.md").read_text(encoding="utf-8")
