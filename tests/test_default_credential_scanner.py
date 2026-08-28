from __future__ import annotations

import hashlib
import importlib.util
import shutil
import threading
from pathlib import Path

import pytest

from mac_audit_agent.default_credential_scanner.engine import (
    DefaultCredentialScanner,
    parse_default_account_xml,
)
from mac_audit_agent.default_credential_scanner.export import export_credential_findings
from mac_audit_agent.default_credential_scanner.models import (
    CredentialFinding,
    CredentialScanReport,
)
from mac_audit_agent.default_credential_scanner.resources import FingerprintManager
from mac_audit_agent.default_credential_scanner.storage import (
    DefaultCredentialRepository,
)
from mac_audit_agent.default_credential_scanner.targets import (
    parse_authorized_target,
    parse_authorized_targets,
)
from mac_audit_agent.ui.navigation_registry import navigation_section

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_LUA = ROOT / "tests/fixtures/default_credentials/http-basic-fingerprints.lua"


def _finding(password: str = "s3cret-unique-password") -> CredentialFinding:
    return CredentialFinding.create(
        scan_id="scan-test", target_url="https://appliance.example/", host="appliance.example",
        port=443, scheme="https", product="Example Appliance", category="security", path="/",
        cpe="cpe:/a:example:appliance", username="admin", password=password,
    )


def _report(finding: CredentialFinding) -> CredentialScanReport:
    return CredentialScanReport(
        "scan-test", "2026-08-26T10:00:00+00:00", "2026-08-26T10:00:01+00:00",
        "CHG-1234", "a" * 64, "Nmap test", (), (finding,), (),
    )


def test_target_parser_accepts_only_explicit_http_servers() -> None:
    target = parse_authorized_target("https://[::1]:8443/admin/")
    assert target.scheme == "https"
    assert target.host == "::1"
    assert target.port == 8443
    assert target.base_path == "/admin/"
    assert target.is_ipv6
    assert parse_authorized_targets("example.test\n# note\nexample.test") == (
        parse_authorized_target("example.test"),
    )


@pytest.mark.parametrize("value", (
    "ftp://example.test", "https://admin:password@example.test", "https://example.test/?x=1",
    "https://example.test/#fragment", "https://example.test/a,b", "https://example.test/a=b",
    "http://--script/", "http://bad_host/", "http://-invalid.example/",
))
def test_target_parser_rejects_unsafe_scope(value: str) -> None:
    with pytest.raises(ValueError):
        parse_authorized_target(value)


def test_parser_extracts_nmap_structured_credentials() -> None:
    target = parse_authorized_target("http://127.0.0.1:18080/")
    xml = """<?xml version='1.0'?><nmaprun><host><ports><port><script id='http-default-accounts'>
    <table key='MSAA Test Fixture'><elem key='cpe'>cpe:/a:msaa:test</elem><elem key='path'>/</elem>
    <table key='credentials'><table><elem key='username'>admin</elem><elem key='password'>admin</elem></table></table>
    </table></script></port></ports></host></nmaprun>"""
    findings = parse_default_account_xml(xml, scan_id="scan-1", target=target, category="web")
    assert len(findings) == 1
    assert findings[0].product == "MSAA Test Fixture"
    assert findings[0].username == "admin"
    assert findings[0].password == "admin"


def test_command_is_fixed_argv_and_scoped_to_one_target(tmp_path: Path) -> None:
    fingerprint = tmp_path / "fingerprints.lua"
    fingerprint.write_text("-- fixture", encoding="utf-8")
    scanner = DefaultCredentialScanner(fingerprint, nmap_path="/opt/homebrew/bin/nmap")
    target = parse_authorized_target("http://192.0.2.10:8080/admin/")
    command = scanner._command(target, "web")
    assert command[-1] == "192.0.2.10"
    assert "8080" in command
    assert "-sV" not in command
    assert "+http-default-accounts" in command
    assert all(item not in command for item in ("-sn", "192.0.2.0/24", "--script=*") )
    assert "<validated-local-dataset>" in " ".join(scanner._redact_command(command))


def test_repository_encrypts_password_and_preserves_disposition(tmp_path: Path) -> None:
    password = "s3cret-unique-password-never-plaintext"
    repository = DefaultCredentialRepository(tmp_path / "credentials.sqlite3")
    finding = _finding(password)
    repository.save(_report(finding))
    repository.set_status(finding.finding_id, "remediated")
    saved = repository.findings()
    repository.close()
    assert saved[0].password == password
    assert saved[0].status == "remediated"
    assert password.encode("utf-8") not in (tmp_path / "credentials.sqlite3").read_bytes()
    assert (tmp_path / "credentials.sqlite3").stat().st_mode & 0o077 == 0
    assert (tmp_path / "credentials.vault.key").stat().st_mode & 0o077 == 0


@pytest.mark.parametrize("extension", ("json", "csv", "html", "txt"))
def test_sensitive_export_is_private_and_contains_remediation_credential(tmp_path: Path, extension: str) -> None:
    finding = _finding()
    path = export_credential_findings([finding], tmp_path / f"report.{extension}")
    assert path.stat().st_mode & 0o077 == 0
    assert finding.password in path.read_text(encoding="utf-8")


def test_fingerprint_manager_validates_and_atomically_installs(tmp_path: Path) -> None:
    payload = (
        b'-- This file is part of NNdefaccts\nlocal http = require "http"\n'
        b'table.insert(fingerprints, { login_combos = {}, login_check = function() return false end })\n'
        + b"-" * (51 * 1024)
    )
    manager = FingerprintManager(
        tmp_path,
        fetcher=lambda *args, **kwargs: (payload, "text/plain", {"etag": "fixture"}),
        approved_hashes=frozenset({hashlib.sha256(payload).hexdigest()}),
    )
    status = manager.install_or_update()
    assert status.ready
    assert status.size == len(payload)
    assert manager.path.stat().st_mode & 0o077 == 0


def test_fingerprint_manager_rejects_unreviewed_executable_lua(tmp_path: Path) -> None:
    payload = (
        b'-- This file is part of NNdefaccts\nlocal http = require "http"\n'
        b'table.insert(fingerprints, { login_combos = {}, login_check = function() return false end })\n'
        + b"-" * (51 * 1024)
    )
    manager = FingerprintManager(
        tmp_path,
        fetcher=lambda *args, **kwargs: (payload, "text/plain", {}),
        approved_hashes=frozenset({"0" * 64}),
    )
    with pytest.raises(ValueError, match="MSAA-reviewed"):
        manager.install_or_update()
    assert not manager.path.exists()


def test_navigation_places_scanner_in_network() -> None:
    assert navigation_section("default_credential_scanner") == "Network"


@pytest.mark.skipif(not (shutil.which("nmap") or Path("/opt/homebrew/bin/nmap").is_file()), reason="Nmap unavailable")
def test_loopback_fixture_acceptance_with_real_nmap() -> None:
    module_path = ROOT / "scripts/run_default_credential_test_server.py"
    spec = importlib.util.spec_from_file_location("msaa_default_credential_fixture", module_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        server = module.ThreadingHTTPServer(("127.0.0.1", 0), module.DefaultCredentialFixtureHandler)
    except PermissionError:
        pytest.skip("execution environment prohibits loopback sockets")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        nmap = shutil.which("nmap") or "/opt/homebrew/bin/nmap"
        scanner = DefaultCredentialScanner(FIXTURE_LUA, nmap_path=nmap, timeout_seconds=30)
        report = scanner.scan(
            [parse_authorized_target(f"http://127.0.0.1:{server.server_port}/")],
            authorization_reference="LOCAL-BENIGN-FIXTURE",
            category="web",
        )
        assert not report.errors
        assert len(report.findings) == 1
        assert report.findings[0].username == "admin"
        assert report.findings[0].password == "admin"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
