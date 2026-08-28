from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from mac_audit_agent.anti_ransomware.cli import main
from mac_audit_agent.anti_ransomware.installation import inspect_install_offer, open_verified_installer


def result(returncode: int, text: str = "") -> SimpleNamespace:
    return SimpleNamespace(returncode=returncode, stdout=text, stderr="")


def test_missing_package_offers_safe_release_engineer_path(tmp_path: Path) -> None:
    offer = inspect_install_offer(tmp_path / "missing.pkg", root=tmp_path)
    assert offer.status == "package_required"
    assert not offer.ready_to_open_installer
    assert not offer.automatic_install_performed
    assert offer.administrator_approval_required
    assert "signed_install_package_missing" in offer.blocked_by
    assert "release engineer" in offer.next_action.lower()


def test_unsigned_or_unnotarized_package_is_never_opened(tmp_path: Path, monkeypatch) -> None:
    package = tmp_path / "MSAAActiveContainment.pkg"
    package.write_bytes(b"not a signed package")
    opened: list[list[str]] = []
    monkeypatch.setattr("mac_audit_agent.anti_ransomware.installation.sys.platform", "darwin")
    offer = open_verified_installer(
        package,
        runner=lambda argv: result(1, "rejected"),
        opener=lambda argv: opened.append(argv) or result(0),
    )
    assert offer.status == "package_rejected"
    assert not opened
    assert not offer.package_signature_valid


def test_verified_package_opens_only_apple_installer_flow(tmp_path: Path, monkeypatch) -> None:
    package = tmp_path / "MSAAActiveContainment.pkg"
    package.write_bytes(b"fixture package")
    opened: list[list[str]] = []
    monkeypatch.setattr("mac_audit_agent.anti_ransomware.installation.sys.platform", "darwin")
    monkeypatch.setenv("MSAA_TEAM_ID", "ABCDEF1234")

    def runner(argv: list[str]):
        if argv[0] == "/usr/sbin/pkgutil":
            return result(0, "Status: signed by a certificate trusted by macOS\nDeveloper ID Installer: Example (ABCDEF1234)")
        return result(0, "accepted")

    offer = open_verified_installer(
        package,
        runner=runner,
        opener=lambda argv: opened.append(argv) or result(0),
    )
    assert offer.status == "installer_opened"
    assert opened == [["/usr/bin/open", str(package)]]
    assert not offer.automatic_install_performed
    assert "not complete" in offer.message.lower()


def test_other_team_installer_is_rejected(tmp_path: Path, monkeypatch) -> None:
    package = tmp_path / "MSAAActiveContainment.pkg"
    package.write_bytes(b"fixture package")
    monkeypatch.setattr("mac_audit_agent.anti_ransomware.installation.sys.platform", "darwin")
    monkeypatch.setenv("MSAA_TEAM_ID", "ABCDEF1234")
    offer = inspect_install_offer(
        package,
        runner=lambda argv: result(0, "Developer ID Installer: Other Team (ZZZZZZ9999)"),
    )
    assert not offer.package_signature_valid
    assert not offer.ready_to_open_installer


def test_install_plan_cli_is_json_only_and_non_destructive(tmp_path: Path, capsys) -> None:
    code = main(["install", "--plan", "--package", str(tmp_path / "missing.pkg"), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 1
    assert payload["status"] == "package_required"
    assert payload["automatic_install_performed"] is False
    assert payload["administrator_approval_required"] is True
