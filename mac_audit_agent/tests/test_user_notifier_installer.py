from __future__ import annotations

import plistlib
import stat
from pathlib import Path

from mac_audit_agent.monitor_settings import load_settings, save_settings, settings_diagnostics
from mac_audit_agent.storage import AuditDatabase
from mac_audit_agent.user_notifier_installer import (
    USER_NOTIFIER_LABEL,
    UserNotifierInstaller,
    update_db_notifier_status,
)


class Completed:
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class FakeRunner:
    def __init__(self) -> None:
        self.commands: list[list[str]] = []
        self.loaded = False

    def __call__(self, command, capture_output=True, text=True):
        command = list(command)
        self.commands.append(command)
        if command[:2] == ["/usr/bin/plutil", "-lint"]:
            return Completed(0, "OK", "")
        if command[:2] == ["/bin/launchctl", "bootstrap"]:
            self.loaded = True
            return Completed(0, "", "")
        if command[:2] == ["/bin/launchctl", "bootout"]:
            self.loaded = False
            return Completed(0, "", "")
        if command[:2] == ["/bin/launchctl", "kickstart"]:
            return Completed(0, "", "")
        if command[:2] == ["/bin/launchctl", "print"]:
            if self.loaded:
                return Completed(0, "state = running\npid = 123\n", "")
            return Completed(113, "", "Could not find specified service")
        return Completed(0, "", "")


def test_user_notifier_installer_writes_canonical_plist_and_loads_gui_domain(tmp_path: Path) -> None:
    runner = FakeRunner()
    installer = UserNotifierInstaller(
        db_path=tmp_path / "audit.sqlite",
        home=tmp_path,
        runner=runner,
        python_executable="/usr/bin/python3",
    )

    status = installer.install_user_notifier()
    payload = plistlib.loads(installer.plist_path.read_bytes())

    assert status.install_status == "loaded"
    assert payload["Label"] == USER_NOTIFIER_LABEL
    assert payload["ProgramArguments"] == ["/usr/bin/python3", "-m", "mac_audit_agent.user_notifier", "--run"]
    assert payload["RunAtLoad"] is True
    assert payload["KeepAlive"] is True
    assert payload["StandardOutPath"].endswith("Library/Logs/MacAuditAgent/user_notifier.stdout.log")
    assert payload["StandardErrorPath"].endswith("Library/Logs/MacAuditAgent/user_notifier.stderr.log")
    assert payload["EnvironmentVariables"]["PYTHONPATH"].endswith("Library/Application Support/MacAuditAgent/runtime")
    assert "gui/" in status.launchctl_domain
    assert ["/bin/launchctl", "bootstrap", status.launchctl_domain, str(installer.plist_path)] in runner.commands
    assert stat.S_IMODE(installer.plist_path.stat().st_mode) == 0o644


def test_user_notifier_missing_and_broken_status_are_diagnostic(tmp_path: Path) -> None:
    installer = UserNotifierInstaller(home=tmp_path, runner=FakeRunner(), python_executable="/usr/bin/python3")

    missing = installer.get_user_notifier_status()
    assert missing.install_status == "missing"
    assert "Events are being collected, but the user alert agent is not running." in missing.last_error

    installer.ensure_directories()
    installer.plist_path.write_bytes(plistlib.dumps({"Label": "wrong", "ProgramArguments": []}))
    installer.plist_path.chmod(0o644)
    broken = installer.get_user_notifier_status()
    assert broken.install_status == "broken"
    assert "plist invalid" in broken.last_error
    assert "recommended fix" in broken.last_error


def test_repair_user_notifier_rewrites_broken_plist(tmp_path: Path) -> None:
    runner = FakeRunner()
    installer = UserNotifierInstaller(home=tmp_path, runner=runner, python_executable="/usr/bin/python3")
    installer.ensure_directories()
    installer.plist_path.write_text("not plist", encoding="utf-8")

    status = installer.repair_user_notifier()
    payload = plistlib.loads(installer.plist_path.read_bytes())

    assert status.install_status == "loaded"
    assert payload["Label"] == USER_NOTIFIER_LABEL


def test_settings_require_user_notifier_when_bottom_right_alerts_enabled(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    settings = load_settings(db)

    assert settings.user_notifier.enabled is True
    assert settings.user_notifier.auto_install is True
    assert settings.notification.bottom_right_alerts is True

    save_settings(db, settings)
    diagnostics = settings_diagnostics(db, load_settings(db), runtime_values={"user_notifier_install_status": "missing", "user_notifier_loaded": "0"})

    assert "user_notifier_not_deliverable" in diagnostics["mismatches"]
    assert diagnostics["user_alert_agent"]["deliverable"] is False


def test_loaded_user_notifier_status_updates_diagnostics(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    installer = UserNotifierInstaller(home=tmp_path, runner=FakeRunner(), python_executable="/usr/bin/python3")
    status = installer.install_user_notifier()
    update_db_notifier_status(db, status)

    diagnostics = settings_diagnostics(db, load_settings(db), runtime_values={
        "user_notifier_install_status": db.get_background_monitor_state("user_notifier_install_status", ""),
        "user_notifier_loaded": db.get_background_monitor_state("user_notifier_loaded", ""),
        "user_notifier_running": db.get_background_monitor_state("user_notifier_running", ""),
    })

    assert diagnostics["user_alert_agent"]["deliverable"] is True
