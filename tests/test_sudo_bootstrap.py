from __future__ import annotations

import json
import os
import pwd
import stat
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from mac_audit_agent.sudo_bootstrap.environment import forbidden_environment_names, sanitized_user_environment
from mac_audit_agent.sudo_bootstrap.identity import IdentityError, InvokingUser, InvocationMode, resolve_invocation
from mac_audit_agent.sudo_bootstrap.result import BootstrapResult, consume_handoff
from mac_audit_agent.sudo_bootstrap.coordinator import run_root_bootstrap
from mac_audit_agent.protection.installer import ActiveProtectionInstallResult, _disable_conflicting_user_monitor
from mac_audit_agent.target_desktop_user import TargetDesktopUser


def account(tmp_path: Path, uid: int = 501, name: str = "tester", gid: int = 20):
    tmp_path.mkdir(exist_ok=True)
    return SimpleNamespace(pw_name=name, pw_uid=uid, pw_gid=gid, pw_dir=str(tmp_path), pw_shell="/bin/zsh")


def test_sudo_identity_is_cross_checked(monkeypatch, tmp_path):
    record = account(tmp_path)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr("mac_audit_agent.sudo_bootstrap.identity.active_console_user", lambda: ("tester", 501))
    monkeypatch.setattr(pwd, "getpwuid", lambda uid: record)
    mode, user = resolve_invocation(headless=False, environ={"SUDO_UID": "501", "SUDO_GID": "20", "SUDO_USER": "tester"})
    assert mode is InvocationMode.SUDO_BOOTSTRAP_AND_GUI
    assert user and user.home_directory == tmp_path.resolve()


@pytest.mark.parametrize("env", [
    {"SUDO_UID": "0", "SUDO_GID": "20", "SUDO_USER": "root"},
    {"SUDO_UID": "abc", "SUDO_GID": "20", "SUDO_USER": "tester"},
    {"SUDO_UID": "501", "SUDO_GID": "20", "SUDO_USER": "other"},
])
def test_invalid_sudo_identity_rejected(monkeypatch, tmp_path, env):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr("mac_audit_agent.sudo_bootstrap.identity.active_console_user", lambda: ("tester", 501))
    monkeypatch.setattr(pwd, "getpwuid", lambda uid: account(tmp_path))
    with pytest.raises(IdentityError):
        resolve_invocation(headless=False, environ=env)


def test_direct_root_gui_is_rejected(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr("mac_audit_agent.sudo_bootstrap.identity.active_console_user", lambda: None)
    with pytest.raises(IdentityError, match="no validated"):
        resolve_invocation(headless=False, environ={})


def test_environment_is_allowlisted(tmp_path):
    user = InvokingUser("tester", 501, 20, tmp_path, "/bin/zsh", True, "sudo")
    source = {"LANG": "en_US.UTF-8", "PYTHONPATH": "/evil", "DYLD_INSERT_LIBRARIES": "/evil.dylib", "QT_PLUGIN_PATH": "/evil"}
    env = sanitized_user_environment(user, source=source)
    assert env["HOME"] == str(tmp_path)
    assert "PYTHONPATH" not in env and not any(key.startswith("DYLD_") for key in env)
    assert set(forbidden_environment_names(source)) == {"DYLD_INSERT_LIBRARIES", "PYTHONPATH", "QT_PLUGIN_PATH"}


def test_handoff_owner_mode_age_and_single_consumption(tmp_path):
    result = BootstrapResult(invoking_user={"uid": os.getuid()})
    path = result.write_handoff(tmp_path / "handoff", os.getuid(), os.getgid())
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    payload = consume_handoff(path, os.getuid())
    assert payload["bootstrap_id"] == result.bootstrap_id and not path.exists()


def test_handoff_rejects_expired_file(tmp_path):
    result = BootstrapResult(created_at_unix=int(time.time()) - 1000)
    path = result.write_handoff(tmp_path / "handoff", os.getuid(), os.getgid())
    with pytest.raises(ValueError, match="expired"):
        consume_handoff(path, os.getuid())


def test_user_writable_source_is_not_installed_as_root(monkeypatch, tmp_path):
    user = InvokingUser("tester", 501, 20, tmp_path, "/bin/zsh", True, "sudo")
    monkeypatch.setattr("mac_audit_agent.sudo_bootstrap.coordinator._source_is_user_writable", lambda root: True)
    result = run_root_bootstrap(user, operation="repair", developer_mode=False, allow_unsigned_development_runtime=False)
    assert result.overall_result == "BOOTSTRAP_PARTIAL"
    assert result.errors[0]["code"] == "BOOTSTRAP_UNSAFE_SOURCE_RUNTIME"
    assert result.safe_to_continue_gui is True


def test_launcher_imports_no_qt_for_bootstrap_source():
    source = Path("launcher.py").read_text(encoding="utf-8")
    route = source.index("sudo_result = _sudo_bootstrap_route")
    qt_import = source.index("from mac_audit_agent.runtime.gui_preflight", route)
    app_import = source.index("from mac_audit_agent.app import main")
    assert route < qt_import < app_import
    assert "import PySide6" not in source
    assert "from PySide6" not in source


def test_protected_install_disables_verified_same_label_user_monitor(monkeypatch, tmp_path):
    home = tmp_path / "home"
    launch_agents = home / "Library" / "LaunchAgents"
    launch_agents.mkdir(parents=True)
    conflict = launch_agents / "com.mac-audit-agent.monitor.plist"
    conflict.write_bytes(__import__("plistlib").dumps({"Label": "com.mac-audit-agent.monitor", "ProgramArguments": ["python3"]}))
    monkeypatch.setattr("mac_audit_agent.protection.installer.subprocess.run", lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="", stderr=""))
    target = TargetDesktopUser("tester", 501, 20, home, "gui/501", True)
    result = ActiveProtectionInstallResult()

    _disable_conflicting_user_monitor(target, result)

    assert not conflict.exists()
    assert len(result.backups_created) == 1
    assert Path(result.backups_created[0]).exists()
    assert "gui/501" in result.launchctl_commands[0]
