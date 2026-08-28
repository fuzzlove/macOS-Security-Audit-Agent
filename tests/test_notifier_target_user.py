from __future__ import annotations

import os
import pwd
from pathlib import Path
from types import SimpleNamespace

import pytest

from mac_audit_agent.target_desktop_user import TargetDesktopUser, TargetUserError, resolve_target_desktop_user
from mac_audit_agent.user_notifier_installer import USER_NOTIFIER_LABEL, UserNotifierInstaller


def record(home: Path, *, name="desktop", uid=501, gid=20):
    home.mkdir(parents=True, exist_ok=True)
    return SimpleNamespace(pw_name=name, pw_uid=uid, pw_gid=gid, pw_dir=str(home), pw_shell="/bin/zsh")


def configure(monkeypatch, tmp_path, *, console=("desktop", 501), name="desktop", uid=501, gid=20):
    account = record(tmp_path / "home", name=name, uid=uid, gid=gid)
    monkeypatch.setattr(pwd, "getpwnam", lambda value: account if value == name else (_ for _ in ()).throw(KeyError(value)))
    monkeypatch.setattr(pwd, "getpwuid", lambda value: account if value == uid else (_ for _ in ()).throw(KeyError(value)))
    monkeypatch.setattr("mac_audit_agent.target_desktop_user.active_console_user", lambda: console)
    return account


def test_validated_sudo_user_maps_to_gui_domain(monkeypatch, tmp_path):
    account = configure(monkeypatch, tmp_path)
    target = resolve_target_desktop_user(environ={"SUDO_USER": "desktop", "SUDO_UID": "501", "SUDO_GID": "20"})
    assert target.home == Path(account.pw_dir).resolve()
    assert target.gui_domain == "gui/501"
    assert target.uid != 0


def test_sanitized_bootstrap_identity_is_supported(monkeypatch, tmp_path):
    account = configure(monkeypatch, tmp_path)
    env = {"MSAA_GUI_USER": "desktop", "MSAA_GUI_UID": "501", "MSAA_GUI_GID": "20", "MSAA_GUI_HOME": account.pw_dir}
    assert resolve_target_desktop_user(environ=env).username == "desktop"


@pytest.mark.parametrize("env,code", [
    ({"SUDO_USER": "root", "SUDO_UID": "0", "SUDO_GID": "0"}, "NOTIFIER_TARGET_USER_IS_ROOT"),
    ({"SUDO_USER": "desktop", "SUDO_UID": "invalid", "SUDO_GID": "20"}, "NOTIFIER_TARGET_USER_UNRESOLVED"),
])
def test_root_and_invalid_uid_are_rejected(monkeypatch, tmp_path, env, code):
    if env["SUDO_USER"] == "root":
        configure(monkeypatch, tmp_path, console=("root", 0), name="root", uid=0, gid=0)
    else:
        configure(monkeypatch, tmp_path)
    with pytest.raises(TargetUserError) as raised:
        resolve_target_desktop_user(environ=env)
    assert raised.value.code == code


def test_console_user_mismatch_rejected(monkeypatch, tmp_path):
    configure(monkeypatch, tmp_path, console=("other", 502))
    with pytest.raises(TargetUserError) as raised:
        resolve_target_desktop_user(environ={"SUDO_USER": "desktop", "SUDO_UID": "501", "SUDO_GID": "20"})
    assert raised.value.code == "NOTIFIER_CONSOLE_SESSION_UNAVAILABLE"


def test_explicit_home_must_match_directory_service(monkeypatch, tmp_path):
    configure(monkeypatch, tmp_path)
    with pytest.raises(TargetUserError) as raised:
        resolve_target_desktop_user(username="desktop", uid=501, gid=20, home=tmp_path / "wrong")
    assert raised.value.code == "NOTIFIER_TARGET_HOME_INVALID"


class Runner:
    def __init__(self): self.commands=[]
    def __call__(self, command, **kwargs):
        self.commands.append(command)
        if command[1:3] == ["print", f"system/{USER_NOTIFIER_LABEL}"] or command[1:3] == ["print", f"gui/0/{USER_NOTIFIER_LABEL}"]:
            return SimpleNamespace(returncode=0, stdout="state = running\n", stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")


def test_stale_root_cleanup_is_narrow_and_evidenced(monkeypatch, tmp_path):
    target_home = tmp_path / "desktop"; target_home.mkdir()
    target = TargetDesktopUser("desktop", os.getuid(), os.getgid(), target_home, f"gui/{os.getuid()}", True)
    runner = Runner()
    installer = UserNotifierInstaller(home=target_home, target_user=target, runner=runner, python_executable="/usr/bin/python3")
    monkeypatch.setattr(Path, "exists", lambda self: False if str(self).startswith("/var/root/") else self.is_dir() or self.is_file())
    actions = installer.cleanup_stale_root_installation()
    bootouts = [item for item in runner.commands if len(item) > 1 and item[1] == "bootout"]
    assert [item[2] for item in bootouts] == [f"system/{USER_NOTIFIER_LABEL}", f"gui/0/{USER_NOTIFIER_LABEL}"]
    assert all(USER_NOTIFIER_LABEL in item[2] for item in bootouts)
    assert len(actions) == 2


def test_plist_target_never_uses_var_root(tmp_path):
    home = tmp_path / "desktop"; home.mkdir()
    target = TargetDesktopUser("desktop", os.getuid(), os.getgid(), home, f"gui/{os.getuid()}", True)
    installer = UserNotifierInstaller(target_user=target, runner=Runner(), python_executable="/usr/bin/python3")
    assert installer.plist_path == home / "Library/LaunchAgents" / f"{USER_NOTIFIER_LABEL}.plist"
    assert "/var/root" not in str(installer.plist_path)
