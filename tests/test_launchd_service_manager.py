from __future__ import annotations

import os
import plistlib
import pwd
from pathlib import Path
from types import SimpleNamespace

import pytest

from mac_audit_agent.platform.macos.launchd_service import LaunchdServiceManager, MONITOR_LABEL


class Runner:
    def __init__(self, gui=None, system=None, bootout=0):
        self.gui = list(gui or [False]); self.system = list(system or [False]); self.bootout = bootout; self.commands=[]
    def __call__(self, command, **kwargs):
        self.commands.append(command)
        if command[:2] == ["/bin/launchctl", "print"]:
            states = self.system if command[2].startswith("system/") else self.gui
            state = states.pop(0) if len(states) > 1 else states[0]
            return SimpleNamespace(returncode=0 if state else 113, stdout="state = running\n" if state else "", stderr="Could not find service" if not state else "")
        if command[:2] == ["/bin/launchctl", "bootout"]:
            return SimpleNamespace(returncode=self.bootout, stdout="", stderr="Operation not permitted" if self.bootout else "")
        return SimpleNamespace(returncode=0, stdout="OK", stderr="")


def manager(tmp_path, runner):
    return LaunchdServiceManager(runner=runner, console_resolver=lambda: (pwd.getpwuid(os.getuid()).pw_name, os.getuid()), sleep=lambda _: None, user_home=tmp_path)


def plist(path: Path, *, label=MONITOR_LABEL, mode=0o644, working=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(plistlib.dumps({"Label":label,"ProgramArguments":["/bin/echo","ok"],"WorkingDirectory":str(working or path.parent),"RunAtLoad":True,"KeepAlive":True}))
    path.chmod(mode)
    return path


def test_gui_domain_detected(tmp_path):
    report = manager(tmp_path, Runner(gui=[True], system=[False])).detect()
    assert report["state"] == "LOADED_GUI" and report["expected_domain"] == f"gui/{os.getuid()}"


def test_system_only_is_wrong_domain(tmp_path):
    report = manager(tmp_path, Runner(gui=[False], system=[True])).detect()
    assert report["error_code"] == "LAUNCHD001_WRONG_DOMAIN"


def test_duplicate_loaded_is_critical(tmp_path):
    report = manager(tmp_path, Runner(gui=[True], system=[True])).detect()
    assert report["error_code"] == "LAUNCHD004_DUPLICATE_INSTALLATION"


def test_already_unloaded_is_idempotent(tmp_path):
    result = manager(tmp_path, Runner()).stop()
    assert result.success and not result.changed and result.state == "ALREADY_UNLOADED"


def test_gui_bootout_uses_gui_target_and_verifies(tmp_path):
    runner = Runner(gui=[True, False], system=[False, False])
    result = manager(tmp_path, runner).stop()
    assert result.success and result.changed
    assert ["/bin/launchctl", "bootout", f"gui/{os.getuid()}/{MONITOR_LABEL}"] in runner.commands


def test_nonzero_bootout_is_success_when_probe_shows_absent(tmp_path):
    result = manager(tmp_path, Runner(gui=[True, False], system=[False, False], bootout=1)).stop()
    assert result.success and result.state == "UNLOADED"


def test_successful_bootout_that_remains_loaded_fails(tmp_path):
    result = manager(tmp_path, Runner(gui=[True, True, True], system=[False, False, False])).stop(verify_attempts=2)
    assert not result.success and result.error_code == "LAUNCHD009_BOOTOUT_VERIFICATION_FAILED"


def test_true_daemon_requires_privileged_workflow(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 501)
    result = manager(tmp_path, Runner(gui=[False], system=[True])).stop()
    assert result.error_code == "LAUNCHD007_PRIVILEGED_HELPER_REQUIRED"


def test_no_console_user(tmp_path):
    report = LaunchdServiceManager(runner=Runner(), console_resolver=lambda: None, user_home=tmp_path).detect()
    assert report["error_code"] == "LAUNCHD006_INVALID_CONSOLE_USER"


def test_invalid_label_cannot_inject():
    with pytest.raises(ValueError): LaunchdServiceManager("x; touch /tmp/bad")


def test_plist_validation_rejects_label_and_permissions(tmp_path):
    runner = Runner(); service = manager(tmp_path, runner)
    path = plist(tmp_path/"Library/LaunchAgents"/f"{MONITOR_LABEL}.plist", label="wrong", mode=0o664, working=tmp_path)
    report = service.validate_plist(path, os.getuid(), tmp_path)
    assert not report["valid"] and "label mismatch" in report["errors"] and "unsafe permissions" in report["errors"]


def test_paths_with_spaces_remain_single_argument(tmp_path, monkeypatch):
    runner = Runner(gui=[False, True], system=[False, False]); service=manager(tmp_path,runner)
    path=plist(tmp_path/"Library/LaunchAgents"/f"{MONITOR_LABEL}.plist",working=tmp_path)
    monkeypatch.setattr(service, "detected_plists", lambda home: [path])
    result=service.start_user_agent(path)
    assert result.success
    bootstrap=next(command for command in runner.commands if command[1]=="bootstrap")
    assert bootstrap[-1] == str(path) and len(bootstrap)==4
