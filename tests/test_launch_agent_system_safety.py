from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from mac_audit_agent.launch_agent import (
    LaunchAgentManager,
    SYSTEM_SERVICE_PERMISSION_ERROR,
    is_system_service_safe_executable,
)


def test_system_service_runtime_rejects_project_virtual_environment(tmp_path: Path) -> None:
    executable = tmp_path / ".venv" / "bin" / "python3"
    executable.parent.mkdir(parents=True)
    executable.write_text("", encoding="utf-8")

    assert not is_system_service_safe_executable(executable)


def test_system_service_runtime_rejects_user_home_runtime() -> None:
    assert not is_system_service_safe_executable("/Users/example/bin/python3")


def test_unprivileged_system_stop_never_calls_launchctl(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def forbidden_run(command: list[str], **_kwargs: object):
        calls.append(command)
        raise AssertionError("launchctl must not be invoked")

    monkeypatch.setattr(os, "geteuid", lambda: 501)
    monkeypatch.setattr(subprocess, "run", forbidden_run)
    manager = LaunchAgentManager(Path("/tmp/msaa-test.sqlite3"), scope="system")
    # Preserve the production-runner identity used by the authorization guard.
    manager.runner = subprocess.run

    with pytest.raises(PermissionError, match="MON006_ADMIN_AUTHORIZATION_REQUIRED") as error:
        manager.stop()

    assert str(error.value) == SYSTEM_SERVICE_PERMISSION_ERROR
    assert calls == []
