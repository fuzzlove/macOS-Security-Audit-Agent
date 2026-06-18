from __future__ import annotations

import json
from pathlib import Path

from mac_audit_agent import cli
from mac_audit_agent.cli import main
from mac_audit_agent.storage import AuditDatabase


def test_run_json_subprocess_keeps_stdout_and_stderr_diagnostics(monkeypatch) -> None:
    class FakeResult:
        returncode = 1
        stdout = "pip stdout\n"
        stderr = "pip stderr\n"

    def fake_run(command, **kwargs):
        return FakeResult()

    monkeypatch.setattr(cli.subprocess, "run", fake_run)

    payload = cli._run_json_subprocess(["python", "-m", "pip"], timeout=5)

    assert payload["returncode"] == 1
    assert payload["stdout"] == "pip stdout\n"
    assert payload["stderr"] == "pip stderr\n"
    assert payload["combined_output"] == "pip stdout\npip stderr\n"


def test_cli_release_readiness_outputs_dashboard_json(tmp_path: Path, capsys) -> None:
    exit_code = main(["--db", str(tmp_path / "audit.sqlite"), "--release-readiness", "--no-gui"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    check_names = {item["check"] for item in payload["checks"]}

    assert exit_code == 0
    assert "ReleaseReadinessScore" in payload
    assert payload["status"] in {"ready", "needs work", "blocked"}
    assert "alert pipeline passes synthetic event test" in check_names
    assert "Apple Exposure Assessment works or degrades cleanly" in check_names


def test_cli_verify_event_flow_persists_report(tmp_path: Path, capsys, monkeypatch) -> None:
    monitor_db = tmp_path / "monitor.sqlite"

    class FakeVerification:
        def to_dict(self) -> dict:
            return {
                "generated_at": "2026-06-16T12:00:00+00:00",
                "request_id": "flow-1",
                "stages": [
                    {"check_id": "daemon_wrote_event", "status": "PASS"},
                    {"check_id": "visible_alert_delivery", "status": "WARNING"},
                ],
            }

    class FakeReadiness:
        def __init__(self, db_path: Path) -> None:
            self.db_path = db_path

        def verify_event_flow(self, timeout_seconds: int = 10) -> FakeVerification:
            assert timeout_seconds == 1
            return FakeVerification()

    monkeypatch.setattr(cli, "SystemMonitorReadiness", FakeReadiness)

    exit_code = main(["--db", str(tmp_path / "audit.sqlite"), "--monitor-db", str(monitor_db), "--verify-event-flow", "--event-flow-timeout", "1", "--no-gui"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 0
    assert payload["request_id"] == "flow-1"
    stored = AuditDatabase(monitor_db).get_background_monitor_state("deployment_event_flow_last_report_json", "")
    assert json.loads(stored)["request_id"] == "flow-1"


def test_cli_verify_event_flow_returns_nonzero_on_failed_stage(tmp_path: Path, capsys, monkeypatch) -> None:
    class FakeVerification:
        def to_dict(self) -> dict:
            return {
                "generated_at": "2026-06-16T12:00:00+00:00",
                "request_id": "flow-fail",
                "stages": [{"check_id": "daemon_wrote_event", "status": "FAIL"}],
            }

    class FakeReadiness:
        def __init__(self, db_path: Path) -> None:
            self.db_path = db_path

        def verify_event_flow(self, timeout_seconds: int = 10) -> FakeVerification:
            return FakeVerification()

    monkeypatch.setattr(cli, "SystemMonitorReadiness", FakeReadiness)

    exit_code = main(["--db", str(tmp_path / "audit.sqlite"), "--monitor-db", str(tmp_path / "monitor.sqlite"), "--verify-event-flow", "--no-gui"])
    captured = capsys.readouterr()

    assert exit_code == 2
    assert json.loads(captured.out)["stages"][0]["status"] == "FAIL"


def test_cli_verify_visible_alert_persists_success_report(tmp_path: Path, capsys, monkeypatch) -> None:
    db_path = tmp_path / "audit.sqlite"

    class FakeNotificationManager:
        def __init__(self, db: AuditDatabase) -> None:
            self.db = db

        def evaluate_notification_decision(self, event, *, force: bool = False) -> dict:
            self.db.update_event_alert_trace(
                f"trace-{event.event_id}",
                notification_policy_checked=True,
                notification_policy_result="sent",
                notification_policy_reason="forced",
                alert_required=True,
                alert_suppressed=False,
            )
            return {"decision": "sent", "reason": "forced"}

        def show_visible_security_alert(self, event, reason: str = "", *, force: bool = False) -> bool:
            event.visible_alert_shown = True
            event.visible_alert_id = event.event_id
            self.db.update_event_alert_trace(
                f"trace-{event.event_id}",
                overlay_dispatch_attempted=True,
                overlay_dispatch_result="SUCCESS",
                visible_alert_id=event.event_id,
                displayed_at=event.timestamp,
            )
            return True

    monkeypatch.setattr(cli, "NotificationManager", FakeNotificationManager)

    exit_code = main(["--db", str(db_path), "--verify-visible-alert", "--no-gui"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    stored = AuditDatabase(db_path).get_background_monitor_state("visible_alert_verification_last_report_json", "")

    assert exit_code == 0
    assert payload["visible_alert_delivered"] is True
    assert json.loads(stored)["event_id"] == payload["event_id"]
    assert {stage["check_id"]: stage["status"] for stage in payload["stages"]}["visible_alert_delivery"] == "PASS"


def test_cli_verify_visible_alert_returns_nonzero_on_failed_overlay(tmp_path: Path, capsys, monkeypatch) -> None:
    class FakeNotificationManager:
        def __init__(self, db: AuditDatabase) -> None:
            self.db = db

        def evaluate_notification_decision(self, event, *, force: bool = False) -> dict:
            return {"decision": "sent", "reason": "forced"}

        def show_visible_security_alert(self, event, reason: str = "", *, force: bool = False) -> bool:
            return False

    monkeypatch.setattr(cli, "NotificationManager", FakeNotificationManager)

    exit_code = main(["--db", str(tmp_path / "audit.sqlite"), "--verify-visible-alert", "--no-gui"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 2
    assert {stage["check_id"]: stage["status"] for stage in payload["stages"]}["visible_alert_delivery"] == "FAIL"


def test_cli_verify_visible_alert_rejects_non_mandatory_event_type(tmp_path: Path, capsys) -> None:
    db_path = tmp_path / "audit.sqlite"

    exit_code = main(
        [
            "--db",
            str(db_path),
            "--verify-visible-alert",
            "--visible-alert-event-type",
            "routine_status",
            "--no-gui",
        ]
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    stored = AuditDatabase(db_path).get_background_monitor_state("visible_alert_verification_last_report_json", "")

    assert exit_code == 2
    assert payload["stages"][0]["check_id"] == "mandatory_visible_event_type"
    assert payload["stages"][0]["status"] == "FAIL"
    assert json.loads(stored)["event_type"] == "routine_status"


def test_cli_verify_clean_install_records_python_version_failure(tmp_path: Path, capsys, monkeypatch) -> None:
    db_path = tmp_path / "audit.sqlite"
    wheel = tmp_path / "package.whl"
    wheel.write_text("placeholder", encoding="utf-8")

    def fake_run(command: list[str], *, timeout: int = 60, max_chars: int | None = 4000) -> dict:
        return {
            "command": command,
            "returncode": 0,
            "stdout": json.dumps({"version": "3.9.6", "major": 3, "minor": 9, "micro": 6}),
            "stderr": "",
        }

    monkeypatch.setattr(cli, "_run_json_subprocess", fake_run)

    exit_code = main(
        [
            "--db",
            str(db_path),
            "--verify-clean-install",
            "--clean-install-python",
            "/usr/bin/python3",
            "--clean-install-wheel",
            str(wheel),
            "--no-gui",
        ]
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    stored = AuditDatabase(db_path).get_background_monitor_state("clean_install_last_report_json", "")

    assert exit_code == 2
    assert {stage["check_id"]: stage["status"] for stage in payload["stages"]}["python_version"] == "FAIL"
    assert json.loads(stored)["python"] == "/usr/bin/python3"


def test_cli_verify_clean_install_checks_packaged_assets_with_public_helper(tmp_path: Path, capsys, monkeypatch) -> None:
    db_path = tmp_path / "audit.sqlite"
    wheel = tmp_path / "package.whl"
    wheel.write_text("placeholder", encoding="utf-8")
    calls: list[list[str]] = []

    def fake_run(command: list[str], *, timeout: int = 60, max_chars: int | None = 4000) -> dict:
        calls.append(command)
        if command[:2] == ["/opt/python3.12", "-c"]:
            return {
                "command": command,
                "returncode": 0,
                "stdout": json.dumps({"version": "3.12.0", "major": 3, "minor": 12, "micro": 0}),
                "stderr": "",
            }
        if command[:3] == ["/opt/python3.12", "-m", "venv"]:
            venv_path = Path(command[3])
            (venv_path / "bin").mkdir(parents=True)
            (venv_path / "bin" / "python").write_text("", encoding="utf-8")
            (venv_path / "bin" / "macos-security-audit-agent").write_text("", encoding="utf-8")
            return {"command": command, "returncode": 0, "stdout": "", "stderr": ""}
        if len(command) >= 4 and command[1:4] == ["-m", "pip", "install"]:
            return {"command": command, "returncode": 0, "stdout": "installed", "stderr": ""}
        if command[-1] == "import mac_audit_agent, mac_audit_agent.cli, mac_audit_agent.reliability; print('imports ok')":
            return {"command": command, "returncode": 0, "stdout": "imports ok\n", "stderr": ""}
        if "get_asset_path('logo.png')" in command[-1]:
            return {"command": command, "returncode": 0, "stdout": "True\nTrue\n", "stderr": ""}
        if command[0].endswith("macos-security-audit-agent") and "--help" in command:
            return {"command": command, "returncode": 0, "stdout": "usage", "stderr": ""}
        if command[0].endswith("macos-security-audit-agent") and "--release-readiness" in command:
            return {"command": command, "returncode": 0, "stdout": json.dumps({"ReleaseReadinessScore": 75, "checks": [], "status": "needs work"}), "stderr": ""}
        return {"command": command, "returncode": 1, "stdout": "", "stderr": "unexpected command"}

    monkeypatch.setattr(cli, "_run_json_subprocess", fake_run)

    exit_code = main(
        [
            "--db",
            str(db_path),
            "--verify-clean-install",
            "--clean-install-python",
            "/opt/python3.12",
            "--clean-install-wheel",
            str(wheel),
            "--no-gui",
        ]
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 0
    assert {stage["check_id"]: stage["status"] for stage in payload["stages"]}["resource_check"] == "PASS"
    assert any("from mac_audit_agent.assets import get_asset_path" in command[-1] for command in calls)


def test_cli_verify_clean_install_rejects_malformed_readiness_json(tmp_path: Path, capsys, monkeypatch) -> None:
    db_path = tmp_path / "audit.sqlite"
    wheel = tmp_path / "package.whl"
    wheel.write_text("placeholder", encoding="utf-8")

    def fake_run(command: list[str], *, timeout: int = 60, max_chars: int | None = 4000) -> dict:
        if command[:2] == ["/opt/python3.12", "-c"]:
            return {
                "command": command,
                "returncode": 0,
                "stdout": json.dumps({"version": "3.12.0", "major": 3, "minor": 12, "micro": 0}),
                "stderr": "",
            }
        if command[:3] == ["/opt/python3.12", "-m", "venv"]:
            venv_path = Path(command[3])
            (venv_path / "bin").mkdir(parents=True)
            (venv_path / "bin" / "python").write_text("", encoding="utf-8")
            (venv_path / "bin" / "macos-security-audit-agent").write_text("", encoding="utf-8")
            return {"command": command, "returncode": 0, "stdout": "", "stderr": ""}
        if len(command) >= 4 and command[1:4] == ["-m", "pip", "install"]:
            return {"command": command, "returncode": 0, "stdout": "installed", "stderr": ""}
        if command[-1] == "import mac_audit_agent, mac_audit_agent.cli, mac_audit_agent.reliability; print('imports ok')":
            return {"command": command, "returncode": 0, "stdout": "imports ok\n", "stderr": ""}
        if "get_asset_path('logo.png')" in command[-1]:
            return {"command": command, "returncode": 0, "stdout": "True\nTrue\n", "stderr": ""}
        if command[0].endswith("macos-security-audit-agent") and "--help" in command:
            return {"command": command, "returncode": 0, "stdout": "usage", "stderr": ""}
        if command[0].endswith("macos-security-audit-agent") and "--release-readiness" in command:
            return {"command": command, "returncode": 0, "stdout": json.dumps({"ReleaseReadinessScore": 75}), "stderr": ""}
        return {"command": command, "returncode": 1, "stdout": "", "stderr": "unexpected command"}

    monkeypatch.setattr(cli, "_run_json_subprocess", fake_run)

    exit_code = main(
        [
            "--db",
            str(db_path),
            "--verify-clean-install",
            "--clean-install-python",
            "/opt/python3.12",
            "--clean-install-wheel",
            str(wheel),
            "--no-gui",
        ]
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 2
    assert {stage["check_id"]: stage["status"] for stage in payload["stages"]}["release_readiness_cli"] == "FAIL"
