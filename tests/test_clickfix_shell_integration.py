from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from mac_audit_agent.clickfix.shell_journal import ShellEventJournalConsumer, ShellJournalError
from mac_audit_agent.clickfix.shell_status import BEGIN, REQUIRED_FILES, shell_guard_status
from mac_audit_agent.monitor import BackgroundMonitorService, MONITOR_ROLE_SYSTEM


def _install_fixture(home: Path) -> Path:
    prefix = home / ".local/lib/msaa-clickfix"
    prefix.mkdir(parents=True)
    manifest = []
    for name in REQUIRED_FILES:
        path = prefix / name
        path.write_text("fixture\n", encoding="utf-8")
        path.chmod(0o700)
        manifest.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {name}")
    (prefix / "MANIFEST.sha256").write_text("\n".join(manifest) + "\n", encoding="ascii")
    (home / ".zshrc").write_text(BEGIN + "\n", encoding="utf-8")
    return prefix


def _event(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema": "msaa.clickfix.event.v1",
        "event_type": "submission_blocked",
        "decision": "block",
        "confidence": "high",
        "timestamp": "2026-07-20T12:00:00Z",
        "command_sha256": "a" * 64,
        "rule_ids": ["network_to_interpreter"],
    }
    value.update(overrides)
    return value


def test_shell_status_reports_adapter_and_detects_manifest_tamper(monkeypatch, tmp_path: Path) -> None:
    home = tmp_path / "user"
    home.mkdir()
    prefix = _install_fixture(home)
    monkeypatch.setattr("mac_audit_agent.clickfix.shell_status.pwd.getpwuid", lambda _uid: type("P", (), {"pw_shell": "/bin/zsh"})())

    status = shell_guard_status(home=home, prefix=prefix)
    assert status["operational"] is True
    assert status["coverage_level"] == "direct_shell_adapter"
    assert status["endpoint_security_required"] is False

    (prefix / "msaa-clickfix-scan").write_text("changed\n", encoding="utf-8")
    status = shell_guard_status(home=home, prefix=prefix)
    assert status["manifest_valid"] is False
    assert status["operational"] is False


def test_proxy_preference_does_not_claim_verified_operational_coverage(monkeypatch, tmp_path: Path) -> None:
    home = tmp_path / "user"
    home.mkdir()
    prefix = _install_fixture(home)
    (home / ".zshrc").unlink()
    preferences = home / "Library/Preferences"
    preferences.mkdir(parents=True)
    import plistlib

    (preferences / "com.msaa.clickfix.plist").write_bytes(plistlib.dumps({"generic_proxy_enabled": True}))
    monkeypatch.setattr("mac_audit_agent.clickfix.shell_status.pwd.getpwuid", lambda _uid: type("P", (), {"pw_shell": "/bin/fish"})())

    status = shell_guard_status(home=home, prefix=prefix)
    assert status["generic_proxy_available"] is True
    assert status["coverage_level"] == "degraded_proxy_available_opt_in_unverified"
    assert status["operational"] is False


def test_shell_journal_is_cursor_based_and_rejects_sensitive_fields(tmp_path: Path) -> None:
    journal = tmp_path / "events.jsonl"
    journal.write_text(json.dumps(_event()) + "\n", encoding="ascii")
    consumer = ShellEventJournalConsumer(journal)
    assert len(consumer.consume()) == 1
    assert consumer.consume() == []

    journal.write_text(json.dumps(_event(command="forbidden")) + "\n", encoding="ascii")
    with pytest.raises(ShellJournalError, match="sensitive_field"):
        ShellEventJournalConsumer(journal).consume()


def test_system_daemon_bridges_only_privacy_safe_shell_metadata(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("MSAA_GUI_HOME", str(tmp_path / "home"))
    service = BackgroundMonitorService(tmp_path / "events.sqlite", mode=MONITOR_ROLE_SYSTEM, record_startup=False)

    class FakeConsumer:
        last_cursor = 42

        def consume(self):
            return [_event(event_type="paste_blocked")]

    service._clickfix_shell_consumer = FakeConsumer()
    events = service._consume_clickfix_shell_events()
    assert len(events) == 1
    assert events[0].event_type == "clickfix_shell_guard_event"
    assert events[0].severity == "high"
    assert "command text was not collected" in events[0].evidence.lower()
    assert "example.invalid" not in events[0].evidence
    assert service.db.get_background_monitor_state("clickfix_shell_journal_cursor") == "42"
    assert service.db.get_background_monitor_state("clickfix_shell_daemon_bridge_status") == "active"
    service.db.close()
