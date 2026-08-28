from pathlib import Path

from mac_audit_agent.storage import AuditDatabase
from mac_audit_agent.user_notifier_installer import _probe_notifier_source_database


def test_notifier_source_probe_accepts_valid_event_database(tmp_path: Path) -> None:
    path = tmp_path / "events.sqlite3"
    AuditDatabase(path).close()
    assert _probe_notifier_source_database(path) == (True, "ok", "")


def test_notifier_source_probe_rejects_malformed_database_without_repair(tmp_path: Path) -> None:
    path = tmp_path / "events.sqlite3"
    path.write_bytes(b"not a sqlite database")
    readable, integrity, error = _probe_notifier_source_database(path)
    assert readable is False
    assert integrity == "malformed"
    assert "preserve" not in error.lower() or "repair" not in error.lower()
    assert path.read_bytes() == b"not a sqlite database"


def test_notifier_source_probe_reports_missing_database(tmp_path: Path) -> None:
    readable, integrity, error = _probe_notifier_source_database(tmp_path / "missing.sqlite3")
    assert readable is False
    assert integrity == "missing"
    assert "missing" in error.lower()
