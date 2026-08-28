from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from mac_audit_agent.attack_simulation import AttackValidationEngine, ValidationError, ValidationStore
from mac_audit_agent.emergency_response import AuthorizationContext
from mac_audit_agent.storage import AuditDatabase


def auth(admin=True):
    return AuthorizationContext("validator", "local_admin_auth", True, admin, (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat())


def test_full_validation_is_safe_isolated_and_reportable(tmp_path: Path) -> None:
    production = AuditDatabase(tmp_path / "production.sqlite3")
    store = ValidationStore(tmp_path / "validation.sqlite3")
    engine = AttackValidationEngine(store, tmp_path / "fixtures")
    report = engine.run_all(auth())
    assert report["simulation_mode"] is True
    assert report["tests"] == 3 and report["failed"] == 0
    assert all(row["simulation_mode"] and row["cleanup_status"] == "complete" for row in report["results"])
    assert production.recent_background_monitor_events(limit=10) == []
    assert not list((tmp_path / "fixtures").iterdir())
    assert engine.export_json(report["simulation_id"], tmp_path / "report.json").is_file()
    assert "SIMULATION MODE: TRUE" in engine.export_html(report["simulation_id"], tmp_path / "report.html").read_text()


def test_unauthorized_run_is_blocked_and_separately_audited(tmp_path: Path) -> None:
    store = ValidationStore(tmp_path / "validation.sqlite3")
    engine = AttackValidationEngine(store, tmp_path / "fixtures")
    with pytest.raises(ValidationError, match="administrator authorization"):
        engine.run_all(auth(False))
    row = store.connection.execute("SELECT * FROM validation_audit").fetchone()
    assert row["action"] == "validation_start" and row["result"] == "blocked"


def test_unknown_test_fails_before_fixture_creation(tmp_path: Path) -> None:
    engine = AttackValidationEngine(ValidationStore(tmp_path / "validation.sqlite3"), tmp_path / "fixtures")
    with pytest.raises(ValidationError, match="Unknown validation"):
        engine.run(["not.registered"], auth())
    assert not (tmp_path / "fixtures").exists()
