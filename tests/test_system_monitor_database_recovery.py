from __future__ import annotations
import json
import sqlite3
from pathlib import Path

import pytest

from mac_audit_agent.database_recovery import immutable_quick_check, quick_check, recover_system_monitor_database


def test_quick_check_reports_healthy_database(tmp_path: Path) -> None:
    path=tmp_path/"healthy.sqlite3"
    connection=sqlite3.connect(path);connection.execute("CREATE TABLE events(id INTEGER PRIMARY KEY, value TEXT)");connection.execute("INSERT INTO events(value) VALUES ('preserved')");connection.commit();connection.close()
    assert quick_check(path)=="ok"
    assert immutable_quick_check(path)=="ok"


def test_recovery_requires_explicit_administrator_authorization(monkeypatch, tmp_path: Path) -> None:
    path=tmp_path/"monitor.sqlite3";sqlite3.connect(path).close()
    monkeypatch.setattr("mac_audit_agent.database_recovery.os.geteuid",lambda:501)
    with pytest.raises(PermissionError,match="administrator"):
        recover_system_monitor_database(source=path,evidence_root=tmp_path/"evidence",manage_launchd=False)


def test_recovery_detaches_corrupt_sidecars_when_main_image_is_healthy(monkeypatch, tmp_path: Path) -> None:
    path=tmp_path/"monitor.sqlite3"
    connection=sqlite3.connect(path);connection.execute("CREATE TABLE events(id INTEGER PRIMARY KEY)");connection.close()
    wal=Path(str(path)+"-wal");wal.write_bytes(b"synthetic-corrupt-wal")
    checks=iter((sqlite3.DatabaseError("malformed WAL"),"ok"))

    def simulated_live_check(_path: Path) -> str:
        result=next(checks)
        if isinstance(result,Exception):raise result
        return result

    monkeypatch.setattr("mac_audit_agent.database_recovery.os.geteuid",lambda:0)
    monkeypatch.setattr("mac_audit_agent.database_recovery.quick_check",simulated_live_check)
    monkeypatch.setattr("mac_audit_agent.database_recovery.immutable_quick_check",lambda _path:"ok")
    receipt=recover_system_monitor_database(source=path,evidence_root=tmp_path/"evidence",manage_launchd=False)

    assert receipt.integrity_check=="ok"
    assert path.exists()
    assert not wal.exists()
    evidence=Path(receipt.evidence_directory)
    assert (evidence/(wal.name+".detached")).read_bytes()==b"synthetic-corrupt-wal"
    assert json.loads((evidence/"recovery-receipt.json").read_text())["recovery_mode"]=="detached_corrupt_sidecars"


def test_recovery_source_uses_separate_file_validation_and_atomic_preservation() -> None:
    source=Path(__file__).parents[1]/"mac_audit_agent/database_recovery.py"
    text=source.read_text(encoding="utf-8")
    assert '".recover"' in text
    assert "quick_check(recovered)" in text
    assert "os.replace(source,quarantined)" in text
    assert 'for suffix in ("-wal", "-shm", "-journal")' in text
    assert "os.replace(sidecar,Path(str(quarantined)+suffix))" in text
    assert "os.replace(recovered,source)" in text
    assert text.index("quick_check(recovered)") < text.index("os.replace(source,quarantined)")
