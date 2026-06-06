from __future__ import annotations

from pathlib import Path

from mac_audit_agent.source_integrity import record_source_integrity_baseline, verify_source_integrity
from mac_audit_agent.storage import AuditDatabase


def test_source_integrity_detects_python_file_tampering(tmp_path: Path) -> None:
    root = tmp_path / "project"
    package = root / "mac_audit_agent"
    package.mkdir(parents=True)
    target = package / "module.py"
    target.write_text("VALUE = 1\n", encoding="utf-8")
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")

    baseline = record_source_integrity_baseline(db, root=root)
    assert baseline["file_count"] == 1

    target.write_text("VALUE = 2\n", encoding="utf-8")
    result = verify_source_integrity(db, root=root, initialize=False)

    assert result["tamper_detected"] is True
    assert result["changed_files"] == ["mac_audit_agent/module.py"]


def test_source_integrity_detects_added_python_file(tmp_path: Path) -> None:
    root = tmp_path / "project"
    package = root / "mac_audit_agent"
    package.mkdir(parents=True)
    (package / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    record_source_integrity_baseline(db, root=root)

    (package / "new_module.py").write_text("VALUE = 2\n", encoding="utf-8")
    result = verify_source_integrity(db, root=root, initialize=False)

    assert result["tamper_detected"] is True
    assert result["added_files"] == ["mac_audit_agent/new_module.py"]
