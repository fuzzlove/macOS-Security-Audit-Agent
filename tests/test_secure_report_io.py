from __future__ import annotations

import json
import os
import stat
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest

import mac_audit_agent.secure_io as secure_io
from mac_audit_agent.secure_io import migrate_legacy_json, probe_report_directory, secure_atomic_write_json, validate_secure_directory


def test_missing_directory_and_json_are_created_restrictively(tmp_path: Path) -> None:
    directory = tmp_path / "private/reports"; target = directory / "ai_summary.json"
    result = secure_atomic_write_json({"unicode": "安全 🛡️"}, target, base_directory=directory)
    assert result.succeeded and json.loads(target.read_text())["unicode"] == "安全 🛡️"
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert not list(directory.glob("*.tmp")) and not list(directory.glob(".*.tmp"))


def test_existing_secure_directory_is_accepted(tmp_path: Path) -> None:
    directory = tmp_path / "reports"; directory.mkdir(mode=0o700)
    assert validate_secure_directory(directory, create=False).succeeded


def test_symlink_directory_and_target_are_rejected(tmp_path: Path) -> None:
    real = tmp_path / "real"; real.mkdir(mode=0o700)
    linked = tmp_path / "linked"; linked.symlink_to(real, target_is_directory=True)
    result = secure_atomic_write_json({}, linked / "ai_summary.json", base_directory=linked)
    assert result.error_code == "REPORT_DIRECTORY_IS_SYMLINK"
    target = real / "ai_summary.json"; other = tmp_path / "other.json"; other.write_text("{}") ; target.symlink_to(other)
    result = secure_atomic_write_json({}, target, base_directory=real)
    assert result.error_code == "REPORT_TARGET_IS_SYMLINK"


def test_non_directory_foreign_owner_and_read_only_are_structured_failures(tmp_path: Path) -> None:
    regular = tmp_path / "not-directory"; regular.write_text("x")
    assert secure_atomic_write_json({}, regular / "x.json", base_directory=regular).error_code == "REPORT_PATH_INVALID"
    directory = tmp_path / "foreign"; directory.mkdir(mode=0o700)
    assert validate_secure_directory(directory, create=False, expected_uid=os.geteuid() + 1).error_code == "REPORT_DIRECTORY_WRONG_OWNER"
    readonly = tmp_path / "readonly"; readonly.mkdir(mode=0o500)
    try: assert secure_atomic_write_json({}, readonly / "x.json", base_directory=readonly).error_code == "REPORT_DIRECTORY_NOT_WRITABLE"
    finally: readonly.chmod(0o700)


def test_fifo_target_is_rejected(tmp_path: Path) -> None:
    directory = tmp_path / "reports"; directory.mkdir(mode=0o700); target = directory / "ai_summary.json"; os.mkfifo(target, 0o600)
    assert secure_atomic_write_json({}, target, base_directory=directory).error_code == "REPORT_PATH_INVALID"


def test_replace_failure_preserves_previous_file_and_removes_temporary(tmp_path: Path) -> None:
    directory = tmp_path / "reports"; directory.mkdir(mode=0o700); target = directory / "ai_summary.json"; target.write_text('{"old": true}\n')
    def fail(_source: str, _destination: str) -> None: raise OSError("injected replace failure")
    result = secure_atomic_write_json({"new": True}, target, base_directory=directory, replace=fail)
    assert result.error_code == "REPORT_ATOMIC_REPLACE_FAILED"
    assert json.loads(target.read_text()) == {"old": True}
    assert not list(directory.glob(".*.tmp"))


def test_serialization_failure_never_touches_previous_file(tmp_path: Path) -> None:
    directory = tmp_path / "reports"; directory.mkdir(mode=0o700); target = directory / "ai_summary.json"; target.write_text('{"old": true}\n')
    result = secure_atomic_write_json({"invalid": object()}, target, base_directory=directory)
    assert not result.attempted and result.error_code == "REPORT_SERIALIZATION_FAILED"
    assert json.loads(target.read_text()) == {"old": True}


def test_concurrent_writers_always_leave_complete_parseable_json(tmp_path: Path) -> None:
    directory = tmp_path / "reports"; target = directory / "ai_summary.json"
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda number: secure_atomic_write_json({"writer": number, "payload": "x" * 1000}, target, base_directory=directory), range(40)))
    assert all(item.succeeded for item in results)
    assert json.loads(target.read_text())["writer"] in range(40)
    assert not list(directory.glob(".*.tmp"))


def test_probe_does_not_create_ai_summary(tmp_path: Path) -> None:
    directory = tmp_path / "reports"; result = probe_report_directory(directory)
    assert result["ai_summary_persistence_available"] is True
    assert not (directory / "ai_summary.json").exists()
    assert not list(directory.glob(".write-probe-*"))


def test_safe_legacy_file_migrates_once_without_deletion(tmp_path: Path) -> None:
    source = tmp_path / "legacy.json"; source.write_text(json.dumps({"legacy": True}), encoding="utf-8")
    directory = tmp_path / "new"; destination = directory / "ai_summary.json"
    result = migrate_legacy_json(source, destination)
    assert result.migrated and source.exists() and json.loads(destination.read_text()) == {"legacy": True}
    assert migrate_legacy_json(source, destination).status == "destination_exists"


def test_legacy_symlink_oversize_and_foreign_owner_are_not_migrated(tmp_path: Path, monkeypatch) -> None:
    real = tmp_path / "real.json"; real.write_text("{}")
    linked = tmp_path / "linked.json"; linked.symlink_to(real)
    assert migrate_legacy_json(linked, tmp_path / "a/out.json").status == "legacy_symlink_rejected"
    large = tmp_path / "large.json"; large.write_bytes(b" " * 100)
    assert migrate_legacy_json(large, tmp_path / "b/out.json", maximum_bytes=10).status == "legacy_oversized_rejected"
    original_lstat = secure_io.os.lstat
    def foreign(path):
        value = original_lstat(path)
        if Path(path) == real: return SimpleNamespace(st_mode=value.st_mode, st_uid=os.geteuid() + 1, st_size=value.st_size)
        return value
    monkeypatch.setattr(secure_io.os, "lstat", foreign)
    assert migrate_legacy_json(real, tmp_path / "c/out.json").status == "legacy_foreign_owner_rejected"
