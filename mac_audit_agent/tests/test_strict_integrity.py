from __future__ import annotations

import os
import stat
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from mac_audit_agent.integrity.change_authorization import AuthorizedChangeRegistry
from mac_audit_agent.integrity.signed_manifest import create_signed_manifest, write_signed_manifest
from mac_audit_agent.integrity.strict_verifier import StrictIntegrityVerifier
from mac_audit_agent.storage import AuditDatabase
from mac_audit_agent.ui.integrity_diff_viewer import IntegrityDiffViewer


def _write_app_tree(root: Path) -> None:
    package = root / "mac_audit_agent"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "app.py").write_text("print('trusted')\n", encoding="utf-8")
    (root / "template.plist").write_text("<plist />\n", encoding="utf-8")


def _signed_manifest(root: Path) -> Path:
    manifest = create_signed_manifest(root)
    path = root / "msaa_integrity_manifest.json"
    write_signed_manifest(manifest, path)
    return path


def test_strict_integrity_verified_state_lists_unchanged_files(tmp_path: Path) -> None:
    _write_app_tree(tmp_path)
    manifest_path = _signed_manifest(tmp_path)

    report = StrictIntegrityVerifier(tmp_path, manifest_path, logs_dir=tmp_path / "logs").verify()

    assert report.status == "verified"
    assert not report.requires_user_acknowledgement
    assert report.unchanged_files
    assert report.hash_mismatches == []
    assert (tmp_path / "logs" / "integrity.log").exists()


def test_modified_file_triggers_modified_hash_and_high_severity(tmp_path: Path) -> None:
    _write_app_tree(tmp_path)
    manifest_path = _signed_manifest(tmp_path)
    (tmp_path / "mac_audit_agent" / "app.py").write_text("print('changed')\n", encoding="utf-8")

    report = StrictIntegrityVerifier(tmp_path, manifest_path, logs_dir=tmp_path / "logs").verify()

    assert report.status == "modified"
    assert report.requires_user_acknowledgement
    assert any(change.change_type == "MODIFIED_HASH" for change in report.hash_mismatches)
    assert any(change.file_path.endswith("app.py") and change.severity in {"HIGH", "CRITICAL"} for change in report.hash_mismatches)


def test_missing_file_extra_file_and_permission_change_are_explicit(tmp_path: Path) -> None:
    _write_app_tree(tmp_path)
    manifest_path = _signed_manifest(tmp_path)
    (tmp_path / "template.plist").unlink()
    extra = tmp_path / "mac_audit_agent" / "extra.py"
    extra.write_text("print('extra')\n", encoding="utf-8")
    target = tmp_path / "mac_audit_agent" / "app.py"
    target.chmod(stat.S_IMODE(target.stat().st_mode) | stat.S_IXUSR)

    report = StrictIntegrityVerifier(tmp_path, manifest_path, logs_dir=tmp_path / "logs").verify()

    assert report.missing_files
    assert report.extra_files
    assert report.permission_changes
    assert {change.change_type for change in report.all_changes} >= {"MISSING", "EXTRA_FILE", "PERMISSION_CHANGED"}


def test_modified_manifest_signature_is_unknown_and_critical(tmp_path: Path) -> None:
    _write_app_tree(tmp_path)
    manifest_path = _signed_manifest(tmp_path)
    payload = manifest_path.read_text(encoding="utf-8").replace("MSAA local trusted manifest signer", "tampered signer")
    manifest_path.write_text(payload, encoding="utf-8")

    report = StrictIntegrityVerifier(tmp_path, manifest_path, logs_dir=tmp_path / "logs").verify()

    assert report.status == "unknown"
    assert report.severity_level == "CRITICAL"
    assert report.requires_user_acknowledgement
    assert "manifest" in report.explanation_summary.lower()


def test_signature_change_is_critical_when_file_signature_differs(tmp_path: Path, monkeypatch) -> None:
    _write_app_tree(tmp_path)
    manifest = create_signed_manifest(tmp_path)
    manifest.file_entries[0].signature = "trusted-signature"
    from mac_audit_agent.integrity.signed_manifest import sign_manifest

    sign_manifest(manifest)
    manifest_path = tmp_path / "msaa_integrity_manifest.json"
    write_signed_manifest(manifest, manifest_path)
    monkeypatch.setattr(StrictIntegrityVerifier, "_file_signature", lambda self, path: "changed-signature")

    report = StrictIntegrityVerifier(tmp_path, manifest_path, logs_dir=tmp_path / "logs").verify()

    assert report.signature_changes
    assert report.severity_level == "CRITICAL"


def test_authorization_records_diff_but_does_not_hide_future_diff(tmp_path: Path) -> None:
    _write_app_tree(tmp_path)
    manifest_path = _signed_manifest(tmp_path)
    (tmp_path / "mac_audit_agent" / "app.py").write_text("print('changed')\n", encoding="utf-8")
    report = StrictIntegrityVerifier(tmp_path, manifest_path, logs_dir=tmp_path / "logs").verify()
    registry = AuthorizedChangeRegistry(tmp_path / "authorized_changes.json")

    record = registry.authorize(report, user_confirmation="I ACKNOWLEDGE THESE CHANGES", reason="test")
    future_report = StrictIntegrityVerifier(tmp_path, manifest_path, logs_dir=tmp_path / "logs").verify()

    assert record.file_paths
    assert registry.has_authorization_for_report(future_report)
    assert future_report.status == "modified"
    assert future_report.hash_mismatches


def test_integrity_history_is_recorded_in_sqlite(tmp_path: Path) -> None:
    _write_app_tree(tmp_path / "app")
    manifest_path = _signed_manifest(tmp_path / "app")
    report = StrictIntegrityVerifier(tmp_path / "app", manifest_path, logs_dir=tmp_path / "logs").verify()
    db = AuditDatabase(tmp_path / "audit.sqlite")

    db.record_integrity_history(report, user_action_taken="launch_verification")
    rows = db.latest_integrity_history()

    assert rows
    assert rows[0]["run_id"] == report.run_id
    assert rows[0]["result_status"] == "verified"
    assert rows[0]["user_action_taken"] == "launch_verification"
    db.close()


def test_integrity_diff_viewer_displays_file_level_changes(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    _write_app_tree(tmp_path)
    manifest_path = _signed_manifest(tmp_path)
    (tmp_path / "mac_audit_agent" / "app.py").write_text("print('changed')\n", encoding="utf-8")
    report = StrictIntegrityVerifier(tmp_path, manifest_path, logs_dir=tmp_path / "logs").verify()

    viewer = IntegrityDiffViewer(report)

    assert viewer.table.rowCount() >= 1
    assert "{" not in viewer.table.item(0, 0).text()
    assert any(viewer.table.item(row, 3).text() == "MODIFIED_HASH" for row in range(viewer.table.rowCount()))
    viewer.close()
    app.processEvents()
