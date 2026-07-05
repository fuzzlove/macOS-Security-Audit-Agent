from pathlib import Path

from mac_audit_agent.integrity.core import IntegrityEngine
from mac_audit_agent.integrity.diff_report import IntegrityState
from mac_audit_agent.integrity.manifest import create_integrity_manifest, write_integrity_manifest
from mac_audit_agent.integrity.repair_wizard import RepairWizard


def _trusted_manifest(root: Path) -> Path:
    manifest = create_integrity_manifest(root, source_type="source_tree", trust_state="trusted")
    return write_integrity_manifest(manifest, root / "msaa_integrity_manifest.json")


def test_integrity_engine_reports_verified_state(tmp_path: Path) -> None:
    root = tmp_path / "app"
    package = root / "mac_audit_agent"
    package.mkdir(parents=True)
    (package / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    manifest_path = _trusted_manifest(root)

    report = IntegrityEngine(root, manifest_path=manifest_path).generate_diff_report()

    assert report.state == IntegrityState.VERIFIED
    assert report.severity == "info"
    assert report.file_changes == []


def test_modified_file_produces_exact_diff_report(tmp_path: Path) -> None:
    root = tmp_path / "app"
    package = root / "mac_audit_agent"
    package.mkdir(parents=True)
    target = package / "monitor.py"
    target.write_text("print('trusted')\n", encoding="utf-8")
    manifest_path = _trusted_manifest(root)

    target.write_text("print('changed')\n", encoding="utf-8")
    report = IntegrityEngine(root, manifest_path=manifest_path).generate_diff_report()

    assert report.state == IntegrityState.MODIFIED
    assert report.severity == "high"
    assert report.modified_files[0].file_path == "mac_audit_agent/monitor.py"
    assert report.modified_files[0].expected_hash
    assert report.modified_files[0].actual_hash
    assert "tampering" in report.modified_files[0].explanation


def test_missing_file_is_critical_and_repairable_from_trusted_source(tmp_path: Path) -> None:
    root = tmp_path / "app"
    package = root / "mac_audit_agent"
    package.mkdir(parents=True)
    target = package / "core.py"
    target.write_text("VALUE = 1\n", encoding="utf-8")
    manifest_path = _trusted_manifest(root)
    repair_source = tmp_path / "trusted_source"
    (repair_source / "mac_audit_agent").mkdir(parents=True)
    (repair_source / "mac_audit_agent" / "core.py").write_text("VALUE = 1\n", encoding="utf-8")

    target.unlink()
    engine = IntegrityEngine(root, manifest_path=manifest_path)
    report = engine.generate_diff_report()
    assert report.state == IntegrityState.MISSING_FILES
    assert report.severity == "critical"

    result = RepairWizard(engine, repair_source_dir=repair_source).safe_repair()
    assert result.success is True
    assert "restored:mac_audit_agent/core.py" in result.actions_run
    assert (package / "core.py").exists()
    assert result.after["state"] == "VERIFIED"


def test_extra_executable_is_high_risk(tmp_path: Path) -> None:
    root = tmp_path / "app"
    package = root / "mac_audit_agent"
    package.mkdir(parents=True)
    (package / "core.py").write_text("VALUE = 1\n", encoding="utf-8")
    manifest_path = _trusted_manifest(root)
    extra = root / "unexpected_tool"
    extra.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    extra.chmod(0o755)

    report = IntegrityEngine(root, manifest_path=manifest_path).generate_diff_report()

    assert report.state == IntegrityState.EXTRA_FILES
    assert report.extra_files[0].severity == "high"
    assert "unexpected executable" in report.extra_files[0].explanation.lower()


def test_logs_settings_and_databases_excluded_from_baseline(tmp_path: Path) -> None:
    root = tmp_path / "app"
    package = root / "mac_audit_agent"
    package.mkdir(parents=True)
    (package / "core.py").write_text("VALUE = 1\n", encoding="utf-8")
    (root / "logs").mkdir()
    (root / "logs" / "integrity.log").write_text("mutable", encoding="utf-8")
    (root / "settings.json").write_text("{}", encoding="utf-8")
    (root / "audit.sqlite3").write_text("db", encoding="utf-8")

    manifest = IntegrityEngine(root).build_manifest_snapshot(trust_state="draft")
    paths = {entry.relative_path for entry in manifest.file_entries}

    assert "mac_audit_agent/core.py" in paths
    assert "logs/integrity.log" not in paths
    assert "settings.json" not in paths
    assert "audit.sqlite3" not in paths


def test_draft_manifest_cannot_verify(tmp_path: Path) -> None:
    root = tmp_path / "app"
    root.mkdir()
    (root / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    manifest = create_integrity_manifest(root, source_type="source_tree", trust_state="draft")
    manifest_path = write_integrity_manifest(manifest, root / "msaa_integrity_manifest.json")

    report = IntegrityEngine(root, manifest_path=manifest_path).generate_diff_report()

    assert report.state == IntegrityState.DRAFT
    assert "draft" in report.summary.lower()


def test_trusted_baseline_creation_requires_confirmation(tmp_path: Path) -> None:
    root = tmp_path / "app"
    root.mkdir()
    (root / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    wizard = RepairWizard(IntegrityEngine(root, manifest_path=root / "msaa_integrity_manifest.json"))

    try:
        wizard.create_trusted_baseline(confirmation="")
    except PermissionError:
        pass
    else:
        raise AssertionError("baseline creation must require explicit confirmation")

    path = wizard.create_trusted_baseline(confirmation="I TRUST THIS INSTALLATION")
    assert path.exists()


def test_integrity_alert_event_contains_diff_summary(tmp_path: Path) -> None:
    root = tmp_path / "app"
    root.mkdir()
    target = root / "module.py"
    target.write_text("VALUE = 1\n", encoding="utf-8")
    manifest_path = _trusted_manifest(root)
    target.write_text("VALUE = 2\n", encoding="utf-8")
    engine = IntegrityEngine(root, manifest_path=manifest_path)
    report = engine.generate_diff_report()

    event = engine.event_for_report(report)

    assert event.event_type == "integrity_modified"
    assert event.severity == "high"
    assert "module.py" in event.evidence
