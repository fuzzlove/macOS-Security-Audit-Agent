from __future__ import annotations

from pathlib import Path

import pytest

from mac_audit_agent.integrity.cleanup import cleanup_generated, cleanup_legacy_integrity
from mac_audit_agent.integrity.consumer_compare import compare_integrity_consumers
from mac_audit_agent.integrity.developer_machine_signing import create_developer_machine_key
from mac_audit_agent.integrity.event_reconciliation import reconcile_integrity_events_after_verified_repair
from mac_audit_agent.integrity.hash_scope import build_hash_scope_report
from mac_audit_agent.integrity.repair_and_sign import repair_and_sign_integrity
from mac_audit_agent.integrity.result_cache import build_current_integrity_status
from mac_audit_agent.integrity.status_resolver import resolve_integrity_status


def _project(root: Path) -> None:
    package = root / "mac_audit_agent"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    (root / "pyproject.toml").write_text("[project]\nname='fixture'\n", encoding="utf-8")


def _enroll(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from mac_audit_agent.integrity import developer_machine_signing

    monkeypatch.setattr(developer_machine_signing, "developer_key_dir", lambda: root.parent / f"{root.name}-keys")
    create_developer_machine_key(root, developer="Liquidsky Network Security", organization="Liquidsky Network Security", machine_label="Test Dev Mac")


def test_repair_and_sign_verified_updates_result_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _project(tmp_path)
    _enroll(tmp_path, monkeypatch)
    writes = []
    monkeypatch.setattr("mac_audit_agent.integrity.consumer_compare.read_current_integrity_status", lambda: None)
    monkeypatch.setattr("mac_audit_agent.integrity.auto_sign.write_current_integrity_status", lambda current, **kwargs: writes.append(current) or tmp_path / "cache.json")

    result = repair_and_sign_integrity(tmp_path, policy="dev", author="A", reason="R", build_id="b1", developer_machine=True)

    assert result.status == "verified"
    assert writes
    assert writes[0].status == "verified"
    assert writes[0].trust_state == "trusted_developer_machine_signed_manifest"


def test_compare_consumers_passes_after_repair(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _project(tmp_path)
    _enroll(tmp_path, monkeypatch)
    monkeypatch.setattr("mac_audit_agent.integrity.consumer_compare.read_current_integrity_status", lambda: None)
    monkeypatch.setattr("mac_audit_agent.integrity.consumer_compare.read_current_integrity_status_db", lambda: None)
    monkeypatch.setattr("mac_audit_agent.integrity.consumer_compare._active_db_unresolved_events_consumer", lambda baseline: baseline)
    monkeypatch.setattr("mac_audit_agent.integrity.consumer_compare._runtime_sync_consumer", lambda root, policy, baseline: baseline)
    monkeypatch.setattr("mac_audit_agent.integrity.auto_sign.write_current_integrity_status", lambda current, **kwargs: tmp_path / "cache.json")
    repair_and_sign_integrity(tmp_path, policy="dev", author="A", reason="R", build_id="b1", developer_machine=True)

    result = compare_integrity_consumers(tmp_path, policy="dev")

    assert result.status == "pass"
    assert result.failure_code == ""


def test_compare_consumers_fails_when_consumer_uses_release_manifest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _project(tmp_path)
    _enroll(tmp_path, monkeypatch)
    monkeypatch.setattr("mac_audit_agent.integrity.consumer_compare.read_current_integrity_status", lambda: None)
    monkeypatch.setattr("mac_audit_agent.integrity.consumer_compare.read_current_integrity_status_db", lambda: None)
    monkeypatch.setattr("mac_audit_agent.integrity.consumer_compare._active_db_unresolved_events_consumer", lambda baseline: baseline)
    monkeypatch.setattr("mac_audit_agent.integrity.consumer_compare._runtime_sync_consumer", lambda root, policy, baseline: baseline)
    monkeypatch.setattr("mac_audit_agent.integrity.auto_sign.write_current_integrity_status", lambda current, **kwargs: tmp_path / "cache.json")
    repair_and_sign_integrity(tmp_path, policy="dev", author="A", reason="R", build_id="b1", developer_machine=True)

    import mac_audit_agent.integrity.consumer_compare as consumer_compare

    original = consumer_compare._pre_uat_consumer

    def divergent(root: Path, policy: str, baseline):
        consumer = original(root, policy, baseline)
        consumer.manifest_path = str(root / "mac_audit_agent/integrity/release_manifest.json")
        return consumer

    monkeypatch.setattr(consumer_compare, "_pre_uat_consumer", divergent)
    result = compare_integrity_consumers(tmp_path, policy="dev")

    assert result.status == "fail"
    assert result.failure_code == "INTEGRITY_CONSUMER_DIVERGENCE"


def test_integrity_metadata_classification(tmp_path: Path) -> None:
    _project(tmp_path)
    integrity = tmp_path / "mac_audit_agent/integrity"
    security = tmp_path / "mac_audit_agent/security"
    integrity.mkdir(parents=True)
    security.mkdir(parents=True)
    (integrity / "integrity_manifest.json").write_text("{}", encoding="utf-8")
    (integrity / "integrity_manifest.signature.json").write_text("{}", encoding="utf-8")
    (integrity / "trusted_developer_machines.json").write_text("{}", encoding="utf-8")
    (integrity / "development_manifest.json").write_text("{}", encoding="utf-8")
    (security / "integrity_manifest.json").write_text("{}", encoding="utf-8")
    yubikey = integrity / "yubikey_signatures"
    yubikey.mkdir()
    (yubikey / "old.sig").write_text("legacy", encoding="utf-8")
    egg = tmp_path / "macos_security_audit_agent.egg-info"
    egg.mkdir()
    (egg / "PKG-INFO").write_text("generated", encoding="utf-8")

    report = build_hash_scope_report(tmp_path)

    assert "mac_audit_agent/integrity/integrity_manifest.json" in report.trust_metadata_files
    assert "mac_audit_agent/integrity/integrity_manifest.signature.json" in report.trust_metadata_files
    assert "mac_audit_agent/integrity/trusted_developer_machines.json" in report.trust_metadata_files
    assert "mac_audit_agent/integrity/development_manifest.json" in report.legacy_ignored_files
    assert "mac_audit_agent/security/integrity_manifest.json" in report.legacy_ignored_files
    assert "mac_audit_agent/integrity/yubikey_signatures/old.sig" in report.deprecated_artifacts
    assert "macos_security_audit_agent.egg-info/PKG-INFO" in report.build_files


def test_old_integrity_events_are_superseded_after_repair() -> None:
    class FakeDb:
        def __init__(self) -> None:
            self.updated = {}

        def list_active_integrity_events(self):
            return [{"id": "evt-1", "event_type": "signed_manifest_validation_failed", "status": "active"}]

        def mark_integrity_event_superseded(self, event_id, payload):
            self.updated[event_id] = payload

    current = build_current_integrity_status(type("Status", (), {"status": "verified", "trust_state": "trusted_developer_machine_signed_manifest", "policy_mode": "dev"})(), root=Path.cwd())
    current.manifest_sha256 = "abc"
    current.evidence_path = "evidence.json"
    db = FakeDb()

    result = reconcile_integrity_events_after_verified_repair(current, db)

    assert result.status == "reconciled"
    assert result.superseded_event_ids == ["evt-1"]
    assert db.updated["evt-1"]["superseded_by_manifest_sha256"] == "abc"


def test_cleanup_commands_are_dry_run_and_safe(tmp_path: Path) -> None:
    _project(tmp_path)
    legacy = tmp_path / "mac_audit_agent/integrity/development_manifest.json"
    legacy.parent.mkdir(parents=True)
    legacy.write_text("{}", encoding="utf-8")
    egg = tmp_path / "macos_security_audit_agent.egg-info"
    egg.mkdir()

    legacy_result = cleanup_legacy_integrity(tmp_path, dry_run=True)
    generated_result = cleanup_generated(tmp_path, egg_info=True, dry_run=True)

    assert legacy_result.status == "dry_run"
    assert "mac_audit_agent/integrity/development_manifest.json" in legacy_result.candidates
    assert generated_result.status == "dry_run"
    assert "macos_security_audit_agent.egg-info" in generated_result.candidates
