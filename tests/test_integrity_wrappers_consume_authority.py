from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from mac_audit_agent.integrity.consumer_compare import ConsumerStatus, _find_mismatches
from mac_audit_agent.integrity.event_reconciliation import (
    SQLiteIntegrityEventStore,
    reconcile_integrity_events_after_verified_repair,
)
from mac_audit_agent.integrity.release_gate_mapping import map_release_gate_exception
from mac_audit_agent.integrity.result_cache import CurrentIntegrityStatus, cache_is_stale
from mac_audit_agent.integrity.wrapper_adapter import IntegrityWrapperAdapter


def _verified_wrapper_status() -> SimpleNamespace:
    return SimpleNamespace(
        status="verified",
        trust_state="trusted_developer_machine_signed_manifest",
        result_code="VALID",
        failure_code="",
        canonical_manifest_path="mac_audit_agent/integrity/integrity_manifest.json",
        manifest_path="mac_audit_agent/integrity/integrity_manifest.json",
        signature_path="mac_audit_agent/integrity/integrity_manifest.signature.json",
        signature_valid=True,
        release_id="release-test",
        build_id="build-test",
        git_commit="abc123",
        signing_key_fingerprint="public-fingerprint",
        signer_status=[{"developer_machine_id": "developer-machine"}],
        source_modified_files=[],
        modified_files=[],
        missing_files=[],
        extra_files=[],
        generated_modified_files=[],
        pre_uat_compatible=True,
        recommended_action="",
        reason="",
        policy_mode="public_release",
        to_dict=lambda: {"canonical_manifest_used": True, "details": {}},
    )


@pytest.mark.parametrize(
    "method",
    [
        "get_integrity_status_for_ui",
        "get_integrity_status_for_dashboard",
        "get_integrity_status_for_operational_health",
        "get_integrity_status_for_release_readiness",
        "get_integrity_status_for_pre_uat",
    ],
)
def test_every_wrapper_uses_live_integrity_authority(tmp_path: Path, method: str) -> None:
    live = _verified_wrapper_status()
    current = CurrentIntegrityStatus(
        generated_at=datetime.now(timezone.utc).isoformat(),
        status="verified",
        manifest_sha256="manifest-sha",
    )
    authority = SimpleNamespace(verify=lambda strict=True: live, status=lambda: live)
    with (
        patch("mac_audit_agent.integrity.wrapper_adapter.IntegrityAuthority", return_value=authority) as authority_type,
        patch("mac_audit_agent.integrity.wrapper_adapter.build_current_integrity_status", return_value=current),
        patch("mac_audit_agent.integrity.wrapper_adapter.read_current_integrity_status", return_value=None),
    ):
        result = getattr(IntegrityWrapperAdapter(tmp_path), method)("public_release")

    authority_type.assert_called_once_with(tmp_path.resolve(), "public_release")
    assert result.status == "verified"
    assert result.trust_state == "trusted_developer_machine_signed_manifest"
    assert result.result_code == "VALID"


def test_dirty_tree_is_release_gate_failure_not_integrity_failure() -> None:
    result = map_release_gate_exception(
        RuntimeError("rehash --require-clean-git rejected dirty source tree"),
        integrity_status="verified",
    )
    assert result.domain == "release_gate"
    assert result.failure_code == "RELEASE_GATE_DIRTY_SOURCE_TREE"
    assert result.integrity_status == "verified"
    assert "SIGNED_MANIFEST" not in result.failure_code


def test_cache_is_display_only_and_stale_by_age_or_manifest() -> None:
    fresh = CurrentIntegrityStatus(
        generated_at=datetime.now(timezone.utc).isoformat(),
        manifest_sha256="current",
    )
    old = CurrentIntegrityStatus(
        generated_at=(datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
        manifest_sha256="current",
    )
    assert not cache_is_stale(fresh, "current")
    assert cache_is_stale(fresh, "different")
    assert cache_is_stale(old, "current")


def test_verified_repair_supersedes_stale_active_db_event(tmp_path: Path) -> None:
    db_path = tmp_path / "active.sqlite3"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """CREATE TABLE events (
                id TEXT PRIMARY KEY, event_type TEXT, status TEXT,
                superseded_by_manifest_sha256 TEXT, superseded_at TEXT,
                repair_evidence_path TEXT, resolution TEXT
            )"""
        )
        conn.execute(
            "INSERT INTO events(id, event_type, status) VALUES (?, ?, ?)",
            ("event-1", "signed_manifest_validation_failed", "active"),
        )
    live = SimpleNamespace(status="verified", manifest_sha256="new-sha", evidence_path="evidence.json")
    result = reconcile_integrity_events_after_verified_repair(live, SQLiteIntegrityEventStore(db_path))
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT status, superseded_by_manifest_sha256 FROM events WHERE id = 'event-1'"
        ).fetchone()
    assert result.status == "reconciled"
    assert result.superseded_event_ids == ["event-1"]
    assert row == ("superseded", "new-sha")


def _consumer(name: str, *, status: str = "verified") -> ConsumerStatus:
    return ConsumerStatus(
        name=name,
        status=status,
        trust_state="trusted_developer_machine_signed_manifest" if status == "verified" else "failed",
        manifest_path="manifest.json",
        signature_path="manifest.signature.json",
        manifest_sha256="sha",
        failure_code="" if status == "verified" else "SOURCE_FILES_MODIFIED",
        evidence_age_seconds=0.0,
        source="test",
    )


def test_compare_consumers_fails_when_displayed_consumer_diverges() -> None:
    baseline = _consumer("cli_status")
    operational = _consumer("operational_health_backend", status="failed")
    mismatches = _find_mismatches([baseline, operational], baseline)
    assert any("operational_health_backend" in item for item in mismatches)


def test_comparison_source_covers_operational_health_and_active_db() -> None:
    source = (Path(__file__).parents[1] / "mac_audit_agent/integrity/consumer_compare.py").read_text(encoding="utf-8")
    assert '"operational_health_backend"' in source
    assert '"active_db_current_status"' in source
    assert '"active_db_unresolved_integrity_events"' in source


def test_display_wrappers_do_not_read_legacy_manifests_directly() -> None:
    root = Path(__file__).parents[1]
    for relative in (
        "mac_audit_agent/integrity/wrapper_adapter.py",
        "mac_audit_agent/operational_health.py",
        "mac_audit_agent/integrity/ui_compat.py",
        "mac_audit_agent/integrity/pre_uat_compat.py",
    ):
        source = (root / relative).read_text(encoding="utf-8")
        assert "release_manifest.json" not in source
        assert "security/integrity_manifest.json" not in source


def test_wrapper_has_no_gui_imports() -> None:
    source = Path(IntegrityWrapperAdapter.__module__.replace(".", "/") + ".py")
    repository_source = Path(__file__).parents[1] / source
    text = repository_source.read_text(encoding="utf-8")
    assert "PySide" not in text
    assert "mac_audit_agent.ui" not in text
