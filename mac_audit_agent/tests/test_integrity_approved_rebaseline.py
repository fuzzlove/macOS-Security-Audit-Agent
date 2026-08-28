from __future__ import annotations

from pathlib import Path

from mac_audit_agent.integrity.approved_changes import create_approved_change_record
from mac_audit_agent.integrity.exclusions import is_runtime_mutable_path
from mac_audit_agent.integrity.manifest import create_integrity_manifest, write_integrity_manifest
from mac_audit_agent.integrity.rebaseline import review_approved_change, update_trusted_development_baseline
from mac_audit_agent.integrity.trust_states import IntegrityTrustState, signature_context_message
from mac_audit_agent.integrity.verifier import verify_integrity_manifest
from mac_audit_agent.quality.functional_registry import build_registry


def _root(tmp_path: Path) -> Path:
    root = tmp_path / "app"
    package = root / "mac_audit_agent"
    package.mkdir(parents=True)
    (package / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    return root


def _manifest(root: Path) -> Path:
    manifest = create_integrity_manifest(root, source_type="source_tree", trust_state="trusted")
    return write_integrity_manifest(manifest, root / "msaa_integrity_manifest.json")


def test_modified_file_without_approved_record_is_unapproved(tmp_path: Path) -> None:
    root = _root(tmp_path)
    manifest_path = _manifest(root)
    (root / "mac_audit_agent" / "module.py").write_text("VALUE = 2\n", encoding="utf-8")

    result = verify_integrity_manifest(manifest_path, root=root, expected_source_type="source_tree")

    assert result.overall_status == "modified"
    assert result.trust_state == IntegrityTrustState.MODIFIED_UNAPPROVED.value
    assert result.modified_file_classification[0]["classification"] == "unapproved"


def test_approved_change_without_rebaseline_is_pending_review(tmp_path: Path) -> None:
    root = _root(tmp_path)
    manifest_path = _manifest(root)
    target = root / "mac_audit_agent" / "module.py"
    target.write_text("VALUE = 2\n", encoding="utf-8")
    record = create_approved_change_record(
        root,
        description="Codex-approved test change",
        source="codex",
        affected_files=["mac_audit_agent/module.py"],
    )

    result = verify_integrity_manifest(manifest_path, root=root, expected_source_type="source_tree")
    review = review_approved_change(root, manifest_path)

    assert result.trust_state == IntegrityTrustState.MODIFIED_PENDING_REVIEW.value
    assert result.approved_change_id == record.change_id
    assert review.update_baseline_allowed is True
    assert "not trusted until reviewed" in " ".join(result.warnings)


def test_approved_change_after_rebaseline_is_trusted_codex_baseline(tmp_path: Path) -> None:
    root = _root(tmp_path)
    manifest_path = _manifest(root)
    (root / "mac_audit_agent" / "module.py").write_text("VALUE = 2\n", encoding="utf-8")
    record = create_approved_change_record(
        root,
        description="Codex-approved test change",
        source="codex",
        affected_files=["mac_audit_agent/module.py"],
        tests_required=[],
    )

    result = update_trusted_development_baseline(
        root,
        approved_change=record,
        manifest_path=manifest_path,
        verification_commands=[],
        require_verification=False,
    )
    fresh = verify_integrity_manifest(manifest_path, root=root, expected_source_type="source_tree")

    assert result["status"] == "rebaselined"
    assert fresh.overall_status == "verified"
    assert fresh.trust_state == IntegrityTrustState.TRUSTED_CODEX_APPROVED_CHANGE.value
    assert fresh.approved_change_id == record.change_id


def test_runtime_mutable_files_are_excluded_from_manifest(tmp_path: Path) -> None:
    root = _root(tmp_path)
    (root / ".pytest_cache").mkdir()
    (root / ".pytest_cache" / "README.md").write_text("mutable", encoding="utf-8")
    (root / "audit.sqlite3-wal").write_text("mutable", encoding="utf-8")
    manifest = create_integrity_manifest(root, source_type="source_tree", trust_state="trusted")
    paths = {entry.relative_path for entry in manifest.file_entries}

    assert "mac_audit_agent/module.py" in paths
    assert ".pytest_cache/README.md" not in paths
    assert "audit.sqlite3-wal" not in paths
    assert is_runtime_mutable_path("reports/output.html")


def test_signature_context_distinguishes_source_and_release() -> None:
    source_message, source_severity = signature_context_message("source_tree", "unsigned")
    release_message, release_severity = signature_context_message("pyinstaller_app", "unsigned")

    assert "Unsigned source checkout" in source_message
    assert source_severity == "info"
    assert "Unsigned release artifact" in release_message
    assert release_severity == "high"


def test_integrity_rebaseline_pre_uat_checks_registered() -> None:
    ids = {check.check_id for check in build_registry()}
    assert {
        "integrity.manifest_exists",
        "integrity.modified_files_classified",
        "integrity.approved_change_rebaseline",
        "integrity.signature_context",
        "integrity.no_silent_trust",
        "integrity.exclusions_valid",
    }.issubset(ids)
