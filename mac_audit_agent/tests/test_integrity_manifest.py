from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

from mac_audit_agent.build_identity import detect_build_identity
from mac_audit_agent.version import APP_VERSION
from mac_audit_agent.integrity.hasher import calculate_sha256, collect_integrity_files
from mac_audit_agent.integrity.manifest import create_integrity_manifest, load_integrity_manifest, main as manifest_main, write_integrity_manifest
from mac_audit_agent.integrity.package_integrity import verify_pyinstaller_app, verify_wheel_record
from mac_audit_agent.integrity.verifier import select_integrity_manifest, verify_current_install_integrity, verify_integrity_manifest
from mac_audit_agent.source_integrity import verify_source_integrity


class MemoryStore:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    def get_background_monitor_state(self, key: str, default: str = "") -> str:
        return self.values.get(key, default)

    def set_background_monitor_state(self, key: str, value: str) -> None:
        self.values[key] = value


def test_sha256_calculated_correctly_and_streams(tmp_path: Path) -> None:
    target = tmp_path / "large.bin"
    payload = b"abc123" * 200_000
    target.write_bytes(payload)

    assert calculate_sha256(target) == hashlib.sha256(payload).hexdigest()


def test_manifest_excludes_mutable_operational_files(tmp_path: Path) -> None:
    root = tmp_path / "project"
    package = root / "mac_audit_agent"
    package.mkdir(parents=True)
    (package / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    (root / "audit.sqlite3").write_text("mutable", encoding="utf-8")
    (root / "logs").mkdir()
    (root / "logs" / "monitor.log").write_text("mutable", encoding="utf-8")
    (root / "__pycache__").mkdir()
    (root / "__pycache__" / "module.pyc").write_bytes(b"cache")

    manifest = create_integrity_manifest(root, source_type="source_tree")
    paths = {entry.relative_path for entry in manifest.file_entries}

    assert "mac_audit_agent/module.py" in paths
    assert "audit.sqlite3" not in paths
    assert "logs/monitor.log" not in paths
    assert "__pycache__/module.pyc" not in paths
    assert manifest.manifest_hash


def test_collect_integrity_files_is_deterministic_and_excludes_mutable_files(tmp_path: Path) -> None:
    root = tmp_path / "project"
    (root / "mac_audit_agent").mkdir(parents=True)
    (root / "mac_audit_agent" / "b.py").write_text("B = 1\n", encoding="utf-8")
    (root / "mac_audit_agent" / "a.py").write_text("A = 1\n", encoding="utf-8")
    (root / "logs").mkdir()
    (root / "logs" / "monitor.log").write_text("mutable", encoding="utf-8")

    files = collect_integrity_files(root, "source_tree", ["logs/"])
    relative = [path.relative_to(root).as_posix() for path in files]

    assert relative == sorted(relative)
    assert "mac_audit_agent/a.py" in relative
    assert "mac_audit_agent/b.py" in relative
    assert "logs/monitor.log" not in relative


def test_source_type_aliases_are_canonicalized(tmp_path: Path) -> None:
    root = tmp_path / "runtime"
    root.mkdir()
    (root / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    manifest = create_integrity_manifest(root, source_type="system_runtime")
    manifest_path = write_integrity_manifest(manifest, root / "integrity_manifest.json")

    assert manifest.source_type == "system_daemon_runtime"
    assert load_integrity_manifest(manifest_path).source_type == "system_daemon_runtime"


def test_matching_modified_missing_and_extra_executable_detection(tmp_path: Path) -> None:
    root = tmp_path / "runtime"
    package = root / "mac_audit_agent"
    package.mkdir(parents=True)
    tracked = package / "monitor.py"
    tracked.write_text("print('ok')\n", encoding="utf-8")
    manifest = create_integrity_manifest(root, source_type="system_runtime")
    manifest_path = write_integrity_manifest(manifest, root / "integrity_manifest.json")

    assert verify_integrity_manifest(manifest_path, root=root).overall_status == "verified"

    tracked.write_text("print('changed')\n", encoding="utf-8")
    modified = verify_integrity_manifest(manifest_path, root=root)
    assert modified.overall_status == "modified"
    assert modified.mismatched_count == 1

    tracked.unlink()
    missing = verify_integrity_manifest(manifest_path, root=root)
    assert missing.overall_status == "modified"
    assert missing.missing_count == 1

    tracked.write_text("print('ok')\n", encoding="utf-8")
    extra = root / "unexpected_tool"
    extra.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    extra.chmod(extra.stat().st_mode | stat.S_IXUSR)
    extra_result = verify_integrity_manifest(manifest_path, root=root)
    assert extra_result.overall_status == "modified"
    assert extra_result.extra_count == 1
    assert any("Unexpected executable" in warning for warning in extra_result.warnings)


def test_permission_and_symlink_change_detected(tmp_path: Path) -> None:
    root = tmp_path / "runtime"
    root.mkdir()
    target = root / "helper.py"
    target.write_text("VALUE = 1\n", encoding="utf-8")
    link = root / "helper-link"
    link.symlink_to("helper.py")
    manifest = create_integrity_manifest(root, source_type="system_runtime")
    manifest_path = write_integrity_manifest(manifest, root / "integrity_manifest.json")

    target.chmod(0o777)
    changed = verify_integrity_manifest(manifest_path, root=root)
    assert changed.overall_status == "modified"
    assert any("mode" in item.get("mismatch_reasons", []) for item in changed.file_results)

    link.unlink()
    link.symlink_to("/tmp/outside-msaa")
    symlink_result = verify_integrity_manifest(manifest_path, root=root)
    assert symlink_result.overall_status == "modified"
    assert any("outside approved root" in warning for warning in symlink_result.warnings)


def test_missing_and_corrupt_manifest_are_not_verified(tmp_path: Path) -> None:
    missing = verify_integrity_manifest(tmp_path / "missing.json", root=tmp_path)
    assert missing.overall_status == "unknown"
    assert "No trusted integrity manifest exists" in missing.errors[0]

    corrupt_path = tmp_path / "manifest.json"
    corrupt_path.write_text("{not-json", encoding="utf-8")
    corrupt = verify_integrity_manifest(corrupt_path, root=tmp_path)
    assert corrupt.overall_status == "failed"


def test_manifest_creation_requires_explicit_trusted_confirmation(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    (root / "module.py").write_text("VALUE = 1\n", encoding="utf-8")

    try:
        manifest_main(["--create-source-manifest", "--root", str(root), "--output", str(root / "manifest.json")])
    except SystemExit as exc:
        assert exc.code != 0
    else:
        raise AssertionError("manifest creation should require explicit trusted confirmation")

    assert not (root / "manifest.json").exists()
    assert manifest_main(["--create-source-manifest", "--root", str(root), "--output", str(root / "manifest.json"), "--trusted-confirmation", "TRUST CURRENT FILES"]) == 0
    assert (root / "manifest.json").exists()


def test_draft_manifest_is_not_trusted_and_cannot_verify(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    (root / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    manifest_path = root / "draft.json"

    assert manifest_main(["--create-source-manifest", "--root", str(root), "--output", str(manifest_path), "--draft"]) == 0
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert payload["trust_state"] == "draft"

    result = verify_integrity_manifest(manifest_path, root=root)
    assert result.overall_status == "draft"
    assert result.trust_state == "draft"
    assert result.mismatched_count == 0


def test_stale_manifest_version_is_degraded_state_not_modified(tmp_path: Path) -> None:
    root = tmp_path / "runtime"
    root.mkdir()
    (root / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    manifest = create_integrity_manifest(root, source_type="system_runtime", app_version="0.0-stale")
    manifest_path = write_integrity_manifest(manifest, root / "integrity_manifest.json")

    result = verify_integrity_manifest(manifest_path, root=root)
    assert result.overall_status == "stale"
    assert result.mismatched_count == 0
    assert result.exact_mismatch_reason
    assert result.mismatch_details[0]["field"] == "app_version"


def test_stale_manifest_still_hashes_files_and_detects_modification(tmp_path: Path) -> None:
    root = tmp_path / "runtime"
    root.mkdir()
    tracked = root / "module.py"
    tracked.write_text("VALUE = 1\n", encoding="utf-8")
    manifest = create_integrity_manifest(root, source_type="system_runtime", app_version="0.0-stale")
    manifest_path = write_integrity_manifest(manifest, root / "integrity_manifest.json")

    tracked.write_text("VALUE = 2\n", encoding="utf-8")
    result = verify_integrity_manifest(manifest_path, root=root)

    assert result.overall_status == "modified"
    assert result.mismatched_count == 1
    assert any(item["field"] == "app_version" for item in result.mismatch_details)


def test_wrong_manifest_source_type_is_incompatible(tmp_path: Path) -> None:
    root = tmp_path / "runtime"
    root.mkdir()
    (root / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    manifest = create_integrity_manifest(root, source_type="source_tree")
    manifest_path = write_integrity_manifest(manifest, root / "msaa_integrity_manifest.json")

    result = verify_integrity_manifest(manifest_path, root=root, expected_source_type="pyinstaller_app")

    assert result.overall_status == "incompatible_manifest"
    assert result.health_impact == "degraded"
    assert result.mismatch_details[0]["field"] == "source_type"


def test_source_integrity_does_not_auto_trust_when_missing() -> None:
    result = verify_source_integrity(MemoryStore(), initialize=True)

    assert result["overall_status"] == "unknown"
    assert result["status"] == "unknown"
    assert result["trust_state"] == "unknown"
    assert "No trusted source integrity manifest exists." in result["errors"]


def test_legacy_source_integrity_schema_is_stale_not_modified() -> None:
    store = MemoryStore()
    store.set_background_monitor_state(
        "source_integrity_manifest_v1",
        json.dumps(
            {
                "schema": "mac-audit-agent-source-integrity-v1",
                "files": {"mac_audit_agent/module.py": {"sha256": "old"}},
                "trust_state": "trusted",
            }
        ),
    )

    result = verify_source_integrity(store)

    assert result["overall_status"] == "stale"
    assert result["tamper_detected"] is False


def test_source_tree_mode_without_git_metadata_is_unknown(tmp_path: Path) -> None:
    root = tmp_path / "not-git"
    root.mkdir()
    (root / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    manifest = create_integrity_manifest(root, source_type="source_tree")
    manifest_path = write_integrity_manifest(manifest, root / "msaa_integrity_manifest.json")

    result = verify_integrity_manifest(manifest_path, root=root)

    assert result.overall_status == "verified"
    assert result.health_impact == "healthy"


def test_matching_manifest_with_excluded_mutable_changes_stays_verified(tmp_path: Path) -> None:
    root = tmp_path / "project"
    package = root / "mac_audit_agent"
    package.mkdir(parents=True)
    (package / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    (root / "logs").mkdir()
    (root / "logs" / "monitor.log").write_text("first", encoding="utf-8")
    (root / "audit.sqlite3").write_text("first", encoding="utf-8")
    (root / "settings.json").write_text("{}", encoding="utf-8")
    manifest = create_integrity_manifest(root, source_type="system_runtime")
    manifest_path = write_integrity_manifest(manifest, root / "integrity_manifest.json")

    (root / "logs" / "monitor.log").write_text("changed", encoding="utf-8")
    (root / "audit.sqlite3").write_text("changed", encoding="utf-8")
    (root / "settings.json").write_text('{"changed": true}', encoding="utf-8")
    result = verify_integrity_manifest(manifest_path, root=root)

    assert result.overall_status == "verified"
    assert result.health_impact == "healthy"
    assert result.mismatched_count == 0
    checked_paths = {item["relative_path"] for item in result.file_results}
    assert "logs/monitor.log" not in checked_paths
    assert "audit.sqlite3" not in checked_paths
    assert "settings.json" not in checked_paths


def test_build_id_matches_current_build_does_not_return_stale(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "runtime"
    root.mkdir()
    (root / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    monkeypatch.setenv("MSAA_BUILD_ID", "build-123")
    manifest = create_integrity_manifest(root, source_type="system_runtime", build_id="build-123")
    manifest_path = write_integrity_manifest(manifest, root / "integrity_manifest.json")

    result = verify_integrity_manifest(manifest_path, root=root)

    assert result.overall_status == "verified"
    assert result.manifest_build_id == "build-123"
    assert result.current_build_id == "build-123"


def test_build_id_mismatch_is_stale_with_exact_reason(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "runtime"
    root.mkdir()
    (root / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    monkeypatch.setenv("MSAA_BUILD_ID", "current-build")
    manifest = create_integrity_manifest(root, source_type="system_runtime", build_id="old-build")
    manifest_path = write_integrity_manifest(manifest, root / "integrity_manifest.json")

    result = verify_integrity_manifest(manifest_path, root=root)

    assert result.overall_status == "stale"
    assert result.mismatch_details[0]["field"] == "build_id"
    assert "old-build" in result.exact_mismatch_reason


def test_required_file_hash_mismatch_has_actionable_exact_reason(tmp_path: Path) -> None:
    root = tmp_path / "runtime"
    root.mkdir()
    tracked = root / "mac_audit_agent_app.py"
    tracked.write_text("VALUE = 1\n", encoding="utf-8")
    manifest = create_integrity_manifest(root, source_type="system_runtime")
    manifest_path = write_integrity_manifest(manifest, root / "integrity_manifest.json")

    tracked.write_text("VALUE = 2\n", encoding="utf-8")
    result = verify_integrity_manifest(manifest_path, root=root)

    assert result.overall_status == "modified"
    assert result.exact_mismatch_reason == "Required file hash mismatch detected: mac_audit_agent_app.py."
    assert result.mismatch_details[0]["field"] == "required_file_mismatch"


def test_missing_optional_manifest_entry_is_warning_not_modified(tmp_path: Path) -> None:
    root = tmp_path / "runtime"
    root.mkdir()
    required = root / "required.py"
    optional = root / "optional.txt"
    required.write_text("VALUE = 1\n", encoding="utf-8")
    optional.write_text("optional\n", encoding="utf-8")
    manifest = create_integrity_manifest(root, source_type="system_runtime")
    for entry in manifest.file_entries:
        if entry.relative_path == "optional.txt":
            entry.required = False
    manifest.manifest_hash = ""
    manifest_path = write_integrity_manifest(manifest, root / "integrity_manifest.json")

    optional.unlink()
    result = verify_integrity_manifest(manifest_path, root=root)

    assert result.overall_status == "verified_with_warnings"
    assert result.missing_count == 0
    assert any("Optional manifest file missing: optional.txt." in warning for warning in result.warnings)


def test_manifest_selection_uses_active_source_mode_and_ignores_wrong_mode_manifest(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    (root / ".git").mkdir()
    (root / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    source_manifest = write_integrity_manifest(create_integrity_manifest(root, source_type="source_tree"), root / "msaa_integrity_manifest.json")
    write_integrity_manifest(create_integrity_manifest(root, source_type="pyinstaller_app"), root / "integrity_manifest.json")

    selection = select_integrity_manifest(root, install_mode="source_tree")
    result = verify_current_install_integrity(root, install_mode="source_tree", bypass_cache=True)

    assert selection.manifest_path == source_manifest
    assert selection.expected_source_type == "source_tree"
    assert any(item["source_type"] == "pyinstaller_app" for item in result.ignored_manifests)
    assert result.overall_status in {"verified", "verified_with_warnings"}


def test_manifest_selection_uses_bundled_pyinstaller_manifest(tmp_path: Path) -> None:
    root = tmp_path / "app"
    root.mkdir()
    (root / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    bundled = write_integrity_manifest(create_integrity_manifest(root, source_type="pyinstaller_app"), root / "integrity_manifest.json")
    write_integrity_manifest(create_integrity_manifest(root, source_type="source_tree"), root / "msaa_integrity_manifest.json")

    selection = select_integrity_manifest(root, install_mode="pyinstaller_app")
    result = verify_current_install_integrity(root, install_mode="pyinstaller_app", bypass_cache=True)

    assert selection.manifest_path == bundled
    assert selection.expected_source_type == "pyinstaller_app"
    assert result.current_install_mode == "pyinstaller_app"
    assert result.overall_status == "verified"


def test_manifest_selection_uses_package_manifest_for_pip_package(tmp_path: Path) -> None:
    root = tmp_path / "package"
    root.mkdir()
    (root / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    package_manifest = write_integrity_manifest(create_integrity_manifest(root, source_type="pip_package"), root / "package_integrity_manifest.json")
    write_integrity_manifest(create_integrity_manifest(root, source_type="source_tree"), root / "msaa_integrity_manifest.json")

    selection = select_integrity_manifest(root, install_mode="pip_package")
    result = verify_current_install_integrity(root, install_mode="pip_package", bypass_cache=True)

    assert selection.manifest_path == package_manifest
    assert selection.expected_source_type == "pip_package"
    assert result.current_install_mode == "pip_package"
    assert result.overall_status == "verified"
    assert any(item["source_type"] == "source_tree" for item in result.ignored_manifests)


def test_manifest_selection_uses_canonical_system_runtime_path(tmp_path: Path) -> None:
    root = tmp_path / "runtime"
    root.mkdir()
    (root / "integrity_manifest.json").write_text("{}", encoding="utf-8")

    selection = select_integrity_manifest(root, install_mode="system_daemon_runtime")
    result = verify_current_install_integrity(root, install_mode="system_daemon_runtime", bypass_cache=True)

    assert selection.manifest_path == Path("/Library/Application Support/MacAuditAgent/runtime/integrity_manifest.json")
    assert selection.expected_source_type == "system_daemon_runtime"
    assert result.overall_status in {"unknown", "failed"}
    assert result.cache_invalidated_reason == "bypassed"


def test_manifest_selection_uses_canonical_user_notifier_runtime_path(tmp_path: Path) -> None:
    root = tmp_path / "runtime"
    root.mkdir()
    (root / "integrity_manifest.json").write_text("{}", encoding="utf-8")

    selection = select_integrity_manifest(root, install_mode="user_notifier_runtime")

    assert selection.manifest_path == Path.home() / "Library" / "Application Support" / "MacAuditAgent" / "runtime" / "integrity_manifest.json"
    assert selection.expected_source_type == "user_notifier_runtime"


def test_verify_now_bypass_records_cache_invalidation_reason(tmp_path: Path) -> None:
    root = tmp_path / "runtime"
    root.mkdir()
    (root / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    manifest_path = write_integrity_manifest(create_integrity_manifest(root, source_type="system_runtime"), root / "integrity_manifest.json")

    result = verify_integrity_manifest(manifest_path, root=root, bypass_cache=True)

    assert result.cached_result is False
    assert result.cache_valid is True
    assert result.cache_invalidated_reason == "bypassed"
    payload = result.to_dict()
    assert payload["verification_result_id"] == payload["result_id"]
    assert payload["verified_at"] == payload["checked_at"]
    assert payload["manifest_created_at"]


def test_new_trusted_manifest_clears_stale_mismatch_after_verification(tmp_path: Path) -> None:
    root = tmp_path / "runtime"
    root.mkdir()
    (root / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    manifest_path = write_integrity_manifest(create_integrity_manifest(root, source_type="system_runtime", app_version="0.0-stale"), root / "integrity_manifest.json")
    stale = verify_integrity_manifest(manifest_path, root=root, bypass_cache=True)
    assert stale.overall_status == "stale"

    fresh_manifest = create_integrity_manifest(root, source_type="system_runtime", app_version=APP_VERSION)
    write_integrity_manifest(fresh_manifest, manifest_path)
    fresh = verify_integrity_manifest(manifest_path, root=root, bypass_cache=True)

    assert fresh.overall_status == "verified"
    assert fresh.exact_mismatch_reason == ""
    assert fresh.cache_invalidated_reason == "bypassed"


def test_build_identity_uses_stable_non_temp_build_id(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("MSAA_BUILD_ID", "stable-build")
    identity = detect_build_identity(tmp_path, install_mode="pyinstaller_app")

    assert identity.build_id == "stable-build"
    assert str(tmp_path) not in identity.build_id


def test_build_identity_detects_app_and_package_version(tmp_path: Path) -> None:
    identity = detect_build_identity(tmp_path, install_mode="pip_package")

    assert identity.app_version == APP_VERSION
    assert identity.package_name == "mac-audit-agent"
    assert identity.build_id


def test_package_and_pyinstaller_modes_return_structured_results(tmp_path: Path) -> None:
    wheel_result = verify_wheel_record("definitely-not-installed-msaa-test-package")
    assert wheel_result["overall_status"] == "unknown"
    assert wheel_result["source_type"] == "pypi_wheel"

    app_root = tmp_path / "app"
    app_root.mkdir()
    result = verify_pyinstaller_app(root=app_root)
    assert result.overall_status == "unknown"
    assert result.source_type == "unknown"
