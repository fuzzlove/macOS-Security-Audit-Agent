import json
from pathlib import Path

import pytest

from mac_audit_agent.not_signed.models import (
    InstalledSoftwareItem,
    SigningAssessment,
    SoftwareTrustClassification,
)
from mac_audit_agent.system_application_control import (
    create_system_application_control_plan,
    execute_system_application_control,
    rollback_system_application_control,
)
from mac_audit_agent.system_application_control_cli import _load_plan


def _item(bundle: Path, *, name: str = "Vendor Utility", bundle_id: str = "com.vendor.utility") -> InstalledSoftwareItem:
    executable = bundle / "Contents/MacOS/utility"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"safe-test-fixture")
    signing = SigningAssessment(
        SoftwareTrustClassification.APPLE_PLATFORM,
        True,
        True,
        True,
        team_identifier="APPLE-TEST-FIXTURE",
    )
    return InstalledSoftwareItem(
        "system-item-1",
        name,
        executable,
        bundle,
        bundle_id,
        "1.0",
        None,
        signing,
        source="system",
    )


def test_dependency_warning_is_always_present(tmp_path: Path) -> None:
    root = tmp_path / "Applications"
    item = _item(root / "Vendor Utility.app")
    plan = create_system_application_control_plan(
        item,
        administrator_active=True,
        application_roots=(root,),
        quarantine_root=tmp_path / "quarantine",
    )
    assert plan.allowed
    assert any(value.dependency_type == "unknown_reverse_dependencies" for value in plan.dependency_impacts)
    assert any(value.dependency_type == "apple_platform_integration" for value in plan.dependency_impacts)


def test_administrator_authorization_is_required(tmp_path: Path) -> None:
    root = tmp_path / "Applications"
    plan = create_system_application_control_plan(
        _item(root / "Vendor Utility.app"),
        administrator_active=False,
        application_roots=(root,),
        quarantine_root=tmp_path / "quarantine",
    )
    assert not plan.allowed
    assert plan.requires_administrator
    assert "Administrator" in plan.refusal_reason
    with pytest.raises(PermissionError, match="Administrator"):
        execute_system_application_control(
            plan,
            administrator_active=False,
            application_roots=(root,),
        )


def test_disable_is_reversible_and_audited(tmp_path: Path) -> None:
    root = tmp_path / "Applications"
    original = root / "Vendor Utility.app"
    quarantine = tmp_path / "quarantine"
    plan = create_system_application_control_plan(
        _item(original),
        administrator_active=True,
        application_roots=(root,),
        quarantine_root=quarantine,
    )
    receipt = execute_system_application_control(
        plan,
        administrator_active=True,
        application_roots=(root,),
        grace_seconds=0.01,
    )
    assert receipt.status == "success"
    assert not original.exists()
    assert Path(receipt.quarantine_path).exists()
    assert Path(receipt.rollback_manifest).exists()
    assert Path(receipt.audit_event).exists()
    assert rollback_system_application_control(
        receipt,
        administrator_active=True,
        application_roots=(root,),
    )
    assert original.exists()


def test_critical_component_is_refused(tmp_path: Path) -> None:
    root = tmp_path / "Applications"
    plan = create_system_application_control_plan(
        _item(root / "Finder.app", name="Finder", bundle_id="com.apple.finder"),
        administrator_active=True,
        application_roots=(root,),
    )
    assert not plan.allowed
    assert plan.critical_component


def test_privileged_plan_loader_rejects_redirected_quarantine(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "Applications"
    plan = create_system_application_control_plan(
        _item(root / "Vendor Utility.app"),
        administrator_active=True,
        application_roots=(root,),
        quarantine_root=tmp_path / "attacker-selected-destination",
    )
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps({"schema_version": 1, "plan": plan.to_dict()}, default=str), encoding="utf-8")
    plan_path.chmod(0o600)
    monkeypatch.setattr("mac_audit_agent.system_application_control_cli.os.geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", str(plan_path.stat().st_uid))
    with pytest.raises(PermissionError, match="quarantine destination"):
        _load_plan(plan_path)


def test_symlink_bundle_is_refused(tmp_path: Path) -> None:
    root = tmp_path / "Applications"
    real = tmp_path / "real/Vendor Utility.app"
    item = _item(real)
    root.mkdir()
    link = root / "Vendor Utility.app"
    link.symlink_to(real, target_is_directory=True)
    linked_item = InstalledSoftwareItem(
        item.item_id,
        item.display_name,
        link / "Contents/MacOS/utility",
        link,
        item.bundle_identifier,
        item.version,
        None,
        item.signing,
        source="system",
    )
    plan = create_system_application_control_plan(
        linked_item,
        administrator_active=True,
        application_roots=(root,),
    )
    assert not plan.allowed
