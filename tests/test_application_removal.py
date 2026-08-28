from pathlib import Path

import pytest

from mac_audit_agent.application_removal import create_application_removal_plan, discover_remnants, execute_application_removal
from mac_audit_agent.not_signed.models import InstalledSoftwareItem, SigningAssessment, SoftwareTrustClassification


def item(bundle: Path, bundle_id: str = "com.example.demo") -> InstalledSoftwareItem:
    bundle.mkdir(parents=True, exist_ok=True)
    signing = SigningAssessment(SoftwareTrustClassification.DEVELOPER_ID_VALID, True, True, True)
    return InstalledSoftwareItem("id", "Demo", bundle, bundle, bundle_id, "1", None, signing)


def test_plan_refuses_system_and_non_application_locations(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    value = item(tmp_path / "Downloads" / "Demo.app")
    plan = create_application_removal_plan(value)
    assert not plan.allowed
    assert "top-level" in plan.refusal_reason


def test_exact_bundle_remnants_only_and_user_data_excluded(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    bundle = item(tmp_path / "Applications" / "Demo.app")
    cache = tmp_path / "Library/Caches/com.example.demo"; cache.mkdir(parents=True)
    lookalike = tmp_path / "Library/Caches/com.example.demo.attacker"; lookalike.mkdir()
    container = tmp_path / "Library/Containers/com.example.demo"; container.mkdir(parents=True)
    removable, excluded = discover_remnants(bundle)
    assert cache in removable and lookalike not in removable
    assert container in excluded and container not in removable


def test_user_application_removal_is_reversible_and_receipted(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    value = item(tmp_path / "Applications" / "Demo.app")
    cache = tmp_path / "Library/Caches/com.example.demo"; cache.mkdir(parents=True)
    plan = create_application_removal_plan(value)
    assert plan.allowed and not plan.requires_administrator
    receipt = execute_application_removal(plan, grace_seconds=0.1)
    assert receipt.status == "success"
    assert not value.bundle_path.exists() and not cache.exists()
    assert (Path(receipt.trash_root) / "removal-receipt.json").exists()


def test_disallowed_plan_cannot_execute(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    plan = create_application_removal_plan(item(tmp_path / "Downloads/Demo.app"))
    with pytest.raises(PermissionError): execute_application_removal(plan)
