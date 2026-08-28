from pathlib import Path

from mac_audit_agent.not_signed.actions import force_disable_software, force_uninstall_to_trash
from mac_audit_agent.not_signed.models import InstalledSoftwareItem, PersistenceRecord, SigningAssessment, SoftwareTrustClassification


def _item(root: Path) -> InstalledSoftwareItem:
    bundle = root / "Applications" / "Demo.app"
    executable = bundle / "Contents/MacOS/Demo"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"fixture")
    launch_agent = root / "Library/LaunchAgents/com.example.demo.plist"
    launch_agent.parent.mkdir(parents=True)
    launch_agent.write_text("fixture", encoding="utf-8")
    return InstalledSoftwareItem(
        "demo", "Demo", executable, bundle, "com.example.demo", "1", None,
        SigningAssessment(SoftwareTrustClassification.UNSIGNED, False, False, False),
        persistence_items=(PersistenceRecord("launch_agent", launch_agent, "com.example.demo", executable),),
    )


def test_force_disable_quarantines_only_user_persistence(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    item = _item(tmp_path)
    result = force_disable_software(item)
    assert result["status"] == "success"
    assert result["application_removed"] is False and item.bundle_path.exists()
    assert not item.persistence_items[0].path.exists()
    assert Path(result["manifest"]).is_file()


def test_force_uninstall_moves_app_to_trash_without_permanent_deletion(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    item = _item(tmp_path)
    result = force_uninstall_to_trash(item)
    assert result["application_moved_to_trash"] is True
    assert result["permanent_deletion"] is False and result["reversible"] is True
    assert not item.bundle_path.exists()


def test_force_controls_refuse_protected_software(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    item = _item(tmp_path)
    protected = InstalledSoftwareItem(**{**item.__dict__, "protected": True, "protection_reason": "protected fixture"})
    try:
        force_disable_software(protected)
    except PermissionError as exc:
        assert "protected fixture" in str(exc)
    else:
        raise AssertionError("protected software was not refused")
