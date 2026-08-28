from __future__ import annotations

import os
import pwd
from pathlib import Path

import pytest

from mac_audit_agent.user_profiles import ProfileRole, UserProfile, current_profile, save_profile_metadata


def test_viewer_cannot_manage_daemon() -> None:
    profile = UserProfile("viewer", 501, "Viewer", "", ProfileRole.VIEWER, "test")
    assert profile.can("view_status")
    assert not profile.can("manage_system_daemon")


def test_profile_metadata_is_uid_bound_and_cannot_select_role(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("mac_audit_agent.user_profiles.profile_root", lambda: tmp_path / "profile")
    before = current_profile()
    saved = save_profile_metadata(display_name="Local Analyst", avatar_path="/tmp/avatar.png")
    assert saved.uid == os.getuid()
    assert saved.username == pwd.getpwuid(os.getuid()).pw_name
    assert saved.display_name == "Local Analyst"
    assert saved.role == before.role
    assert (tmp_path / "profile/profile.json").stat().st_mode & 0o777 == 0o600


def test_permission_denial_is_explicit(monkeypatch) -> None:
    viewer = UserProfile("viewer", 501, "Viewer", "", ProfileRole.VIEWER, "test")
    monkeypatch.setattr("mac_audit_agent.user_profiles.current_profile", lambda: viewer)
    from mac_audit_agent.user_profiles import require_permission
    with pytest.raises(PermissionError, match="PROFILE_PERMISSION_DENIED"):
        require_permission("manage_system_daemon")
