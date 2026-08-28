from __future__ import annotations

import grp
import json
import os
import pwd
import stat
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Any


class ProfileRole(str, Enum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    ADMINISTRATOR = "administrator"


ROLE_PERMISSIONS: dict[ProfileRole, frozenset[str]] = {
    ProfileRole.VIEWER: frozenset({"view_status", "view_reports"}),
    ProfileRole.ANALYST: frozenset({"view_status", "view_reports", "run_scans", "export_reports", "review_findings"}),
    ProfileRole.ADMINISTRATOR: frozenset({
        "view_status", "view_reports", "run_scans", "export_reports", "review_findings",
        "change_monitor_settings", "manage_system_daemon", "manage_profiles",
        "remediate_persistence",
    }),
}

SYSTEM_POLICY_PATH = Path("/Library/Application Support/MacAuditAgent/access_policy.json")


@dataclass(frozen=True)
class UserProfile:
    username: str
    uid: int
    display_name: str
    avatar_path: str
    role: ProfileRole
    role_source: str

    def can(self, permission: str) -> bool:
        return permission in ROLE_PERMISSIONS[self.role]

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self); payload["role"] = self.role.value
        payload["permissions"] = sorted(ROLE_PERMISSIONS[self.role])
        return payload


def profile_root() -> Path:
    return Path.home() / "Library/Application Support/MacAuditAgent/profile"


def _trusted_policy_roles(path: Path | None = None) -> dict[str, str]:
    path = path or SYSTEM_POLICY_PATH
    try:
        info = path.stat()
        mode = stat.S_IMODE(info.st_mode)
        if info.st_uid != 0 or mode & (stat.S_IWGRP | stat.S_IWOTH):
            return {}
        payload = json.loads(path.read_text(encoding="utf-8"))
        roles = payload.get("roles", {})
        return roles if isinstance(roles, dict) else {}
    except (OSError, ValueError, json.JSONDecodeError):
        return {}


def _os_admin(username: str) -> bool:
    try:
        return username in grp.getgrnam("admin").gr_mem or pwd.getpwnam(username).pw_gid == grp.getgrnam("admin").gr_gid
    except KeyError:
        return False


def current_profile() -> UserProfile:
    record = pwd.getpwuid(os.getuid())
    local_path = profile_root() / "profile.json"
    local: dict[str, Any] = {}
    try:
        candidate = json.loads(local_path.read_text(encoding="utf-8"))
        if isinstance(candidate, dict) and int(candidate.get("uid", -1)) == record.pw_uid:
            local = candidate
    except (OSError, ValueError, json.JSONDecodeError):
        pass
    policy_role = _trusted_policy_roles().get(record.pw_name, "")
    try:
        role = ProfileRole(policy_role)
        source = "root-owned MSAA policy"
    except ValueError:
        role = ProfileRole.ADMINISTRATOR if _os_admin(record.pw_name) else ProfileRole.ANALYST
        source = "macOS admin-group membership" if role is ProfileRole.ADMINISTRATOR else "macOS account default"
    return UserProfile(
        username=record.pw_name, uid=record.pw_uid,
        display_name=str(local.get("display_name") or record.pw_gecos.split(",")[0] or record.pw_name)[:80],
        avatar_path=str(local.get("avatar_path") or ""), role=role, role_source=source,
    )


def save_profile_metadata(*, display_name: str, avatar_path: str) -> UserProfile:
    profile = current_profile(); root = profile_root(); root.mkdir(parents=True, exist_ok=True)
    root.chmod(0o700)
    payload = {"schema_version": 1, "uid": profile.uid, "username": profile.username,
               "display_name": display_name.strip()[:80] or profile.username, "avatar_path": avatar_path}
    temporary = root / "profile.json.tmp"; destination = root / "profile.json"
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    temporary.chmod(0o600); os.replace(temporary, destination)
    return current_profile()


def require_permission(permission: str) -> UserProfile:
    profile = current_profile()
    if not profile.can(permission):
        raise PermissionError(f"PROFILE_PERMISSION_DENIED: {profile.role.value} cannot {permission.replace('_', ' ')}")
    return profile
