from __future__ import annotations

import os
import pwd
from dataclasses import dataclass
from pathlib import Path

from mac_audit_agent.sudo_bootstrap.identity import active_console_user


class TargetUserError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code


@dataclass(frozen=True)
class TargetDesktopUser:
    username: str
    uid: int
    gid: int
    home: Path
    gui_domain: str
    console_session_active: bool

    def to_dict(self) -> dict[str, object]:
        return {"username": self.username, "uid": self.uid, "gid": self.gid, "home": str(self.home), "gui_domain": self.gui_domain, "console_session_active": self.console_session_active}


def _numeric(value: str | int | None, field: str) -> int | None:
    if value is None or value == "":
        return None
    text = str(value)
    if not text.isascii() or not text.isdigit():
        raise TargetUserError("NOTIFIER_TARGET_USER_UNRESOLVED", f"{field} must be numeric.")
    parsed = int(text)
    if parsed < 0 or parsed > 2_147_483_647:
        raise TargetUserError("NOTIFIER_TARGET_USER_UNRESOLVED", f"{field} is outside the supported range.")
    return parsed


def resolve_target_desktop_user(*, username: str | None = None, uid: int | str | None = None, gid: int | str | None = None, home: Path | str | None = None, require_gui_session: bool = True, environ: dict[str, str] | None = None) -> TargetDesktopUser:
    env = os.environ if environ is None else environ
    username = username or env.get("MSAA_GUI_USER") or env.get("SUDO_USER")
    uid = uid if uid not in (None, "") else env.get("MSAA_GUI_UID") or env.get("SUDO_UID")
    gid = gid if gid not in (None, "") else env.get("MSAA_GUI_GID") or env.get("SUDO_GID")
    home = home if home not in (None, "") else env.get("MSAA_GUI_HOME")
    resolved_uid = _numeric(uid, "target UID")
    resolved_gid = _numeric(gid, "target GID")
    console = active_console_user()
    if username is None and resolved_uid is None and console is not None:
        username, resolved_uid = console
    if username is not None:
        try:
            record = pwd.getpwnam(username)
        except KeyError as exc:
            raise TargetUserError("NOTIFIER_TARGET_USER_UNRESOLVED", "Target username does not exist.") from exc
    elif resolved_uid is not None:
        try:
            record = pwd.getpwuid(resolved_uid)
        except KeyError as exc:
            raise TargetUserError("NOTIFIER_TARGET_USER_UNRESOLVED", "Target UID does not exist.") from exc
    elif os.geteuid() != 0:
        record = pwd.getpwuid(os.getuid())
    else:
        raise TargetUserError("NOTIFIER_TARGET_USER_UNRESOLVED", "No validated non-root desktop user was supplied or active.")
    if record.pw_uid == 0 or record.pw_dir == "/var/root" or record.pw_name == "root":
        raise TargetUserError("NOTIFIER_TARGET_USER_IS_ROOT", "The notifier must never target root.")
    if record.pw_uid < 500 or record.pw_name.startswith("_"):
        raise TargetUserError("NOTIFIER_TARGET_USER_UNRESOLVED", "System accounts cannot own the desktop notifier.")
    if resolved_uid is not None and record.pw_uid != resolved_uid:
        raise TargetUserError("NOTIFIER_TARGET_USER_UNRESOLVED", "Target username and UID do not match.")
    if resolved_gid is not None and record.pw_gid != resolved_gid:
        raise TargetUserError("NOTIFIER_TARGET_USER_UNRESOLVED", "Target GID does not match the directory-service record.")
    canonical_home = Path(record.pw_dir)
    if home is not None and Path(home) != canonical_home:
        raise TargetUserError("NOTIFIER_TARGET_HOME_INVALID", "Target home does not match the directory-service record.")
    if not canonical_home.is_absolute() or canonical_home == Path("/var/root") or not canonical_home.is_dir() or canonical_home.is_symlink():
        raise TargetUserError("NOTIFIER_TARGET_HOME_INVALID", "Target home must be an existing absolute non-symlink directory outside /var/root.")
    session_active = console == (record.pw_name, record.pw_uid)
    if require_gui_session and not session_active:
        raise TargetUserError("NOTIFIER_CONSOLE_SESSION_UNAVAILABLE", "The target user does not own the active graphical console session.")
    return TargetDesktopUser(record.pw_name, record.pw_uid, record.pw_gid, canonical_home.resolve(), f"gui/{record.pw_uid}", session_active)


__all__ = ["TargetDesktopUser", "TargetUserError", "resolve_target_desktop_user"]
