from __future__ import annotations

import os
import pwd
import subprocess
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class InvocationMode(str, Enum):
    NORMAL_USER_GUI = "normal_user_gui"
    SUDO_BOOTSTRAP_AND_GUI = "sudo_bootstrap_and_gui"
    DIRECT_ROOT_HEADLESS = "direct_root_headless"
    USER_HEADLESS = "user_headless"
    SERVICE_PROCESS = "service_process"


class IdentityError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class InvokingUser:
    username: str
    uid: int
    gid: int
    home_directory: Path
    shell: str
    console_session_active: bool
    source: str

    def to_dict(self) -> dict[str, object]:
        return {
            "username": self.username,
            "uid": self.uid,
            "gid": self.gid,
            "home_directory": str(self.home_directory),
            "shell": self.shell,
            "console_session_active": self.console_session_active,
            "source": self.source,
        }


def _bounded_id(value: str, name: str) -> int:
    if not value or not value.isascii() or not value.isdigit():
        raise IdentityError("BOOTSTRAP_INVALID_SUDO_IDENTITY", f"{name} is missing or invalid.")
    parsed = int(value, 10)
    if parsed <= 0 or parsed > 2_147_483_647:
        raise IdentityError("BOOTSTRAP_INVALID_SUDO_IDENTITY", f"{name} is outside the allowed non-root range.")
    return parsed


def active_console_user() -> tuple[str, int] | None:
    if os.uname().sysname != "Darwin":
        return None
    try:
        result = subprocess.run(
            ["/usr/bin/stat", "-f", "%Su:%u", "/dev/console"],
            capture_output=True, text=True, timeout=3, check=False,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
        )
        name, uid_text = result.stdout.strip().rsplit(":", 1)
        uid = int(uid_text)
        if result.returncode == 0 and name not in {"", "root", "loginwindow", "_mbsetupuser"} and uid > 0:
            return name, uid
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    return None


def _validated_account(uid: int, username: str, gid: int, *, source: str, console: tuple[str, int] | None) -> InvokingUser:
    try:
        record = pwd.getpwuid(uid)
    except KeyError as exc:
        raise IdentityError("BOOTSTRAP_INVALID_SUDO_IDENTITY", "The invoking UID does not resolve through the passwd database.") from exc
    if record.pw_name != username:
        raise IdentityError("BOOTSTRAP_INVALID_SUDO_IDENTITY", "SUDO_USER does not match SUDO_UID.")
    if record.pw_uid == 0 or record.pw_uid < 500 or record.pw_name.startswith("_"):
        raise IdentityError("BOOTSTRAP_INVALID_SUDO_IDENTITY", "A system or root account cannot be the GUI target.")
    if record.pw_gid != gid:
        raise IdentityError("BOOTSTRAP_INVALID_SUDO_IDENTITY", "SUDO_GID does not match the account primary group.")
    home = Path(record.pw_dir)
    if not home.is_absolute() or not home.is_dir() or home.is_symlink():
        raise IdentityError("BOOTSTRAP_INVALID_SUDO_IDENTITY", "The invoking account has no safe home directory.")
    active = console == (record.pw_name, record.pw_uid)
    if console is not None and not active:
        raise IdentityError("BOOTSTRAP_CONSOLE_USER_MISMATCH", "The sudo identity is not the active console user; specify a valid active target explicitly from a root shell.")
    return InvokingUser(record.pw_name, record.pw_uid, record.pw_gid, home.resolve(), record.pw_shell or "/bin/zsh", active, source)


def resolve_invocation(*, headless: bool, target_user: str | None = None, environ: dict[str, str] | None = None) -> tuple[InvocationMode, InvokingUser | None]:
    env = os.environ if environ is None else environ
    euid = os.geteuid()
    if euid != 0:
        record = pwd.getpwuid(os.getuid())
        user = InvokingUser(record.pw_name, record.pw_uid, record.pw_gid, Path(record.pw_dir), record.pw_shell, True, "current_process")
        return (InvocationMode.USER_HEADLESS if headless else InvocationMode.NORMAL_USER_GUI), user
    console = active_console_user()
    if env.get("SUDO_UID") or env.get("SUDO_USER") or env.get("SUDO_GID"):
        uid = _bounded_id(env.get("SUDO_UID", ""), "SUDO_UID")
        gid = _bounded_id(env.get("SUDO_GID", ""), "SUDO_GID")
        username = env.get("SUDO_USER", "")
        user = _validated_account(uid, username, gid, source="sudo", console=console)
        return (InvocationMode.DIRECT_ROOT_HEADLESS if headless else InvocationMode.SUDO_BOOTSTRAP_AND_GUI), user
    if target_user:
        try:
            record = pwd.getpwnam(target_user)
        except KeyError as exc:
            raise IdentityError("BOOTSTRAP_NO_GUI_USER", "The requested target user does not exist.") from exc
        user = _validated_account(record.pw_uid, record.pw_name, record.pw_gid, source="explicit_target", console=console)
        return (InvocationMode.DIRECT_ROOT_HEADLESS if headless else InvocationMode.SUDO_BOOTSTRAP_AND_GUI), user
    if headless:
        return InvocationMode.DIRECT_ROOT_HEADLESS, None
    raise IdentityError("BOOTSTRAP_NO_GUI_USER", "Direct root GUI launch has no validated non-root console user. Use a headless service command or --target-user.")
