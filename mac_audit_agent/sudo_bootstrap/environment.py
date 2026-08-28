from __future__ import annotations

import os
from pathlib import Path

from .identity import InvokingUser

SAFE_PATH = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
FORBIDDEN_PREFIXES = ("DYLD_", "LD_")
FORBIDDEN_NAMES = {
    "PYTHONPATH", "PYTHONHOME", "BASH_ENV", "ENV", "QT_PLUGIN_PATH",
    "QML2_IMPORT_PATH", "QT_QPA_PLATFORM_PLUGIN_PATH", "SUDO_COMMAND",
    "SUDO_USER", "SUDO_UID", "SUDO_GID", "CDPATH", "GLOBIGNORE",
}


def sanitized_user_environment(user: InvokingUser, *, bootstrap_result: Path | None = None, source: dict[str, str] | None = None) -> dict[str, str]:
    inherited = os.environ if source is None else source
    env: dict[str, str] = {
        "HOME": str(user.home_directory), "USER": user.username, "LOGNAME": user.username,
        "SHELL": user.shell, "PATH": SAFE_PATH,
        "LANG": inherited.get("LANG", "en_US.UTF-8"),
        "LC_CTYPE": inherited.get("LC_CTYPE", inherited.get("LANG", "en_US.UTF-8")),
        "TMPDIR": f"/private/tmp/msaa-{user.uid}",
        "MSAA_PRIVILEGE_DROPPED": "1",
    }
    if bootstrap_result is not None:
        env["MSAA_BOOTSTRAP_RESULT"] = str(bootstrap_result)
    return env


def forbidden_environment_names(source: dict[str, str] | None = None) -> tuple[str, ...]:
    inherited = os.environ if source is None else source
    return tuple(sorted(name for name in inherited if name in FORBIDDEN_NAMES or name.startswith(FORBIDDEN_PREFIXES)))
