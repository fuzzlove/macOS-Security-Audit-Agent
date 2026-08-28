from __future__ import annotations

import os
import resource
from pathlib import Path

from .environment import sanitized_user_environment
from .identity import InvokingUser


class PrivilegeDropError(PermissionError):
    pass


def _close_privileged_descriptors() -> None:
    """Close inherited descriptors other than stdin/stdout/stderr before identity change."""
    try:
        descriptors = [int(name) for name in os.listdir("/dev/fd") if name.isdigit()]
    except OSError:
        soft_limit = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
        descriptors = range(3, min(int(soft_limit), 65536))
    for descriptor in descriptors:
        if descriptor > 2:
            try:
                os.close(descriptor)
            except OSError:
                pass


def reexec_as_user(user: InvokingUser, executable: str, launcher: Path, arguments: list[str], result_path: Path) -> None:
    """Permanently discard root identity and replace the process before GUI imports."""
    if os.geteuid() != 0:
        raise PrivilegeDropError("privilege drop requires effective UID zero")
    temp_dir = Path(f"/private/tmp/msaa-{user.uid}")
    temp_dir.mkdir(mode=0o700, exist_ok=True)
    os.chown(temp_dir, user.uid, user.gid)
    os.chmod(temp_dir, 0o700)
    os.chdir(user.home_directory)
    _close_privileged_descriptors()
    os.setgroups([])
    os.initgroups(user.username, user.gid)
    if hasattr(os, "setresgid"):
        os.setresgid(user.gid, user.gid, user.gid)
    else:
        os.setgid(user.gid)
    if hasattr(os, "setresuid"):
        os.setresuid(user.uid, user.uid, user.uid)
    else:
        os.setuid(user.uid)
    if os.getuid() != user.uid or os.geteuid() != user.uid or os.getgid() != user.gid:
        raise PrivilegeDropError("identity verification failed after privilege drop")
    try:
        os.setuid(0)
    except PermissionError:
        pass
    else:
        raise PrivilegeDropError("root identity could be regained")
    env = sanitized_user_environment(user, bootstrap_result=result_path)
    os.execve(executable, [executable, str(launcher), *arguments], env)
    raise PrivilegeDropError("GUI re-exec unexpectedly returned")
