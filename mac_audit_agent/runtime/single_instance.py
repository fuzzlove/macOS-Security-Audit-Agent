from __future__ import annotations

import fcntl
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO


@dataclass
class SingleInstanceLock:
    name: str
    path: Path
    handle: TextIO | None = None
    activation_mtime_ns: int = 0

    @classmethod
    def for_app(cls, name: str = "mac-audit-agent-gui") -> "SingleInstanceLock":
        base = Path.home() / ".mac_audit_agent" / "state"
        return cls(name=name, path=base / f"{name}.lock")

    def acquire(self) -> bool:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = self.path.open("a+", encoding="utf-8")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            handle.close()
            return False
        handle.seek(0)
        handle.truncate()
        handle.write(f"{os.getpid()}\n")
        handle.flush()
        self.handle = handle
        try:
            self.activation_mtime_ns = self.activation_path.stat().st_mtime_ns
        except OSError:
            self.activation_mtime_ns = 0
        return True

    @property
    def activation_path(self) -> Path:
        return self.path.with_suffix(".activate")

    def request_activation(self) -> bool:
        """Ask the lock-owning GUI process to present its existing window."""
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(self.activation_path, flags, 0o600)
            try:
                os.write(descriptor, f"{os.getpid()} {time.time_ns()}\n".encode("ascii"))
            finally:
                os.close(descriptor)
            return True
        except OSError:
            return False

    def consume_activation_request(self) -> bool:
        try:
            modified = self.activation_path.stat().st_mtime_ns
        except OSError:
            return False
        if modified <= self.activation_mtime_ns:
            return False
        self.activation_mtime_ns = modified
        return True

    def release(self) -> None:
        if self.handle is None:
            return
        try:
            fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
        finally:
            self.handle.close()
            self.handle = None


__all__ = ["SingleInstanceLock"]
