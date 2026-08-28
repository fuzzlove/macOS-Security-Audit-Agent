"""Process-safe, re-entrant serialization for definition mutations."""

from __future__ import annotations

import errno
import fcntl
import os
from pathlib import Path
from typing import Self


class UpdateAlreadyRunning(RuntimeError):
    code = "UPDATE_ALREADY_RUNNING"


class DefinitionUpdateLock:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._descriptor: int | None = None
        self._depth = 0

    def __enter__(self) -> Self:
        if self._depth:
            self._depth += 1
            return self
        self.path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(descriptor)
            if exc.errno in {errno.EACCES, errno.EAGAIN}:
                raise UpdateAlreadyRunning("another malware-definition update is already running") from exc
            raise
        os.ftruncate(descriptor, 0)
        os.write(descriptor, f"pid={os.getpid()}\n".encode("ascii"))
        os.fsync(descriptor)
        self._descriptor = descriptor
        self._depth = 1
        return self

    def __exit__(self, _kind, _value, _traceback) -> None:
        if not self._depth:
            return
        self._depth -= 1
        if self._depth:
            return
        descriptor, self._descriptor = self._descriptor, None
        if descriptor is not None:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)


__all__ = ["DefinitionUpdateLock", "UpdateAlreadyRunning"]
