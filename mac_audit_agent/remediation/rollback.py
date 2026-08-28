from __future__ import annotations

from pathlib import Path
from typing import Any

from .quarantine import restore_quarantine


def rollback_keylogger_quarantine(manifest_path: Path) -> dict[str, Any]:
    return restore_quarantine(manifest_path)


__all__ = ["rollback_keylogger_quarantine"]
