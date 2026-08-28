"""GUI launch-mode selection and persistent crash-loop prevention."""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any


class GuiLaunchMode(str, Enum):
    APP_BUNDLE = "app_bundle"
    TERMINAL_DIRECT = "terminal_direct"
    TERMINAL_DIRECT_SAFE = "terminal_direct_safe"
    HEADLESS_ONLY = "headless_only"
    BLOCKED = "blocked"


@dataclass(frozen=True)
class GuiCrashMarker:
    python_version: str
    python_executable: str
    qt_version: str
    pyside_version: str
    launch_mode: str
    crash_signature: str
    timestamp: str


def crash_marker_path() -> Path:
    override = os.environ.get("MSAA_GUI_CRASH_MARKERS", "").strip()
    if override:
        return Path(override).expanduser()
    return Path.home() / "Library" / "Application Support" / "MacAuditAgent" / "runtime" / "gui_crash_markers.json"


def load_crash_markers(path: Path | None = None) -> list[dict[str, Any]]:
    target = path or crash_marker_path()
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return []
    return [item for item in payload if isinstance(item, dict)] if isinstance(payload, list) else []


def matching_crash_marker(*, python_executable: str, python_version: str, launch_mode: str, path: Path | None = None) -> dict[str, Any] | None:
    executable = os.path.realpath(python_executable)
    for marker in load_crash_markers(path):
        if (
            os.path.realpath(str(marker.get("python_executable", ""))) == executable
            and str(marker.get("python_version", "")) == python_version
            and str(marker.get("launch_mode", "")) == launch_mode
        ):
            return marker
    return None


def record_gui_crash(*, qt_version: str, pyside_version: str, launch_mode: str, crash_signature: str, path: Path | None = None) -> Path:
    target = path or crash_marker_path()
    marker = GuiCrashMarker(
        python_version=".".join(str(item) for item in sys.version_info[:3]),
        python_executable=os.path.realpath(sys.executable),
        qt_version=qt_version,
        pyside_version=pyside_version,
        launch_mode=launch_mode,
        crash_signature=crash_signature,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )
    markers = load_crash_markers(target)
    markers.append(asdict(marker))
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(markers[-50:], indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target


__all__ = ["GuiCrashMarker", "GuiLaunchMode", "crash_marker_path", "load_crash_markers", "matching_crash_marker", "record_gui_crash"]
