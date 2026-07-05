from __future__ import annotations

import os
import pwd
import stat
from pathlib import Path
from typing import Any

from mac_audit_agent.live_response.models import FileArtifact
from mac_audit_agent.models import utc_now_iso


MLRC_FILE_TARGETS = {
    "shell_history": [".bash_history", ".zsh_history", ".sh_history", ".history", ".fish_history", ".python_history"],
    "browser_artifacts": [
        "Library/Safari/History.db",
        "Library/Safari/Downloads.plist",
        "Library/Application Support/Google/Chrome/Default/History",
        "Library/Application Support/Microsoft Edge/Default/History",
        "Library/Application Support/Chromium/Default/History",
    ],
    "tcc": ["Library/Application Support/com.apple.TCC/TCC.db"],
}


def collect_gap_file_metadata(scope: str = "quick", *, max_items: int = 250) -> tuple[list[FileArtifact], list[str]]:
    """Collect metadata only for MLRC artifact classes MSAA does not fully model yet."""
    if scope == "quick":
        return [], ["Quick scope skipped MLRC gap file metadata collection."]
    artifacts: list[FileArtifact] = []
    warnings: list[str] = []
    for home in _user_homes():
        for category, relative_paths in MLRC_FILE_TARGETS.items():
            for relative in relative_paths:
                if len(artifacts) >= max_items:
                    warnings.append(f"File metadata limit reached: {max_items}")
                    return artifacts, warnings
                path = home / relative
                artifact = _metadata_artifact(path, category)
                if artifact:
                    artifacts.append(artifact)
    return artifacts, warnings


def _user_homes() -> list[Path]:
    homes: list[Path] = []
    for entry in pwd.getpwall():
        home = Path(entry.pw_dir)
        if str(home).startswith("/Users/") and home.exists():
            homes.append(home)
    return sorted(set(homes))


def _metadata_artifact(path: Path, category: str) -> FileArtifact | None:
    try:
        if not path.exists():
            return None
        st = path.stat()
        return FileArtifact(
            path=str(path),
            permissions=oct(stat.S_IMODE(st.st_mode)),
            owner=_owner(st.st_uid),
            modified_time=utc_now_iso() if not st.st_mtime else _iso_from_epoch(st.st_mtime),
            risk_flag=category,
            source=f"mlrc_gap_metadata_{category}",
        )
    except PermissionError:
        return FileArtifact(path=str(path), risk_flag=f"{category}:permission_denied", source=f"mlrc_gap_metadata_{category}")
    except OSError:
        return None


def _owner(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def _iso_from_epoch(value: float) -> str:
    from datetime import datetime, timezone

    return datetime.fromtimestamp(value, timezone.utc).isoformat().replace("+00:00", "Z")


def overlap_warnings() -> list[dict[str, Any]]:
    return [
        {"module": "processes", "message": "Overlapping MSAA subsystem detected - using MSAA process inventory instead of MLRC ps commands."},
        {"module": "network", "message": "Overlapping MSAA subsystem detected - using Network Intelligence instead of MLRC netstat/lsof commands."},
        {"module": "launch_services", "message": "Overlapping MSAA subsystem detected - using Persistence Intelligence and MSAA launch snapshots."},
        {"module": "usb", "message": "Overlapping MSAA subsystem detected - using MSAA device monitoring artifacts when available."},
        {"module": "reports", "message": "Overlapping MSAA subsystem detected - using MSAA report exporters instead of MLRC report.html."},
    ]


def safety_policy() -> dict[str, Any]:
    return {
        "read_only": True,
        "destructive_operations": False,
        "source_files_copied_by_default": False,
        "network_blocking": False,
        "persistence_removal": False,
        "fallback_collectors_require_gap": True,
    }
