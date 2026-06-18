from __future__ import annotations

import subprocess
from datetime import datetime, timezone
from pathlib import Path


APP_VERSION = "0.1.1"
RUNTIME_MANIFEST_SCHEMA_VERSION = 1
DATABASE_SCHEMA_VERSION = 1


def utc_build_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def current_git_commit(root: Path | None = None) -> str:
    repo_root = root or Path(__file__).resolve().parent.parent
    try:
        result = subprocess.run(
            ["/usr/bin/git", "-C", str(repo_root), "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except Exception:
        return "unknown"
    commit = (result.stdout or "").strip()
    return commit if result.returncode == 0 and commit else "unknown"
