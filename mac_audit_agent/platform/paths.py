from __future__ import annotations

import os
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class PlatformPaths:
    immutable_resources: str; user_data: str; user_cache: str; user_logs: str; reports: str; temporary: str; system_data: str
    def to_dict(self) -> dict[str, str]: return asdict(self)


def resolve_platform_paths() -> PlatformPaths:
    home = Path.home(); resources = Path(__file__).resolve().parents[1]
    data = Path(os.environ.get("MSAA_USER_DATA_DIR", home / "Library/Application Support/MacAuditAgent"))
    return PlatformPaths(str(resources), str(data), str(home / "Library/Caches/MacAuditAgent"), str(home / "Library/Logs/MacAuditAgent"), str(data / "reports"), tempfile.gettempdir(), "/Library/Application Support/MacAuditAgent")


__all__ = ["PlatformPaths", "resolve_platform_paths"]
