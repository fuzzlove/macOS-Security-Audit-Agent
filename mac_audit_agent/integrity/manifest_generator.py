from __future__ import annotations

from pathlib import Path
from typing import Any

from mac_audit_agent.integrity.dev_manifest import build_manifest


def generate_source_manifest(policy: str, author: str, reason: str, build_id: str = "", *, root: Path | None = None) -> dict[str, Any]:
    return build_manifest(Path(root or Path.cwd()).resolve(strict=False), author=author, reason=reason, build_id=build_id, policy=policy)


__all__ = ["generate_source_manifest"]
