from __future__ import annotations

from pathlib import Path
from typing import Any

from mac_audit_agent.integrity.authority import IntegrityAuthority


def build_integrity_doctor_status(root: Path | None = None, **kwargs: Any) -> dict[str, Any]:
    """Return read-only integrity status for MSAA Doctor and GUI status panels."""
    policy = str(kwargs.get("policy") or "dev")
    return IntegrityAuthority(Path(root or Path.cwd()).resolve(strict=False), policy).doctor()


__all__ = ["build_integrity_doctor_status"]
