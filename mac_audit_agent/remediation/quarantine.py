from __future__ import annotations

import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from .evidence import sha256_file


def quarantine_path(path: Path, *, finding: dict[str, Any], root: Path | None = None) -> dict[str, Any]:
    if path.is_symlink():
        raise ValueError("Quarantine refuses symbolic links.")
    source = path.resolve(strict=True)
    protected = str(source).startswith(("/System/", "/usr/", "/bin/", "/sbin/"))
    if protected:
        raise PermissionError("Apple system and sealed-volume content cannot be quarantined.")
    quarantine = Path(root or _default_root())
    quarantine.mkdir(parents=True, exist_ok=True, mode=0o700)
    incident = quarantine / f"keylogger-{uuid4().hex}"
    incident.mkdir(mode=0o700)
    destination = incident / source.name
    info = source.stat()
    digest = sha256_file(source) if source.is_file() else ""
    shutil.move(str(source), str(destination))
    _remove_execution_bits(destination)
    manifest = {
        "quarantine_id": incident.name, "original_path": str(source), "quarantine_path": str(destination),
        "sha256": digest, "timestamp": datetime.now(timezone.utc).isoformat(),
        "detection_reason": "; ".join(str(item) for item in finding.get("signals", ())),
        "confidence": finding.get("confidence", ""), "permissions": oct(info.st_mode & 0o7777),
        "owner": {"uid": info.st_uid, "gid": info.st_gid}, "codesign_status": finding.get("evidence", {}).get("signature", {}),
        "finding_id": finding.get("finding_id", ""), "restorable": True,
    }
    (incident / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    return manifest


def restore_quarantine(manifest_path: Path) -> dict[str, Any]:
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    source = Path(payload["quarantine_path"]); destination = Path(payload["original_path"])
    if source.is_symlink() or not source.exists() or destination.exists():
        raise ValueError("Restore refused because identity changed or destination already exists.")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(source), str(destination))
    try:
        destination.chmod(int(str(payload.get("permissions", "0o600")), 8))
        owner = dict(payload.get("owner") or {})
        if os.geteuid() == 0 and "uid" in owner and "gid" in owner:
            os.chown(destination, int(owner["uid"]), int(owner["gid"]))
    except (OSError, TypeError, ValueError):
        payload["metadata_restore_warning"] = "The item was restored, but one or more ownership or mode attributes could not be reapplied."
    return {**payload, "restored_at": datetime.now(timezone.utc).isoformat(), "restored": True}


def _default_root() -> Path:
    system = Path("/Library/Application Support/MSAA/Quarantine")
    return system if os.access(system.parent, os.W_OK) else Path.home() / "Library/Application Support/MSAA/Quarantine"


def _remove_execution_bits(path: Path) -> None:
    for item in ([path] if path.is_file() else path.rglob("*")):
        try:
            if item.is_file() and not item.is_symlink():
                item.chmod(item.stat().st_mode & ~0o111)
        except OSError:
            continue


__all__ = ["quarantine_path", "restore_quarantine"]
