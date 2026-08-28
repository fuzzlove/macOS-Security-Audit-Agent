from __future__ import annotations

import hashlib
import os
import signal
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from .models import InstalledSoftwareItem, RemovalPlan
from .protected_items import protected_process, protected_path


def hash_file(path: Path, limit: int = 512 * 1024 * 1024) -> str:
    if path.is_symlink() or not path.is_file(): return ""
    digest = hashlib.sha256(); consumed = 0
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                consumed += len(chunk)
                if consumed > limit: return ""
                digest.update(chunk)
    except OSError: return ""
    return digest.hexdigest()


def create_removal_plan(item: InstalledSoftwareItem, *, privileged_helper_available: bool = False) -> RemovalPlan:
    protected, reason = protected_path(item.bundle_path or item.executable_path)
    warnings: list[str] = []
    if protected: warnings.append(reason)
    if item.running_processes: warnings.append("Running processes will be revalidated and stopped gracefully before removal.")
    if item.persistence_items: warnings.append("Confirmed persistence will be disabled before moving files.")
    selected = tuple(file for file in item.associated_files if file.confidence in {"Confirmed", "High Confidence"} and not file.user_data)
    excluded = tuple(file for file in item.associated_files if file not in selected)
    requires_admin = any(process.privileged for process in item.running_processes) or str(item.bundle_path or item.executable_path).startswith("/Library/")
    return RemovalPlan(f"removal-{uuid4().hex}", item.item_id, item.display_name, hash_file(item.executable_path), item.running_processes, item.persistence_items, selected, excluded, requires_admin, privileged_helper_available, not requires_admin and not protected, item.size_bytes, tuple(warnings), datetime.now(timezone.utc).isoformat())


def terminate_process(pid: int, expected_start: str, expected_executable: Path, *, force: bool = False) -> tuple[bool, str]:
    if pid <= 1: return False, "Protected PID."
    try:
        import subprocess
        row = subprocess.run(["/bin/ps", "-p", str(pid), "-o", "lstart=,comm="], capture_output=True, text=True, timeout=3, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc: return False, str(exc)
    current = row.stdout.strip()
    if row.returncode or not current: return False, "Process is no longer running."
    if expected_start and expected_start not in current: return False, "PID reuse detected: start time changed."
    if str(expected_executable) not in current: return False, "Process executable identity changed."
    protected, reason = protected_process(pid, expected_executable.name, expected_executable)
    if protected: return False, reason
    try: os.kill(pid, signal.SIGKILL if force else signal.SIGTERM)
    except OSError as exc: return False, str(exc)
    return True, "Force termination requested." if force else "Graceful termination requested."


def move_application_to_trash(item: InstalledSoftwareItem) -> tuple[bool, str]:
    target = item.bundle_path or item.executable_path
    protected, reason = protected_path(target)
    if protected or item.protected:
        return False, item.protection_reason or reason or "Protected software cannot be removed."
    try:
        source = target.resolve(strict=True)
    except OSError as exc:
        return False, f"Application identity could not be revalidated: {exc}"
    if target.is_symlink() or not source.exists():
        return False, "Symlink or missing application refused."
    trash = Path.home() / ".Trash"
    trash.mkdir(mode=0o700, exist_ok=True)
    destination = trash / source.name
    if destination.exists():
        destination = trash / f"{source.stem}-{uuid4().hex[:8]}{source.suffix}"
    try:
        shutil.move(str(source), str(destination))
        manifest_root = Path.home() / "Library/Application Support/MSAA/NotSigned/removal_manifests"
        manifest_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        manifest = manifest_root / f"{uuid4().hex}.json"
        manifest.write_text(json.dumps({
            "item_id": item.item_id, "display_name": item.display_name,
            "original_path": str(source), "trash_path": str(destination),
            "classification": item.signing.classification.value,
            "team_identifier": item.signing.team_identifier,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "reversible": True,
        }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except OSError as exc:
        return False, f"Move to Trash failed; no privileged fallback was attempted: {exc}"
    return True, f"Moved to Trash: {destination}\nRemoval manifest: {manifest}"


def force_disable_software(item: InstalledSoftwareItem) -> dict:
    """Force-stop exact processes and reversibly disable user persistence.

    System/SIP/MSAA targets and privileged persistence are never modified by
    this user-context workflow.
    """
    target = item.bundle_path or item.executable_path
    protected, reason = protected_path(target)
    if protected or item.protected:
        raise PermissionError(item.protection_reason or reason or "Protected software cannot be disabled.")
    terminated: list[int] = []
    errors: list[str] = []
    for process in item.running_processes:
        ok, message = terminate_process(process.pid, process.start_time, process.executable_path, force=True)
        if ok:
            terminated.append(process.pid)
        else:
            errors.append(f"PID {process.pid}: {message}")

    root = Path.home() / "Library/Application Support/MSAA/NotSigned/disabled" / f"{item.item_id}-{uuid4().hex[:8]}"
    persistence_root = Path.home() / "Library/LaunchAgents"
    disabled_persistence: list[dict[str, str]] = []
    for record in item.persistence_items:
        source = record.path
        try:
            resolved = source.resolve(strict=True)
        except OSError as exc:
            errors.append(f"{source}: {exc}")
            continue
        if source.is_symlink() or resolved.parent != persistence_root:
            errors.append(f"{source}: administrator review required; only exact user LaunchAgents can be disabled here")
            continue
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        destination = root / resolved.name
        if destination.exists():
            errors.append(f"{source}: quarantine destination already exists")
            continue
        try:
            shutil.move(str(resolved), str(destination))
            disabled_persistence.append({"original_path": str(resolved), "disabled_path": str(destination), "label": record.label})
        except OSError as exc:
            errors.append(f"{source}: {exc}")

    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    manifest = root / "disable-manifest.json"
    payload = {
        "schema_version": "1.0", "operation": "force_disable", "item_id": item.item_id,
        "display_name": item.display_name, "target": str(target), "terminated_pids": terminated,
        "disabled_persistence": disabled_persistence, "errors": errors, "application_removed": False,
        "manual_launch_still_possible": True, "reversible": True, "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    manifest.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    payload["manifest"] = str(manifest)
    payload["status"] = "success" if not errors else "partial"
    return payload


def force_uninstall_to_trash(item: InstalledSoftwareItem) -> dict:
    """Force-disable exact active components, then move the app to Trash."""
    disable = force_disable_software(item)
    moved, message = move_application_to_trash(item)
    return {
        "operation": "force_uninstall_to_trash", "status": "success" if moved and disable["status"] == "success" else "partial" if moved else "failed",
        "disable": disable, "application_moved_to_trash": moved, "message": message,
        "permanent_deletion": False, "reversible": moved,
    }


__all__ = [
    "create_removal_plan", "force_disable_software", "force_uninstall_to_trash",
    "hash_file", "move_application_to_trash", "terminate_process",
]
