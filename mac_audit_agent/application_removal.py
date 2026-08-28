from __future__ import annotations

import json
import os
import shutil
import signal
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from mac_audit_agent.not_signed.models import InstalledSoftwareItem, ProcessRecord
from mac_audit_agent.not_signed.protected_items import protected_path, protected_process


@dataclass(frozen=True)
class ApplicationRemovalPlan:
    plan_id: str
    item_id: str
    display_name: str
    application_path: str
    bundle_identifier: str
    processes: tuple[ProcessRecord, ...]
    persistence_files: tuple[str, ...]
    remnants: tuple[str, ...]
    excluded_user_data: tuple[str, ...]
    requires_administrator: bool
    allowed: bool
    refusal_reason: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class ApplicationRemovalReceipt:
    plan_id: str
    status: str
    removed_paths: tuple[str, ...]
    retained_paths: tuple[str, ...]
    terminated_pids: tuple[int, ...]
    forced_pids: tuple[int, ...]
    errors: tuple[str, ...]
    trash_root: str
    completed_at: str

    def to_dict(self) -> dict:
        return asdict(self)


def _safe_child(root: Path, name: str) -> Path | None:
    if not name or name in {".", ".."} or "/" in name or "\0" in name:
        return None
    candidate = root / name
    return candidate if candidate.exists() and not candidate.is_symlink() else None


def discover_remnants(item: InstalledSoftwareItem) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
    """Return exact bundle-identity remnants and excluded document-like data."""
    identifier = (item.bundle_identifier or "").strip()
    names = {identifier} if identifier else set()
    if identifier:
        names.update({identifier + ".plist", identifier + ".savedState"})
    home_library = Path.home() / "Library"
    roots = (
        home_library / "Caches",
        home_library / "Preferences",
        home_library / "Logs",
        home_library / "Saved Application State",
        home_library / "HTTPStorages",
        home_library / "WebKit",
    )
    removable: list[Path] = []
    for root in roots:
        for name in names:
            candidate = _safe_child(root, name)
            if candidate is not None:
                removable.append(candidate)
    # Application Support and sandbox containers can contain irreplaceable user
    # documents. Show them in the preview, but never select them automatically.
    excluded: list[Path] = []
    for root in (home_library / "Application Support", home_library / "Containers", home_library / "Group Containers"):
        candidate = _safe_child(root, identifier)
        if candidate is not None:
            excluded.append(candidate)
    return tuple(dict.fromkeys(removable)), tuple(dict.fromkeys(excluded))


def create_application_removal_plan(item: InstalledSoftwareItem) -> ApplicationRemovalPlan:
    target = item.bundle_path or item.executable_path
    protected, reason = protected_path(target)
    try:
        resolved = target.resolve(strict=True)
    except OSError as exc:
        return ApplicationRemovalPlan(uuid4().hex, item.item_id, item.display_name, str(target), item.bundle_identifier or "", (), (), (), (), False, False, f"Application cannot be revalidated: {exc}")
    allowed_root = resolved.parent == Path("/Applications") or resolved.parent == Path.home() / "Applications"
    if resolved.suffix.lower() != ".app" or not allowed_root:
        protected, reason = True, reason or "Only top-level applications in /Applications or ~/Applications are eligible."
    remnants, excluded = discover_remnants(item)
    persistence = tuple(
        str(record.path) for record in item.persistence_items
        if record.path.parent == Path.home() / "Library/LaunchAgents" and not record.path.is_symlink()
    )
    privileged_persistence = any(record.path not in {Path(value) for value in persistence} for record in item.persistence_items)
    requires_admin = not os.access(resolved.parent, os.W_OK) or any(process.privileged for process in item.running_processes) or privileged_persistence
    return ApplicationRemovalPlan(
        uuid4().hex, item.item_id, item.display_name, str(resolved), item.bundle_identifier or "",
        item.running_processes, persistence, tuple(map(str, remnants)), tuple(map(str, excluded)), requires_admin,
        not protected and not requires_admin, reason if protected else ("Administrator-authorized helper is required for one or more selected paths or processes." if requires_admin else ""),
    )


def _identity_matches(process: ProcessRecord) -> bool:
    try:
        result = __import__("subprocess").run(
            ["/bin/ps", "-p", str(process.pid), "-o", "lstart=,comm="],
            capture_output=True, text=True, timeout=3, check=False,
        )
    except (OSError, __import__("subprocess").TimeoutExpired):
        return False
    current = result.stdout.strip()
    return bool(current and (not process.start_time or process.start_time in current) and str(process.executable_path) in current)


def execute_application_removal(plan: ApplicationRemovalPlan, *, grace_seconds: float = 5.0) -> ApplicationRemovalReceipt:
    if not plan.allowed:
        raise PermissionError(plan.refusal_reason or "Removal plan is not authorized.")
    target = Path(plan.application_path)
    protected, reason = protected_path(target)
    if protected or target.is_symlink() or target.resolve(strict=True) != target:
        raise PermissionError(reason or "Application identity changed after review.")

    terminated: list[int] = []
    forced: list[int] = []
    errors: list[str] = []
    live: list[ProcessRecord] = []
    for process in plan.processes:
        blocked, why = protected_process(process.pid, process.name, process.executable_path)
        if blocked or not _identity_matches(process):
            errors.append(f"PID {process.pid} was not stopped: {why or 'identity changed'}")
            continue
        try:
            os.kill(process.pid, signal.SIGTERM); live.append(process)
        except ProcessLookupError:
            pass
        except OSError as exc:
            errors.append(f"PID {process.pid}: {exc}")
    deadline = time.monotonic() + max(0.1, grace_seconds)
    while live and time.monotonic() < deadline:
        live = [process for process in live if _identity_matches(process)]
        if live: time.sleep(0.1)
    for process in live:
        if _identity_matches(process):
            try: os.kill(process.pid, signal.SIGKILL); forced.append(process.pid)
            except ProcessLookupError: pass
            except OSError as exc: errors.append(f"PID {process.pid}: {exc}")
    terminated.extend(process.pid for process in plan.processes if process.pid not in forced and not _identity_matches(process))

    trash_root = Path.home() / ".Trash" / f"MSAA-{target.stem}-{plan.plan_id[:8]}"
    trash_root.mkdir(parents=True, mode=0o700)
    removed: list[str] = []
    retained: list[str] = list(plan.excluded_user_data)
    for source in (target, *(Path(value) for value in plan.persistence_files), *(Path(value) for value in plan.remnants)):
        try:
            if not source.exists(): continue
            if source.is_symlink(): raise OSError("symlink refused")
            destination = trash_root / source.name
            if destination.exists(): destination = trash_root / f"{source.name}-{uuid4().hex[:8]}"
            shutil.move(str(source), str(destination)); removed.append(str(source))
        except OSError as exc:
            retained.append(str(source)); errors.append(f"{source}: {exc}")
    status = "success" if not errors and not target.exists() else "partial"
    receipt = ApplicationRemovalReceipt(plan.plan_id, status, tuple(removed), tuple(dict.fromkeys(retained)), tuple(terminated), tuple(forced), tuple(errors), str(trash_root), datetime.now(timezone.utc).isoformat())
    receipt_path = trash_root / "removal-receipt.json"
    receipt_path.write_text(json.dumps(receipt.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return receipt
