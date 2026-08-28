from __future__ import annotations

import hashlib
import json
import os
import plistlib
import shutil
import stat
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from mac_audit_agent.persistence_intelligence.models import PersistenceItem
from mac_audit_agent.user_profiles import require_permission


PROTECTED_LABELS = {"com.mac-audit-agent.monitor", "com.mac-audit-agent.user-notifier"}


@dataclass(frozen=True)
class RemovalPlan:
    allowed: bool
    path: str
    label: str
    impact: str
    administrator_required: bool
    refusal_reason: str = ""
    referenced_payload: str = ""
    tamper_flags: tuple[str, ...] = ()
    forced_removal_available: bool = False


def _file_flags(path: Path) -> tuple[str, ...]:
    try:
        flags = path.lstat().st_flags
    except (AttributeError, OSError):
        return ()
    known = (
        (getattr(stat, "UF_IMMUTABLE", 0), "user_immutable"),
        (getattr(stat, "UF_APPEND", 0), "user_append_only"),
        (getattr(stat, "SF_IMMUTABLE", 0), "system_immutable"),
        (getattr(stat, "SF_APPEND", 0), "system_append_only"),
    )
    return tuple(name for mask, name in known if mask and flags & mask)


def _referenced_payload(path: Path) -> str:
    if path.suffix.lower() != ".plist" or not path.is_file() or path.is_symlink():
        return ""
    try:
        payload = plistlib.loads(path.read_bytes())
    except (OSError, plistlib.InvalidFileException, ValueError):
        return ""
    program = payload.get("Program")
    arguments = payload.get("ProgramArguments")
    candidate = str(program or (arguments[0] if isinstance(arguments, list) and arguments else ""))
    return candidate if candidate.startswith("/") else ""


def _within(path: Path, root: Path) -> bool:
    try: path.resolve(strict=False).relative_to(root.resolve(strict=False)); return True
    except ValueError: return False


def plan_removal(item: PersistenceItem) -> RemovalPlan:
    raw = item.plist_path or item.path
    if not raw: return RemovalPlan(False, "", item.label, "", False, "No concrete persistence artifact path is available.")
    path = Path(raw).expanduser()
    if not path.is_absolute(): return RemovalPlan(False, str(path), item.label, "", False, "Relative paths cannot be remediated.")
    if path.is_symlink(): return RemovalPlan(False, str(path), item.label, "", False, "Symlink targets are never removed automatically.")
    label = (item.label or item.bundle_id or path.stem).strip()
    if label.startswith("com.apple.") or _within(path, Path("/System/Library")): return RemovalPlan(False, str(path), label, "", False, "Apple platform services are protected from in-app removal.")
    if label in PROTECTED_LABELS: return RemovalPlan(False, str(path), label, "", False, "MSAA protection services must be managed through Operational Health.")
    suffix = path.suffix.lower()
    supported_artifact = suffix in {".plist", ".kext", ".systemextension", ".dext"}
    user_library = Path.home() / "Library"
    if supported_artifact and _within(path, user_library):
        flags = _file_flags(path)
        return RemovalPlan(True, str(path), label, "Disables persistence for the current macOS user and may prevent the associated application from starting at login.", False, referenced_payload=_referenced_payload(path), tamper_flags=flags, forced_removal_available=bool(flags))
    # Persistence scanners cover more than LaunchAgents/LaunchDaemons (for
    # example login hooks, emond rules, extensions, and vendor helper plists).
    # Permit concrete third-party persistence artifacts anywhere below
    # /Library while continuing to refuse Apple's sealed /System/Library tree.
    if supported_artifact and _within(path, Path("/Library")):
        flags = _file_flags(path)
        extension = item.mechanism in {"kernel_extension", "system_extension", "driver_extension"} or suffix in {".kext", ".systemextension", ".dext"}
        impact = "System-wide removal can break software, networking, security tools, drivers, or startup behavior for every user."
        if extension:
            impact += " A loaded extension may remain active until restart even after its on-disk bundle is quarantined."
        return RemovalPlan(True, str(path), label, impact, True, referenced_payload=_referenced_payload(path), tamper_flags=flags, forced_removal_available=extension or bool(flags))
    return RemovalPlan(False, str(path), label, "", False, "The artifact is outside MSAA's bounded persistence-remediation locations.")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    if path.is_file():
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""): digest.update(chunk)
    return digest.hexdigest()


def _clear_user_removal_flags(path: Path) -> tuple[int, int]:
    """Clear only owner-controlled flags; never weaken system security flags."""
    before = getattr(path.lstat(), "st_flags", 0)
    system_mask = getattr(stat, "SF_IMMUTABLE", 0) | getattr(stat, "SF_APPEND", 0)
    if before & system_mask:
        raise PermissionError("RECOVERY_REQUIRED: system immutable/append-only flags cannot be bypassed by MSAA. Preserve evidence and use an authorized recovery workflow.")
    user_mask = getattr(stat, "UF_IMMUTABLE", 0) | getattr(stat, "UF_APPEND", 0)
    after = before & ~user_mask
    if before != after:
        if not hasattr(os, "chflags"):
            raise PermissionError("FLAG_CLEAR_UNAVAILABLE: this runtime cannot clear owner-controlled file flags.")
        os.chflags(path, after, follow_symlinks=False)
    return before, after


def _safe_payload(item: PersistenceItem, payload: str) -> Path:
    target = Path(payload)
    if not target.is_absolute() or target.is_symlink() or not target.is_file():
        raise RuntimeError("PAYLOAD_REMEDIATION_REFUSED: referenced target is not an absolute regular file.")
    if _within(target, Path("/System")) or _within(target, Path("/usr/bin")) or _within(target, Path("/bin")) or _within(target, Path("/sbin")):
        raise RuntimeError("PAYLOAD_REMEDIATION_REFUSED: operating-system paths are never removed.")
    expected = item.target_hash_sha256
    if expected and _sha256(target) != expected:
        raise RuntimeError("PAYLOAD_REMEDIATION_REFUSED: referenced target hash changed after scanning.")
    return target


def quarantine_removal(
    item: PersistenceItem,
    *,
    include_referenced_payload: bool = False,
    force_stop_launchd_job: bool = False,
    force_unload_extension: bool = False,
    incident_reference: str = "",
) -> dict[str, object]:
    require_permission("remediate_persistence")
    plan = plan_removal(item); path = Path(plan.path)
    if not plan.allowed: raise RuntimeError(f"REMEDIATION_REFUSED: {plan.refusal_reason}")
    if plan.administrator_required and os.geteuid() != 0:
        raise PermissionError("ADMINISTRATOR_REQUIRED: system-wide persistence removal requires the authorized privileged workflow.")
    is_kernel_extension = item.mechanism == "kernel_extension" or path.suffix.lower() == ".kext"
    if force_unload_extension and not is_kernel_extension:
        raise RuntimeError("FORCED_EXTENSION_REMOVAL_REFUSED: forced kernel-extension unload is only available for an exact kernel-extension item.")
    if force_unload_extension and not incident_reference.strip():
        raise RuntimeError("INCIDENT_REFERENCE_REQUIRED: forced kernel-extension removal must be tied to an incident or change record.")
    if not path.exists(): raise FileNotFoundError(f"Artifact no longer exists: {path}")
    planned_target: Path | None = None
    if include_referenced_payload:
        if not plan.referenced_payload:
            raise RuntimeError("PAYLOAD_REMEDIATION_REFUSED: plist does not identify an absolute executable target.")
        planned_target = _safe_payload(item, plan.referenced_payload)
    case_id = f"remediation-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid4().hex[:8]}"
    destination = Path.home() / "Library/Application Support/MacAuditAgent/quarantine/remediation" / case_id
    destination.mkdir(parents=True, mode=0o700); backup = destination / path.name
    if path.is_dir(): shutil.copytree(path, backup, symlinks=True)
    else: shutil.copy2(path, backup)
    flags_before, flags_after = _clear_user_removal_flags(path)
    unload: dict[str, object] = {"attempted": False, "success": False, "domain": "", "stderr": "", "force_stop_attempted": False}
    extension_unload: dict[str, object] = {"attempted": False, "success": False, "bundle_id": plan.label, "stderr": "", "restart_required": False}
    if is_kernel_extension and force_unload_extension:
        command = ["/usr/bin/kmutil", "unload", "-b", plan.label]
        try:
            extension_result = subprocess.run(command, capture_output=True, text=True, check=False)
            extension_unload.update({
                "attempted": True,
                "success": extension_result.returncode == 0,
                "returncode": extension_result.returncode,
                "stderr": (extension_result.stderr or "")[-1000:],
                "restart_required": extension_result.returncode != 0,
            })
        except OSError as exc:
            extension_unload.update({"attempted": True, "stderr": f"{type(exc).__name__}: {exc}", "restart_required": True})
    if path.suffix.lower() == ".plist":
        try:
            payload = plistlib.loads(path.read_bytes()); label = str(payload.get("Label", ""))
        except (OSError, plistlib.InvalidFileException, ValueError) as exc:
            raise RuntimeError(f"REMEDIATION_REFUSED: invalid plist: {exc}") from exc
        if not label or label != plan.label: raise RuntimeError("REMEDIATION_REFUSED: selected label does not match plist Label.")
        domain = "system" if _within(path, Path("/Library/LaunchDaemons")) else f"gui/{os.getuid()}"
        command = ["/bin/launchctl", "bootout", f"{domain}/{label}"]
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        unload = {"attempted": True, "success": result.returncode in {0, 3, 113}, "domain": domain, "stderr": (result.stderr or "")[-1000:], "force_stop_attempted": False}
        if not unload["success"] and force_stop_launchd_job:
            service_target = f"{domain}/{label}"
            forced = subprocess.run(
                ["/bin/launchctl", "kill", "SIGKILL", service_target],
                capture_output=True,
                text=True,
                check=False,
            )
            unload.update({
                "force_stop_attempted": True,
                "force_stop_success": forced.returncode == 0,
                "force_stop_stderr": (forced.stderr or "")[-1000:],
            })
            if forced.returncode == 0:
                retried = subprocess.run(command, capture_output=True, text=True, check=False)
                unload.update({
                    "success": retried.returncode in {0, 3, 113},
                    "retry_returncode": retried.returncode,
                    "retry_stderr": (retried.stderr or "")[-1000:],
                })
        if not unload["success"]: raise RuntimeError("REMEDIATION_ABORTED: service could not be safely unloaded; backup retained.")
    removed = destination / "removed" / path.name; removed.parent.mkdir()
    shutil.move(str(path), str(removed))
    payload_evidence: dict[str, object] = {"requested": include_referenced_payload, "quarantined": False}
    if include_referenced_payload:
        assert planned_target is not None
        target = planned_target
        target_backup = destination / "payload_backup" / target.name
        target_backup.parent.mkdir()
        shutil.copy2(target, target_backup)
        target_flags_before, target_flags_after = _clear_user_removal_flags(target)
        target_removed = destination / "removed_payload" / target.name
        target_removed.parent.mkdir()
        shutil.move(str(target), str(target_removed))
        payload_evidence = {
            "requested": True, "quarantined": True, "source_path": str(target),
            "backup_path": str(target_backup), "quarantined_path": str(target_removed),
            "sha256": _sha256(target_backup), "flags_before": target_flags_before, "flags_after": target_flags_after,
        }
    evidence = {"case_id": case_id, "timestamp": datetime.now(timezone.utc).isoformat(), "plan": asdict(plan),
                "backup_path": str(backup), "quarantined_original": str(removed), "source_sha256": _sha256(backup), "unload": unload,
                "extension_unload": extension_unload, "incident_reference": incident_reference.strip(),
                "flags_before": flags_before, "flags_after": flags_after, "payload": payload_evidence,
                "restorable": True, "deleted": False}
    manifest = destination / "manifest.json"; manifest.write_text(json.dumps(evidence, indent=2, sort_keys=True), encoding="utf-8"); manifest.chmod(0o600)
    evidence["manifest_path"] = str(manifest); return evidence
