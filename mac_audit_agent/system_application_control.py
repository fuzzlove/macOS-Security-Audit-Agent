from __future__ import annotations

import json
import os
import plistlib
import shutil
import signal
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from mac_audit_agent.not_signed.actions import hash_file
from mac_audit_agent.not_signed.models import InstalledSoftwareItem,ProcessRecord,SoftwareTrustClassification
from mac_audit_agent.not_signed.protected_items import protected_process
from mac_audit_agent.application_removal import _identity_matches

SEALED_ROOTS = (Path("/System"), Path("/usr"), Path("/bin"), Path("/sbin"))
CRITICAL_BUNDLE_IDS={"com.apple.finder","com.apple.systempreferences","com.apple.loginwindow","com.apple.SecurityAgent","com.apple.DiskUtility"}
CRITICAL_NAMES={"Finder","System Settings","System Preferences","SecurityAgent","loginwindow","Disk Utility"}
SYSTEM_QUARANTINE=Path("/Library/Application Support/MSAA/Disabled Applications")


@dataclass(frozen=True)
class DependencyImpact:
    dependency_type:str; identifier:str; impact:str; severity:str; evidence:str; validation_required:str


@dataclass(frozen=True)
class SystemApplicationControlPlan:
    plan_id:str;item_id:str;display_name:str;bundle_identifier:str;application_path:str;application_hash:str;signing_classification:str;team_identifier:str;action:str;platform_classification:str;sealed_system_volume:bool;critical_component:bool;requires_administrator:bool;administrator_active:bool;allowed:bool;refusal_reason:str;dependency_impacts:tuple[DependencyImpact,...];processes:tuple[ProcessRecord,...];persistence_paths:tuple[str,...];quarantine_path:str;rollback_available:bool;warnings:tuple[str,...];created_at:str
    def to_dict(self):return asdict(self)


@dataclass(frozen=True)
class SystemApplicationControlReceipt:
    plan_id:str;action:str;status:str;original_path:str;quarantine_path:str;terminated_pids:tuple[int,...];forced_pids:tuple[int,...];dependency_impacts:tuple[dict,...];errors:tuple[str,...];rollback_manifest:str;audit_event:str;completed_at:str
    def to_dict(self):return asdict(self)


def _under(path:Path,root:Path)->bool:return path==root or root in path.parents


def _dependency_impacts(item:InstalledSoftwareItem,target:Path)->tuple[DependencyImpact,...]:
    impacts=[];identifier=item.bundle_identifier or target.stem
    impacts.append(DependencyImpact("unknown_reverse_dependencies",identifier,"Other applications, automations, documents, URL handlers, or administrative workflows may depend on this application.","high","macOS does not provide a complete authoritative reverse dependency graph for application bundles.","Review MDM profiles, scripts, LaunchServices handlers, business workflows, package receipts, and recent process/file/network evidence."))
    info=target/"Contents/Info.plist"
    try:payload=plistlib.loads(info.read_bytes()) if info.stat().st_size<=2*1024*1024 else {}
    except (OSError,plistlib.InvalidFileException,ValueError):payload={}
    for key,label in (("CFBundleURLTypes","URL schemes"),("CFBundleDocumentTypes","document types"),("NSExtension","extensions"),("SMPrivilegedExecutables","privileged helpers")):
        if payload.get(key):impacts.append(DependencyImpact("declared_capability",key,f"Disabling may break registered {label}.","high",f"Info.plist declares {key}.",f"Review {key} registrations and dependent applications before proceeding."))
    for folder,label in ((target/"Contents/Library/LoginItems","login items"),(target/"Contents/XPCServices","XPC services"),(target/"Contents/Library/LaunchServices","launch services"),(target/"Contents/Frameworks","embedded frameworks"),(target/"Contents/PlugIns","plugins")):
        try:count=sum(1 for _ in folder.iterdir()) if folder.is_dir() else 0
        except OSError:count=0
        if count:impacts.append(DependencyImpact("embedded_component",str(folder),f"Disabling also removes availability of {count} embedded {label} component(s).","high",f"Bundle contains {count} entries under {folder.name}.","Identify active clients and validate replacement or rollback before disabling."))
    for persistence in item.persistence_items:impacts.append(DependencyImpact("launch_service",str(persistence.path),"A launch item references this application and will fail or repeatedly restart while it is disabled.","critical",f"Inventory associated {persistence.kind}: {persistence.label}.","Disable the exact launch item through an approved administrator workflow and preserve its prior state."))
    if item.signing.classification==SoftwareTrustClassification.APPLE_PLATFORM:impacts.append(DependencyImpact("apple_platform_integration",identifier,"Apple-signed components may participate in undocumented or release-specific operating-system workflows.","critical","The bundle is classified as Apple platform software.","Confirm with Apple deployment guidance and test recovery on an equivalent disposable host."))
    return tuple(impacts)


def create_system_application_control_plan(
    item: InstalledSoftwareItem,
    *,
    action: str = "disable",
    administrator_active: bool | None = None,
    quarantine_root: Path = SYSTEM_QUARANTINE,
    application_roots: tuple[Path, ...] = (Path("/Applications"),),
) -> SystemApplicationControlPlan:
    if action not in {"disable","remove"}:raise ValueError("unsupported system application action")
    target = (item.bundle_path or item.executable_path).resolve(strict=False)
    sealed = any(_under(target, root) for root in SEALED_ROOTS)
    critical = (item.bundle_identifier or "") in CRITICAL_BUNDLE_IDS or item.display_name in CRITICAL_NAMES
    eligible_root = any(target.parent == root.resolve(strict=False) for root in application_roots)
    admin = os.geteuid() == 0 if administrator_active is None else bool(administrator_active)
    requires_admin = eligible_root
    platform_classification="sealed_system_volume" if sealed else "system_installed_application" if eligible_root and (item.signing.classification==SoftwareTrustClassification.APPLE_PLATFORM or item.source=="system") else "non_system_application"
    refusal=""
    if sealed:refusal="This application is on the sealed system volume or another SIP-protected location. MSAA will not bypass SIP or authenticated-root protections."
    elif critical:refusal="This application is classified as a critical macOS component and cannot be disabled by this workflow."
    elif not eligible_root:refusal="System-application control is limited to top-level application bundles in /Applications."
    elif target.suffix.lower()!=".app" or target.is_symlink():refusal="Only canonical, non-symlink application bundles are eligible."
    elif requires_admin and not admin:refusal="Administrator execution is required to modify this system-installed application. Relaunch the approved MSAA administrative workflow."
    quarantine=quarantine_root/f"{item.item_id}-{target.name}"
    impacts=_dependency_impacts(item,target);warnings=("Dependency impact cannot be proven complete; review every listed and unknown dependency.","Disabling an Apple-signed application does not establish that it was malicious or backdoored.","Preserve evidence before containment and validate rollback on an equivalent host.")
    return SystemApplicationControlPlan(f"system-app-{uuid4().hex}",item.item_id,item.display_name,item.bundle_identifier or "",str(target),hash_file(item.executable_path),item.signing.classification.value,item.signing.team_identifier or "",action,platform_classification,sealed,critical,requires_admin,admin,not refusal,refusal,impacts,item.running_processes,tuple(str(v.path) for v in item.persistence_items),str(quarantine),not sealed and not critical,warnings,datetime.now(timezone.utc).isoformat())


def execute_system_application_control(
    plan: SystemApplicationControlPlan,
    *,
    grace_seconds: float = 5.0,
    application_roots: tuple[Path, ...] = (Path("/Applications"),),
    administrator_active: bool | None = None,
) -> SystemApplicationControlReceipt:
    if not plan.allowed:raise PermissionError(plan.refusal_reason or "System application control is not authorized.")
    admin = os.geteuid() == 0 if administrator_active is None else bool(administrator_active)
    if plan.requires_administrator and not admin:
        raise PermissionError("Administrator authorization through the approved privileged workflow is required.")
    source=Path(plan.application_path);destination=Path(plan.quarantine_path)
    approved_parents = {root.resolve(strict=False) for root in application_roots}
    if source.is_symlink() or source.parent not in approved_parents or source.suffix.lower() != ".app":
        raise PermissionError("Application path changed or is outside the approved boundary.")
    resolved=source.resolve(strict=True)
    if resolved!=source or any(_under(resolved,root) for root in SEALED_ROOTS):raise PermissionError("SIP or sealed-system target refused.")
    executable_candidates = list((source / "Contents/MacOS").glob("*"))[:20]
    observed_hash = ""
    for path in executable_candidates:
        if path.is_file():
            observed_hash = hash_file(path)
            if observed_hash:
                break
    if plan.application_hash and observed_hash and plan.application_hash!=observed_hash:raise PermissionError("Application executable hash changed after preview.")
    terminated=[];forced=[];errors=[];live=[]
    for process in plan.processes:
        blocked,reason=protected_process(process.pid,process.name,process.executable_path)
        if blocked or not _identity_matches(process):
            errors.append(f"PID {process.pid} retained: {reason or 'process identity changed after preview'}");continue
        try:os.kill(process.pid,signal.SIGTERM);live.append(process);terminated.append(process.pid)
        except ProcessLookupError:pass
        except OSError as exc:errors.append(f"PID {process.pid}: {exc}")
    deadline=time.monotonic()+max(.1,grace_seconds)
    while live and time.monotonic()<deadline:
        remaining=[]
        for process in live:
            try:os.kill(process.pid,0);remaining.append(process)
            except OSError:pass
        live=remaining
        if live:time.sleep(.1)
    for process in live:
        try:os.kill(process.pid,signal.SIGKILL);forced.append(process.pid)
        except OSError as exc:errors.append(f"PID {process.pid}: {exc}")
    destination.parent.mkdir(parents=True,exist_ok=True,mode=0o700);destination.parent.chmod(0o700)
    if destination.exists():raise FileExistsError("Quarantine destination already exists; no overwrite was attempted.")
    shutil.move(str(source),str(destination));destination.chmod(0o700)
    manifest=destination.parent/f"{plan.plan_id}-rollback.json";payload={"schema_version":"1.0","plan":plan.to_dict(),"original_path":str(source),"quarantine_path":str(destination),"disabled_at":datetime.now(timezone.utc).isoformat(),"rollback":{"requires_administrator":True,"destination_must_be_absent":True,"revalidate_hash_and_signature":True},"status":"DISABLED" if plan.action=="disable" else "REMOVED_TO_REVERSIBLE_QUARANTINE"};manifest.write_text(json.dumps(payload,indent=2,sort_keys=True,default=str)+"\n",encoding="utf-8");manifest.chmod(0o600)
    audit=destination.parent/f"{plan.plan_id}-audit.json";audit.write_text(json.dumps({"event":"system_application_control","action":plan.action,"plan_id":plan.plan_id,"timestamp":datetime.now(timezone.utc).isoformat(),"application_hash":plan.application_hash,"dependency_count":len(plan.dependency_impacts),"errors":errors},indent=2,sort_keys=True)+"\n",encoding="utf-8");audit.chmod(0o600)
    return SystemApplicationControlReceipt(plan.plan_id,plan.action,"success" if not errors else "partial",str(source),str(destination),tuple(terminated),tuple(forced),tuple(asdict(v) for v in plan.dependency_impacts),tuple(errors),str(manifest),str(audit),datetime.now(timezone.utc).isoformat())


def rollback_system_application_control(
    receipt: SystemApplicationControlReceipt,
    *,
    application_roots: tuple[Path, ...] = (Path("/Applications"),),
    administrator_active: bool | None = None,
) -> bool:
    source=Path(receipt.quarantine_path);destination=Path(receipt.original_path)
    admin = os.geteuid() == 0 if administrator_active is None else bool(administrator_active)
    if not admin:
        raise PermissionError("Administrator execution is required for rollback.")
    approved_parents = {root.resolve(strict=False) for root in application_roots}
    if not source.is_dir() or source.is_symlink() or destination.exists() or destination.parent not in approved_parents:
        raise PermissionError("Rollback paths failed revalidation.")
    shutil.move(str(source),str(destination));return destination.exists()
