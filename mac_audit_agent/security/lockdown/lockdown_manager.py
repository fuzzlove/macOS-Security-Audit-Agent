from __future__ import annotations

import json
import os
import platform
import shutil
import socket
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from mac_audit_agent.launch_agent import user_launchctl_uid

from .lockdown_audit import AuditChain, verify_evidence, write_evidence
from .lockdown_enforcement import LockdownEnforcer
from .lockdown_permissions import ActivationAuthorization
from .lockdown_policy import APPLE_DISCLAIMER, FEATURE_ID, PRODUCT_NAME, LockdownProfile, load_profile
from .lockdown_rollback import rollback_controls

SYSTEM_STATE_DIR = Path("/Library/Application Support/MSAA/lockdown")
USER_STATE_DIR = Path.home() / "Library/Application Support/MSAA/lockdown"


class LockdownManager:
    def __init__(self, state_dir: Path | None = None, *, runner: Callable[..., Any] | None = None, require_root: bool = True) -> None:
        self.state_dir = Path(state_dir or (SYSTEM_STATE_DIR if os.geteuid() == 0 else USER_STATE_DIR))
        self.runner = runner or subprocess.run
        self.require_root = require_root
        self.enforcer = LockdownEnforcer(self.runner)
        self.audit = AuditChain(self.state_dir / "lockdown_audit.jsonl")

    def _run(self, command: list[str], timeout: int = 12) -> dict[str, Any]:
        try:
            result = self.runner(command, capture_output=True, text=True, timeout=timeout, check=False)
            return {"command": command, "returncode": int(result.returncode), "stdout": (result.stdout or "")[-32768:], "stderr": (result.stderr or "")[-32768:]}
        except Exception as exc:
            return {"command": command, "returncode": -1, "stdout": "", "stderr": str(exc)}

    def preflight(self, profile_name: str = "emergency") -> dict[str, Any]:
        profile = load_profile(profile_name)
        probes = {
            "hardware": self._run(["/usr/sbin/system_profiler", "SPHardwareDataType", "-json"]),
            "filevault": self._run(["/usr/bin/fdesetup", "status"]),
            "sip": self._run(["/usr/bin/csrutil", "status"]),
            "application_firewall": self._run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"]),
            "pf": self._run(["/sbin/pfctl", "-s", "info"]),
            "users": self._run(["/usr/bin/who"]),
            "processes": self._run(["/bin/ps", "-axo", "pid,ppid,user,command"]),
            "network": self._run(["/usr/sbin/netstat", "-anv"]),
            "launch_agents": self._run(["/bin/launchctl", "print", f"gui/{user_launchctl_uid()}"]),
            "launch_daemons": self._run(["/bin/launchctl", "print", "system"]),
            "system_extensions": self._run(["/usr/bin/systemextensionsctl", "list"]),
            "kernel_extensions": self._run(["/usr/bin/kmutil", "showloaded"]),
            "mdm": self._run(["/usr/bin/profiles", "status", "-type", "enrollment"]),
            "gatekeeper": self._run(["/usr/sbin/spctl", "--status"]),
            "remote_login": self._run(["/usr/sbin/systemsetup", "-getremotelogin"]),
        }
        warnings = [str(control.get("warning")) for control in profile.controls if control.get("warning")]
        failures = [name for name, result in probes.items() if result["returncode"] not in {0, 1}]
        report = {"feature_id": FEATURE_ID, "product_name": PRODUCT_NAME, "apple_lockdown_mode": False, "disclaimer": APPLE_DISCLAIMER, "ready": not failures, "risk_level": "critical", "profile": profile.to_dict(), "macos_version": platform.mac_ver()[0], "hardware_model": platform.machine(), "cpu_architecture": platform.machine(), "hostname": socket.gethostname(), "warnings": warnings, "probe_failures": failures, "inventory": probes}
        write_evidence(self.state_dir / "lockdown_preflight_report.json", report)
        self.audit.append("preflight", {"profile": profile.profile_id, "ready": report["ready"], "failures": failures})
        return report

    def enable(self, profile_name: str, authorization: ActivationAuthorization, *, dry_run: bool = False) -> dict[str, Any]:
        authorization.validate(require_root=self.require_root and not dry_run)
        profile = load_profile(profile_name)
        if self.status().get("active"):
            raise RuntimeError("LOCKDOWN_ALREADY_ACTIVE: disable and verify rollback before enabling another profile.")
        preflight = self.preflight(profile_name)
        if not preflight.get("ready") and not dry_run:
            raise RuntimeError(f"LOCKDOWN_PREFLIGHT_FAILED: {', '.join(preflight.get('probe_failures', []))}")
        controls = self._controls_with_observed_rollback(profile, preflight)
        activation_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        activation_dir = self.state_dir / "activations" / activation_id
        activation_dir.mkdir(parents=True, exist_ok=False)
        os.chmod(activation_dir, 0o700)
        write_evidence(activation_dir / "activation_authorization.json", authorization.to_dict())
        write_evidence(activation_dir / "system_inventory.json", preflight)
        write_evidence(activation_dir / "network_state.json", preflight["inventory"].get("network", {}))
        write_evidence(activation_dir / "process_snapshot.json", preflight["inventory"].get("processes", {}))
        write_evidence(activation_dir / "persistence_snapshot.json", {key: preflight["inventory"].get(key, {}) for key in ("launch_agents", "launch_daemons", "system_extensions", "kernel_extensions")})
        write_evidence(activation_dir / "security_configuration.json", {key: preflight["inventory"].get(key, {}) for key in ("filevault", "sip", "application_firewall", "pf", "gatekeeper", "remote_login", "mdm")})
        write_evidence(activation_dir / "rollback_state.json", {"profile": profile.to_dict(), "controls": controls, "status": "prepared"})
        applied: list[dict[str, Any]] = []
        results: list[dict[str, Any]] = []
        try:
            for control in controls:
                result = self.enforcer.apply(control, dry_run=dry_run)
                results.append(result.to_dict())
                if not result.success: raise RuntimeError(f"LOCKDOWN_CONTROL_FAILED: {result.control_id}: {result.stderr}")
                if result.changed: applied.append(control)
        except Exception:
            rollback = rollback_controls(applied, self.enforcer, dry_run=dry_run)
            write_evidence(activation_dir / "partial_activation.json", {"results": results, "rollback": rollback})
            self.audit.append("activation_failed", {"activation_id": activation_id, "results": results, "rollback": rollback})
            raise
        profile_payload = profile.to_dict(); profile_payload["controls"] = controls
        manifest = {"feature_id": FEATURE_ID, "product_name": PRODUCT_NAME, "active": not dry_run, "dry_run": dry_run, "activation_id": activation_id, "activation_dir": str(activation_dir), "profile": profile_payload, "authorization": authorization.to_dict(), "started_at": datetime.now(timezone.utc).isoformat(), "controls_applied": len(applied), "protections_enabled": len(profile.controls) + len(profile.monitoring), "restrictions_applied": len(profile.controls), "exceptions": [], "rollback_available": True, "results": results, "persistent_banner": True, "score_adjustments": profile.score_adjustments, "network_enforcement": {"requested_mode": profile.network_mode, "applied": profile.network_mode == "normal", "reason": "Critical or restricted PF isolation requires a separately reviewed and validated incident allowlist." if profile.network_mode != "normal" else "No PF restriction requested."}, "disclaimer": APPLE_DISCLAIMER}
        write_evidence(activation_dir / "lockdown_activation.json", manifest)
        write_evidence(self.state_dir / "active_state.json", manifest)
        self.audit.append("enabled" if not dry_run else "enable_preview", {"activation_id": activation_id, "profile": profile.profile_id, "operator": authorization.operator, "results": results})
        return manifest

    @staticmethod
    def _controls_with_observed_rollback(profile: LockdownProfile, preflight: dict[str, Any]) -> list[dict[str, Any]]:
        inventory = preflight.get("inventory", {})
        controls = [dict(item) for item in profile.controls]
        for control in controls:
            probe = str(control.get("state_probe", ""))
            output = str(inventory.get(probe, {}).get("stdout", "")).lower()
            if probe == "remote_login":
                control["rollback"] = ["/usr/sbin/systemsetup", "-setremotelogin", "on" if "on" in output else "off"]
            elif probe == "application_firewall":
                control["rollback"] = ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--setglobalstate", "on" if "enabled" in output or "state = 1" in output else "off"]
        return controls

    def disable(self, authorization: ActivationAuthorization, *, restore: bool = True, dry_run: bool = False) -> dict[str, Any]:
        authorization.validate(require_root=self.require_root and not dry_run)
        if not restore:
            raise ValueError("LOCKDOWN_RESTORE_REQUIRED: disabling without restoring the recorded security posture is prohibited.")
        state = self.status()
        if not state.get("active") and not dry_run: raise RuntimeError("LOCKDOWN_NOT_ACTIVE")
        controls = list(state.get("profile", {}).get("controls", []))
        results = rollback_controls(controls, self.enforcer, dry_run=dry_run) if restore else []
        success = all(item.get("success") for item in results) if restore else True
        report = {"feature_id": FEATURE_ID, "product_name": PRODUCT_NAME, "disabled_at": datetime.now(timezone.utc).isoformat(), "restore_requested": restore, "restored": success, "results": results, "authorization": authorization.to_dict()}
        write_evidence(self.state_dir / "lockdown_rollback_report.json", report)
        if success and not dry_run: (self.state_dir / "active_state.json").unlink(missing_ok=True)
        self.audit.append("disabled", report)
        return report

    def status(self) -> dict[str, Any]:
        path = self.state_dir / "active_state.json"
        if not path.exists(): return {"feature_id": FEATURE_ID, "product_name": PRODUCT_NAME, "active": False, "rollback_available": False, "disclaimer": APPLE_DISCLAIMER}
        try:
            if path.stat().st_mode & 0o077:
                self.audit.append("tamper_detected", {"target": str(path), "reason": "unsafe file permissions"})
                return {"feature_id": FEATURE_ID, "product_name": PRODUCT_NAME, "active": False, "tamper_detected": True, "error": "LOCKDOWN_STATE_PERMISSIONS_UNSAFE", "disclaimer": APPLE_DISCLAIMER}
            payload = json.loads(path.read_text(encoding="utf-8"))
            if not verify_evidence(payload):
                self.audit.append("tamper_detected", {"target": str(path), "reason": "integrity hash mismatch"})
                return {"feature_id": FEATURE_ID, "product_name": PRODUCT_NAME, "active": False, "tamper_detected": True, "error": "LOCKDOWN_STATE_INTEGRITY_MISMATCH", "disclaimer": APPLE_DISCLAIMER}
            return payload
        except (OSError, json.JSONDecodeError) as exc: return {"feature_id": FEATURE_ID, "product_name": PRODUCT_NAME, "active": False, "tamper_detected": True, "error": str(exc), "disclaimer": APPLE_DISCLAIMER}

    def add_exception(self, application: str, duration_minutes: int, reason: str, authorization: ActivationAuthorization) -> dict[str, Any]:
        authorization.validate(require_root=self.require_root)
        if duration_minutes < 1 or duration_minutes > 1440 or not application.strip() or not reason.strip(): raise ValueError("Invalid emergency exception request.")
        state = self.status()
        if not state.get("active"): raise RuntimeError("LOCKDOWN_NOT_ACTIVE")
        exception = {"application": application, "reason": reason, "approved_by": authorization.operator, "created_at": datetime.now(timezone.utc).isoformat(), "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=duration_minutes)).isoformat(), "ticket_number": authorization.ticket_number}
        state.setdefault("exceptions", []).append(exception)
        write_evidence(self.state_dir / "active_state.json", state)
        self.audit.append("exception_added", exception)
        return exception

    def export_report(self, destination: Path) -> Path:
        return write_evidence(destination, self.report_payload(), mode=0o600)

    def report_payload(self) -> dict[str, Any]:
        return {
            "status": self.status(),
            "audit_log": self.audit.path.read_text(encoding="utf-8").splitlines()[-1000:] if self.audit.path.exists() else [],
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
