from __future__ import annotations

import getpass
import hashlib
import json
import os
import signal
import socket
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mac_audit_agent.not_signed.protected_items import protected_path

from .evidence import collect_keylogger_evidence, discover_exact_persistence, sha256_file
from .permissions import tcc_remediation_guidance
from .quarantine import quarantine_path


@dataclass(frozen=True)
class KeyloggerRemediationAssessment:
    finding_id: str
    threat_score: int
    severity: str
    confidence: str
    factors: tuple[str, ...]
    recommended_action: str
    target_path: str
    pid: int | None
    persistence: tuple[str, ...]
    protected: bool
    protection_reason: str
    requires_admin: bool
    analytic_confidence_percent: int
    false_positive_risk_percent: int
    intervention_actions: tuple[str, ...]
    removal_actions: tuple[str, ...]
    remediation_actions: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class KeyloggerAuditLog:
    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path or (Path.home() / "Library/Application Support/MSAA/Keylogger/audit/remediation.jsonl"))

    def append(self, *, finding: dict[str, Any], action: str, target: str, result: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
        previous = ""
        if self.path.exists():
            try:
                previous = json.loads(self.path.read_text(encoding="utf-8").splitlines()[-1]).get("record_hash", "")
            except (OSError, json.JSONDecodeError, IndexError):
                previous = ""
        event = {
            "event_type": "KEYLOGGER_REMEDIATION_EVENT", "timestamp": datetime.now(timezone.utc).isoformat(),
            "user": getpass.getuser(), "hostname": socket.gethostname(),
            "finding_id": finding.get("finding_id", ""), "action": action, "target": target,
            "hash": sha256_file(Path(target)) if target and Path(target).is_file() else "",
            "result": result, "details": details or {}, "previous_hash": previous,
        }
        event["record_hash"] = hashlib.sha256(json.dumps(event, sort_keys=True, default=str).encode()).hexdigest()
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True, default=str) + "\n")
        return event


class KeyloggerRemediationEngine:
    def __init__(self, *, evidence_root: Path | None = None, quarantine_root: Path | None = None, audit_log: KeyloggerAuditLog | None = None) -> None:
        self.evidence_root = evidence_root
        self.quarantine_root = quarantine_root
        self.audit = audit_log or KeyloggerAuditLog()

    def assess(self, finding: dict[str, Any]) -> KeyloggerRemediationAssessment:
        factors = list(str(item) for item in finding.get("signals", ()))
        evidence = dict(finding.get("evidence") or {})
        path = Path(str(finding.get("path") or "")).expanduser()
        score = int(finding.get("score") or 0)
        signal_text = " ".join(factors).lower()
        weighted = {
            "cgeventtap": 25, "event tap": 25, "accessibility": 12, "input monitoring": 15,
            "iohid": 20, "persistence": 18, "unsigned": 18, "invalid code signature": 20,
            "network": 12, "hidden": 10, "obfuscat": 15, "known malware": 35,
        }
        for marker, value in weighted.items():
            if marker in signal_text:
                score = max(score, min(100, score + value))
        signature = dict(evidence.get("signature") or {})
        if signature and not signature.get("valid"):
            factors.append("Unsigned or invalidly signed executable")
            score = max(score, 70)
        persistence = tuple(str(item) for item in discover_exact_persistence(path, str(finding.get("bundle_id") or ""))) if str(path) else ()
        if persistence:
            factors.append(f"{len(persistence)} exact persistence reference(s)")
            score = min(100, score + 15)
        protected, reason = protected_path(path) if str(finding.get("path") or "") else (True, "Executable path is unresolved.")
        trusted = bool(signature.get("valid") and (signature.get("team_id") or signature.get("authority")))
        if trusted:
            factors.append("Valid publisher identity present; analyst confirmation required before containment")
        severity = "critical" if score >= 85 else "high" if score >= 65 else "medium" if score >= 35 else "low"
        action = "Quarantine and remove after evidence capture" if score >= 85 and not trusted else "Investigate and preserve evidence before containment"
        confidence_percent = max(0, min(100, int(finding.get("analytic_confidence_percent", 0) or 0)))
        if not confidence_percent:
            confidence_percent = {"high": 85, "medium": 60, "low": 35}.get(str(finding.get("confidence", "")).lower(), 50)
        reported_false_positive = finding.get("false_positive_risk_percent")
        false_positive_percent = max(0, min(100, int(reported_false_positive if reported_false_positive is not None else 100 - score)))
        intervention_actions = tuple(str(item) for item in finding.get("intervention_actions", ()) if str(item)) or (
            "Preserve evidence and validate the application owner before containment.",
        )
        removal_actions = tuple(str(item) for item in finding.get("removal_actions", ()) if str(item)) or (
            "Use reversible quarantine only after the removal threshold and identity checks pass.",
        )
        remediation_actions = tuple(str(item) for item in finding.get("remediation_actions", ()) if str(item)) or (
            "Review privacy permissions and verify with a new scan.",
        )
        requires_admin = str(path).startswith(("/Applications/", "/Library/")) or any(
            str(item).startswith("/Library/") for item in persistence
        )
        return KeyloggerRemediationAssessment(
            str(finding.get("finding_id") or ""), min(100, score), severity,
            str(finding.get("confidence") or "unknown"), tuple(dict.fromkeys(factors)), action,
            str(path) if str(finding.get("path") or "") else "", int(finding.get("pid") or 0) or None,
            persistence, protected, reason, requires_admin, confidence_percent, false_positive_percent,
            intervention_actions, removal_actions, remediation_actions,
        )

    def investigate(self, finding: dict[str, Any]) -> dict[str, Any]:
        assessment = self.assess(finding)
        evidence = collect_keylogger_evidence(finding, root=self.evidence_root)
        result = {"assessment": assessment.to_dict(), "evidence_path": str(evidence), "tcc_guidance": tcc_remediation_guidance(finding)}
        self.audit.append(finding=finding, action="investigate", target=assessment.target_path, result="success", details=result)
        return result

    def contain_process(self, finding: dict[str, Any], *, suspend: bool = False) -> dict[str, Any]:
        assessment = self.assess(finding)
        if assessment.protected:
            raise PermissionError(assessment.protection_reason)
        if assessment.threat_score < 65 or assessment.false_positive_risk_percent > 35:
            raise PermissionError("Analytic thresholds require investigation before process intervention.")
        pid = assessment.pid or 0
        self._revalidate_process(pid, Path(assessment.target_path))
        evidence = collect_keylogger_evidence(finding, root=self.evidence_root)
        os.kill(pid, signal.SIGSTOP if suspend else signal.SIGTERM)
        action = "suspend_process" if suspend else "terminate_process"
        result = {"status": "requested", "signal": "SIGSTOP" if suspend else "SIGTERM", "pid": pid, "evidence_path": str(evidence)}
        self.audit.append(finding=finding, action=action, target=assessment.target_path, result="success", details=result)
        return result

    def quarantine(self, finding: dict[str, Any]) -> dict[str, Any]:
        assessment = self.assess(finding)
        if assessment.protected:
            raise PermissionError(assessment.protection_reason)
        if assessment.threat_score < 65 or assessment.false_positive_risk_percent > 35:
            raise PermissionError("Threat score is below the quarantine threshold or false-positive risk is too high; investigate and obtain analyst approval.")
        evidence = collect_keylogger_evidence(finding, root=self.evidence_root)
        manifest = quarantine_path(Path(assessment.target_path), finding=finding, root=self.quarantine_root)
        result = {"status": "quarantined", "evidence_path": str(evidence), "quarantine": manifest, "tcc_guidance": tcc_remediation_guidance(finding)}
        self.audit.append(finding=finding, action="quarantine", target=assessment.target_path, result="success", details=result)
        return result

    def unhook_and_quarantine(self, finding: dict[str, Any]) -> dict[str, Any]:
        """Release a suspicious keyboard event tap and quarantine its exact artifacts.

        macOS does not expose an API for one process to detach another process's
        event tap. Revalidating and terminating the owning process is therefore the
        safe unhook operation. Evidence is preserved before any state changes, and
        every moved artifact remains restorable from quarantine.
        """
        assessment = self.assess(finding)
        if assessment.protected:
            raise PermissionError(assessment.protection_reason)
        if assessment.threat_score < 65 or assessment.false_positive_risk_percent > 35:
            raise PermissionError("Threat score is below the unhook threshold or false-positive risk is too high; investigate and obtain analyst approval.")
        if assessment.requires_admin and os.geteuid() != 0:
            raise PermissionError("Administrator authorization through the approved privileged helper is required for this system-wide target.")

        target = Path(assessment.target_path)
        pid = assessment.pid or 0
        process_running = self._process_is_running(pid) if pid else False
        if process_running:
            self._revalidate_process(pid, target)

        evidence = collect_keylogger_evidence(finding, root=self.evidence_root)
        quarantined: list[dict[str, Any]] = []
        try:
            # Remove exact persistence first so launchd cannot immediately recreate
            # the event tap after the owning process exits.
            for persistence in assessment.persistence:
                quarantined.append(quarantine_path(Path(persistence), finding=finding, root=self.quarantine_root))
            if process_running:
                try:
                    self._revalidate_process(pid, target)
                    os.kill(pid, signal.SIGTERM)
                except ProcessLookupError:
                    # The owner exited after evidence capture, which also releases
                    # its event tap. Continue with reversible artifact quarantine.
                    process_running = False
            quarantined.append(quarantine_path(target, finding=finding, root=self.quarantine_root))
        except Exception as exc:
            self.audit.append(
                finding=finding,
                action="unhook_and_quarantine",
                target=assessment.target_path,
                result="partial_or_refused",
                details={
                    "error": str(exc),
                    "evidence_path": str(evidence),
                    "quarantined": quarantined,
                },
            )
            raise

        result = {
            "status": "unhooked_and_quarantined",
            "hook_release": "termination_requested" if process_running else "owner_not_running",
            "pid": pid or None,
            "evidence_path": str(evidence),
            "quarantined": quarantined,
            "permanent_deletion": False,
            "tcc_guidance": tcc_remediation_guidance(finding),
        }
        self.audit.append(
            finding=finding,
            action="unhook_and_quarantine",
            target=assessment.target_path,
            result="success",
            details=result,
        )
        return result

    def remove_threat(self, finding: dict[str, Any]) -> dict[str, Any]:
        assessment = self.assess(finding)
        if assessment.protected:
            raise PermissionError(assessment.protection_reason)
        if assessment.requires_admin and os.geteuid() != 0:
            raise PermissionError("Administrator authorization through the approved privileged helper is required for this system-wide target.")
        if assessment.threat_score < 85 or assessment.false_positive_risk_percent > 20:
            raise PermissionError("Threat-removal workflow requires a critical score, low false-positive risk, or explicit analyst escalation; use quarantine.")
        evidence = collect_keylogger_evidence(finding, root=self.evidence_root)
        quarantined: list[dict[str, Any]] = []
        for persistence in assessment.persistence:
            quarantined.append(quarantine_path(Path(persistence), finding=finding, root=self.quarantine_root))
        quarantined.append(quarantine_path(Path(assessment.target_path), finding=finding, root=self.quarantine_root))
        result = {"status": "removed_to_quarantine", "evidence_path": str(evidence), "quarantined": quarantined, "permanent_deletion": False, "tcc_guidance": tcc_remediation_guidance(finding)}
        self.audit.append(finding=finding, action="remove_threat", target=assessment.target_path, result="success", details=result)
        return result

    def verify(self, finding: dict[str, Any]) -> dict[str, Any]:
        assessment = self.assess(finding)
        process_running = False
        if assessment.pid:
            process_running = subprocess.run(["/bin/kill", "-0", str(assessment.pid)], capture_output=True, check=False).returncode == 0
        target_present = bool(assessment.target_path and Path(assessment.target_path).exists())
        persistence = discover_exact_persistence(Path(assessment.target_path), str(finding.get("bundle_id") or "")) if assessment.target_path else []
        status = "success" if not process_running and not target_present and not persistence else "remaining_risk"
        result = {
            "status": status, "process_running": process_running, "target_present": target_present,
            "persistence_remaining": [str(item) for item in persistence],
            "permissions_review": tcc_remediation_guidance(finding),
            "recommended_actions": ["Review passwords and active sessions if credential compromise is suspected.", "Rescan Keylogger Detection after permission review."],
        }
        self.audit.append(finding=finding, action="verify", target=assessment.target_path, result=status, details=result)
        return result

    @staticmethod
    def _process_is_running(pid: int) -> bool:
        if pid <= 1:
            return False
        return subprocess.run(
            ["/bin/kill", "-0", str(pid)], capture_output=True, check=False
        ).returncode == 0

    @staticmethod
    def _revalidate_process(pid: int, expected_path: Path) -> None:
        if pid <= 1:
            raise PermissionError("Protected or invalid PID.")
        result = subprocess.run(["/bin/ps", "-p", str(pid), "-o", "comm="], capture_output=True, text=True, timeout=4, check=False)
        observed = (result.stdout or "").strip()
        if result.returncode or not observed:
            raise ProcessLookupError("Process is no longer running.")
        if Path(observed).resolve(strict=False) != expected_path.resolve(strict=False):
            raise PermissionError("PID reuse or executable identity change detected.")


__all__ = ["KeyloggerAuditLog", "KeyloggerRemediationAssessment", "KeyloggerRemediationEngine"]
