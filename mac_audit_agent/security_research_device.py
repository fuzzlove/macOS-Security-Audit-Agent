from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from mac_audit_agent.zero_trust.automatic_validation import collect_automatic_posture_evidence


@dataclass(frozen=True)
class ResearchDeviceTask:
    task_id: str
    title: str
    purpose: str
    automatic_key: str | None
    manual_steps: tuple[str, ...]
    remediation: str
    rollback: str
    requires_admin: bool
    requires_mdm: bool
    restart_may_be_required: bool
    mappings: tuple[str, ...]


@dataclass(frozen=True)
class ResearchDeviceProfile:
    profile_id: str
    title: str
    description: str
    task_ids: tuple[str, ...]


TASKS: tuple[ResearchDeviceTask, ...] = (
    ResearchDeviceTask("filevault", "Encrypt research data with FileVault", "Reduce offline data exposure after loss or theft.", "filevault_enabled", ("Open System Settings > Privacy & Security > FileVault.", "Confirm FileVault is On and verify the institutional recovery-key escrow process without recording the key in MSAA."), "Enable FileVault through System Settings or an approved MDM policy after confirming recovery-key custody.", "Use the approved organizational recovery-key and decryption procedure; do not disable encryption during an active incident.", True, False, True, ("NIST SP 800-53 SC-28", "DoD macOS STIG", "Apple Platform Security")),
    ResearchDeviceTask("secure_boot", "Verify Secure Boot policy", "Detect reduced boot-policy protection where supported.", "secure_boot_verified", ("On Apple silicon, inspect Startup Security Utility from macOS Recovery.", "Confirm Full Security unless an approved research exception documents why reduced security is required."), "Restore Full Security in Startup Security Utility; preserve any research exception and its expiration.", "A boot-policy change may require Recovery and a restart; document the prior policy.", True, False, True, ("NIST SP 800-53 SI-7", "DoD macOS STIG", "Apple Platform Security")),
    ResearchDeviceTask("sip", "Keep System Integrity Protection enabled", "Protect restricted system locations and processes from modification.", "sip_enabled", ("Run MSAA's automatic check.", "For independent validation, use csrutil status from a trusted Terminal and retain only the status, not unrelated command history."), "Re-enable SIP from macOS Recovery unless an approved, time-limited laboratory exception requires otherwise.", "Record the prior state and remove the exception when the authorized test ends.", True, False, True, ("NIST SP 800-53 SI-7", "DoD macOS STIG", "Apple Platform Security")),
    ResearchDeviceTask("firewall", "Enable and review the application firewall", "Reduce unintended inbound service exposure.", "firewall_enabled", ("Open System Settings > Network > Firewall.", "Confirm it is enabled, then review permitted applications and required research listeners with the asset owner."), "Enable the firewall and narrowly approve only required inbound services.", "Export the prior exception list and restore only reviewed entries if a workflow breaks.", True, False, False, ("NIST SP 800-53 SC-7", "DoD macOS STIG")),
    ResearchDeviceTask("updates", "Define rapid security-update handling", "Limit exposure while preserving research reproducibility.", None, ("Open System Settings > General > Software Update > Automatic Updates.", "Confirm the client-approved policy for security responses, OS updates, validation, and rollback."), "Use MDM for managed update deadlines and staged rollout; preserve research snapshots before material upgrades.", "Maintain tested backups and a documented recovery path; macOS downgrades may require erase-and-restore.", False, True, True, ("NIST SP 800-53 SI-2", "DoD macOS STIG")),
    ResearchDeviceTask("accounts", "Separate research and administration identities", "Reduce accidental privilege use and cross-project exposure.", None, ("Review Users & Groups and approved identity-provider records.", "Confirm daily research uses a standard account and administrator access is separately controlled."), "Create separate least-privilege research and administrator identities under organizational policy.", "Ensure a tested recovery administrator remains available before changing account privileges.", True, True, False, ("NIST SP 800-53 AC-2", "NIST SP 800-53 AC-6")),
    ResearchDeviceTask("screen_lock", "Require prompt screen lock and strong authentication", "Reduce unattended-device access.", None, ("Open System Settings > Lock Screen.", "Confirm the approved inactivity timeout and immediate password requirement; verify recovery and accessibility needs."), "Apply the approved lock-screen and password policy locally or through MDM.", "Document any accessibility exception and preserve a secure alternative control.", False, True, False, ("NIST SP 800-53 AC-11", "DoD macOS STIG")),
    ResearchDeviceTask("sharing", "Review remote access and sharing services", "Limit externally reachable administration and data-sharing paths.", None, ("Open System Settings > General > Sharing.", "Review Remote Login, Remote Management, Screen Sharing, File Sharing, Media Sharing, and AirDrop against engagement scope."), "Disable unneeded services; restrict required services to approved users and networks.", "Record prior services and test an out-of-band recovery path before disabling remote administration.", True, True, False, ("NIST SP 800-53 AC-17", "NIST SP 800-53 CM-7", "DoD macOS STIG")),
    ResearchDeviceTask("software_trust", "Review software provenance and extensions", "Reduce unsigned or unnecessary code in the research trust boundary.", None, ("Open MSAA Not Signed and export the complete software report.", "Review unsigned, ad hoc, invalid, revoked, and unexpected developer identities; separately review extensions and privileged helpers."), "Remove or contain unapproved software using the reviewed Add/Remove Programs workflow; do not bypass SIP or the signed system volume.", "Preserve installers, hashes, licenses, and rollback packages required by the engagement.", False, True, True, ("NIST SP 800-53 CM-7", "NIST SP 800-53 SI-7", "DoD macOS STIG")),
    ResearchDeviceTask("network_scope", "Approve research network, DNS, VPN, and outbound scope", "Prevent accidental exposure and preserve attributable network evidence.", None, ("Review MSAA Network Monitor, Network Intelligence, and DNS Configuration Assurance.", "Export evidence and obtain client approval for expected resolvers, VPN, listeners, and outbound destinations."), "Use an approved isolated VLAN/VPN and narrowly scoped firewall policy; never assume an unfamiliar endpoint is malicious.", "Retain console or out-of-band recovery before applying isolation that could remove management access.", True, True, False, ("NIST SP 800-53 SC-7", "NIST SP 800-53 AC-4")),
    ResearchDeviceTask("backup_recovery", "Test encrypted backup and recovery", "Make research recoverable after theft, damage, or containment.", None, ("Confirm the approved encrypted backup destination and retention policy.", "Restore a non-sensitive test fixture and record the result; do not claim this proves full-system recovery."), "Configure an approved encrypted backup with access separation and test its restore procedure.", "Keep at least one protected recovery copy outside the primary device failure domain.", False, True, False, ("NIST SP 800-53 CP-9", "NIST SP 800-53 CP-10")),
    ResearchDeviceTask("data_handling", "Define research data classification and export boundaries", "Prevent intellectual-property leakage through unclear handling rules.", None, ("Record the project classification, approved storage locations, retention, external-service restrictions, and export recipients.", "Confirm secrets and vulnerability details are not placed in ordinary notes, telemetry, or unapproved cloud services."), "Apply project-specific data labels, least-privilege access, encryption, and an approved disclosure channel.", "Define secure archival or deletion procedures before collection begins.", False, True, False, ("NIST SP 800-53 MP-4", "NIST SP 800-53 SC-28", "NIST SP 800-171 3.8")),
    ResearchDeviceTask("incident_plan", "Prepare incident, disclosure, and evidence procedures", "Preserve evidence and route suspected theft or compromise correctly.", None, ("Confirm the system-owner, security, privacy, legal, and vulnerability-disclosure contacts.", "Review stop conditions, chain of custody, reporting timelines, and CISA/vendor submission instructions applicable to this engagement."), "Create an engagement-specific incident and coordinated-disclosure plan; INTERPOL resources may inform reporting awareness but do not authorize access or define macOS compliance.", "Test contact and recovery procedures with a tabletop exercise, not a destructive live test.", False, True, False, ("NIST SP 800-53 IR-4", "NIST CSF Respond/Recover", "INTERPOL cybercrime reporting awareness")),
)

PROFILES: tuple[ResearchDeviceProfile, ...] = (
    ResearchDeviceProfile("theft_prevention", "Theft Prevention", "Core device, data-at-rest, account, lock-screen, and recovery protections.", ("filevault", "secure_boot", "sip", "firewall", "screen_lock", "accounts", "backup_recovery")),
    ResearchDeviceProfile("sensitive_research", "Sensitive Security Research", "Adds software provenance, network scope, updates, sharing, and explicit data handling.", tuple(task.task_id for task in TASKS if task.task_id != "incident_plan")),
    ResearchDeviceProfile("government_submission_readiness", "CISA / DoD Submission Readiness", "Full evidence-oriented review for work intended for an authorized government submission. This does not establish compliance, approval, or authorization.", tuple(task.task_id for task in TASKS)),
)


def profile_by_id(profile_id: str) -> ResearchDeviceProfile:
    return next((profile for profile in PROFILES if profile.profile_id == profile_id), PROFILES[0])


def tasks_for_profile(profile_id: str) -> tuple[ResearchDeviceTask, ...]:
    wanted = set(profile_by_id(profile_id).task_ids)
    return tuple(task for task in TASKS if task.task_id in wanted)


def evaluate_automatic_tasks(collector: Callable[[], Any] = collect_automatic_posture_evidence) -> dict[str, dict[str, Any]]:
    evidence = collector()
    by_key = {task.automatic_key: task for task in TASKS if task.automatic_key}
    results: dict[str, dict[str, Any]] = {}
    for key, task in by_key.items():
        value = evidence.values.get(key)
        results[task.task_id] = {
            "status": "pass" if value is True else "fail" if value is False else "unknown",
            "collected_at": evidence.collected_at,
            "observation": evidence.observations.get(key, {}),
        }
    return results


def export_assessment(path: Path, *, profile_id: str, states: dict[str, dict[str, Any]]) -> Path:
    payload = {
        "schema_version": "1.0",
        "assessment_type": "MSAA Security Research Device",
        "profile": asdict(profile_by_id(profile_id)),
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "disclaimer": "An MSAA assessment is evidence support, not certification, government approval, or a guarantee against compromise.",
        "tasks": [{**asdict(task), "assessment": states.get(task.task_id, {"status": "not_assessed"})} for task in tasks_for_profile(profile_id)],
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    payload["sha256"] = hashlib.sha256(canonical).hexdigest()
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return path
