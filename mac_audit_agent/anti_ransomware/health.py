from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mac_audit_agent.compat.enum import StrEnum

from .adaptive_detector import MODEL_VERSION as ADAPTIVE_MODEL_VERSION
from .models import ProtectionMode, SensorMode

STATUS_SCHEMA_VERSION="2.0"
EXPECTED_SENSOR_PATH=Path("/Library/Application Support/MacAuditAgent/bin/MSAAEndpointSecuritySensor.app/Contents/MacOS/MSAAEndpointSecuritySensor")
EXPECTED_HELPER_PATH=Path("/Library/Application Support/MacAuditAgent/bin/MSAAContainmentHelper")

class ProtectionState(StrEnum):
    DISABLED="DISABLED"; INITIALIZING="INITIALIZING"; DEGRADED="DEGRADED"; OBSERVE_READY="OBSERVE_READY"
    ENDPOINT_SECURITY_OBSERVE_READY="ENDPOINT_SECURITY_OBSERVE_READY"; CONTAINMENT_DEGRADED="CONTAINMENT_DEGRADED"
    FULL_ACTIVE_PROTECTION="FULL_ACTIVE_PROTECTION"; PERMISSION_REQUIRED="PERMISSION_REQUIRED"; ENTITLEMENT_REQUIRED="ENTITLEMENT_REQUIRED"
    INSTALLATION_REQUIRED="INSTALLATION_REQUIRED"; SIGNING_REQUIRED="SIGNING_REQUIRED"; EXTERNAL_APPROVAL_REQUIRED="EXTERNAL_APPROVAL_REQUIRED"
    MISCONFIGURED="MISCONFIGURED"; TAMPERED="TAMPERED"; ERROR="ERROR"

class OperationalState(StrEnum):
    UNINSTALLED="UNINSTALLED"; INSTALLING="INSTALLING"; WAITING_FOR_ADMIN_AUTHORIZATION="WAITING_FOR_ADMIN_AUTHORIZATION"
    WAITING_FOR_SYSTEM_EXTENSION_APPROVAL="WAITING_FOR_SYSTEM_EXTENSION_APPROVAL"; WAITING_FOR_FULL_DISK_ACCESS="WAITING_FOR_FULL_DISK_ACCESS"
    STARTING="STARTING"; OBSERVE="OBSERVE"; PROTECTED="PROTECTED"; DEGRADED="DEGRADED"
    SELF_PROTECTION_DEGRADED="SELF_PROTECTION_DEGRADED"; EMERGENCY_CONTAINMENT="EMERGENCY_CONTAINMENT"
    HOST_ISOLATED="HOST_ISOLATED"; STOPPING="STOPPING"; ERROR="ERROR"

class ContainmentState(StrEnum):
    UNAVAILABLE="UNAVAILABLE"; IMPLEMENTED_NOT_INSTALLED="IMPLEMENTED_NOT_INSTALLED"; HELPER_NOT_RUNNING="HELPER_NOT_RUNNING"
    IPC_UNAVAILABLE="IPC_UNAVAILABLE"; IDENTITY_REVALIDATION_UNAVAILABLE="IDENTITY_REVALIDATION_UNAVAILABLE"
    OBSERVE_ONLY_POLICY="OBSERVE_ONLY_POLICY"; AVAILABLE_NOT_LIVE_TESTED="AVAILABLE_NOT_LIVE_TESTED"; AVAILABLE="AVAILABLE"; DEGRADED="DEGRADED"

class ESClientResult(StrEnum):
    SUCCESS="SUCCESS"; NOT_ENTITLED="NOT_ENTITLED"; NOT_PERMITTED="NOT_PERMITTED"; INVALID_ARGUMENT="INVALID_ARGUMENT"
    NOT_PRIVILEGED="NOT_PRIVILEGED"; TOO_MANY_CLIENTS="TOO_MANY_CLIENTS"; INTERNAL_ERROR="INTERNAL_ERROR"; UNSUPPORTED_OS="UNSUPPORTED_OS"
    SENSOR_NOT_INSTALLED="SENSOR_NOT_INSTALLED"; SENSOR_NOT_RUNNING="SENSOR_NOT_RUNNING"; CONNECTION_NOT_ATTEMPTED="CONNECTION_NOT_ATTEMPTED"

@dataclass(frozen=True)
class RuntimeEvidence:
    build_id: str=""; current_build_id: str=""; boot_session_id: str=""; current_boot_session_id: str=""; fresh: bool=False
    sensor_artifact_exists: bool=False; sensor_installed: bool=False; sensor_loaded: bool=False; sensor_running: bool=False
    sensor_signature_valid: bool=False; sensor_team_id: str=""; sensor_signing_identifier: str=""; sensor_cdhash: str=""
    sensor_architecture: str=""; sensor_version: str=""; sensor_heartbeat_fresh: bool=False
    entitlement_embedded: bool=False; entitlement_accepted: bool=False; tcc_approval_present: bool=False; privacy_approval_source: str="none"
    endpoint_security_client_result: ESClientResult=ESClientResult.CONNECTION_NOT_ATTEMPTED; endpoint_security_connected: bool=False
    endpoint_security_subscriptions_active: bool=False; endpoint_security_live_event_seen: bool=False; endpoint_security_sequence_gap_detected: bool=False
    sequence_tracking_active: bool=False; system_engine_running: bool=False; system_engine_heartbeat_fresh: bool=False
    containment_helper_installed: bool=False; containment_helper_running: bool=False; containment_ipc_authenticated: bool=False
    containment_identity_revalidation: bool=False; containment_lease_watchdog_passed: bool=False; live_fixture_pause_passed: bool=False
    live_fixture_resume_passed: bool=False; live_fixture_termination_passed: bool=False; crash_recovery_passed: bool=False
    no_orphaned_suspended_fixture: bool=False; notifier_required: bool=True; notifier_running: bool=False; notifier_authenticated: bool=False
    python_engine_imports: bool=True; simulation_root_is_safe: bool=True; detection_algorithms_pass: bool=True; incident_storage_available: bool=True
    cleanup_verified: bool=True; degraded_observer_available: bool=True; limitations_reported: bool=True; no_active_protection_claim: bool=True
    production_policy_valid: bool=False; production_rules_valid: bool=False; no_user_policy_valid: bool=False; durable_incident_vault_available: bool=True
    service_restart_verified: bool=False; boot_prelogin_coverage_verified: bool=False; current_uat_no_required_blocker: bool=False
    self_integrity_valid: bool=False; policy_signature_valid: bool=False; rule_package_signature_valid: bool=False
    sensor_details: dict[str,Any]=field(default_factory=dict)

    def is_current(self) -> bool:
        return self.fresh and bool(self.build_id) and self.build_id==self.current_build_id and bool(self.boot_session_id) and self.boot_session_id==self.current_boot_session_id

@dataclass(frozen=True)
class ReadinessResult:
    safe_simulation_ready: bool; degraded_observation_ready: bool; endpoint_security_observe_ready: bool
    active_containment_ready: bool; full_active_protection: bool

@dataclass(frozen=True)
class UnderlyingError:
    error_code: str; component: str; message: str

@dataclass(frozen=True)
class StateTransition:
    previous_state: str; new_state: str; reason: str; error_code: str; timestamp: str; source_component: str
    build_id: str; policy_version: str; evidence_references: tuple[str,...]=()

@dataclass(frozen=True)
class AntiRansomwareHealth:
    state: ProtectionState; active_mode: ProtectionMode; sensor_mode: SensorMode
    sensor_artifact_exists: bool; sensor_installed: bool; sensor_loaded: bool; sensor_running: bool; sensor_signature_valid: bool
    sensor_team_id: str; sensor_signing_identifier: str; sensor_cdhash: str; sensor_architecture: str; sensor_version: str; sensor_heartbeat_fresh: bool
    entitlement_embedded: bool; entitlement_accepted: bool; entitlement_request_required: bool
    tcc_approval_present: bool; full_disk_access_present: bool; privacy_approval_source: str
    endpoint_security_connected: bool; endpoint_security_client_result: ESClientResult; endpoint_security_subscriptions_active: bool
    endpoint_security_live_event_seen: bool; endpoint_security_sequence_gap_detected: bool
    system_engine_running: bool; system_engine_heartbeat_fresh: bool
    containment_state: ContainmentState; containment_helper_installed: bool; containment_helper_running: bool
    containment_ipc_authenticated: bool; containment_identity_revalidation: bool; containment_available: bool
    notifier_required: bool; notifier_running: bool; notifier_authenticated: bool
    safe_simulation_ready: bool; degraded_observation_ready: bool; endpoint_security_observe_ready: bool
    active_containment_ready: bool; full_active_protection: bool
    blocked_by: tuple[str,...]; external_gates: tuple[str,...]; repair_actions: tuple[dict[str,Any],...]
    contribution_actions: tuple[dict[str,Any],...]; underlying_errors: tuple[UnderlyingError,...]
    error_code: str; message: str; status_badge: str; limitations: tuple[str,...]; transitions: tuple[StateTransition,...]
    sensor_details: dict[str,Any]=field(default_factory=dict)
    self_integrity_valid: bool=False
    policy_signature_valid: bool=False
    rule_package_signature_valid: bool=False
    schema_version: str=STATUS_SCHEMA_VERSION
    @property
    def entitlement_present(self): return self.entitlement_accepted
    def to_dict(self):
        value=asdict(self); value["entitlement_present"]=self.entitlement_present
        prototype = self.sensor_details.get("development_observer", {}) if isinstance(self.sensor_details, dict) else {}
        value["development_observer_running"] = bool(prototype.get("running"))
        value["development_observer_mode"] = str(prototype.get("mode", "DEVELOPMENT_OBSERVATION_ONLY"))
        fallback_observe_ready = self.state == ProtectionState.OBSERVE_READY and bool(prototype.get("running"))
        value["operational_state"] = OperationalState.PROTECTED.value if self.full_active_protection else OperationalState.OBSERVE.value if self.endpoint_security_observe_ready or fallback_observe_ready else OperationalState.UNINSTALLED.value if not self.sensor_artifact_exists else OperationalState.WAITING_FOR_SYSTEM_EXTENSION_APPROVAL.value if self.entitlement_embedded and not self.entitlement_accepted else OperationalState.WAITING_FOR_FULL_DISK_ACCESS.value if not self.full_disk_access_present else OperationalState.DEGRADED.value
        value["policy_signature_state"] = "VERIFIED" if self.policy_signature_valid else "NOT_CONFIGURED"
        value["rule_package_signature_state"] = "VERIFIED" if self.rule_package_signature_valid else "NOT_CONFIGURED"
        value["self_integrity_state"] = "VERIFIED" if self.self_integrity_valid else "UNVERIFIED"
        value["remediation_actions"] = (["INSTALL_ENDPOINT_SECURITY_EXTENSION"] if not self.sensor_installed else []) + (["REQUEST_FULL_DISK_ACCESS"] if not self.full_disk_access_present else []) + (["RUN_PROTECTION_VALIDATION"] if not self.endpoint_security_live_event_seen else [])
        return value

def evaluate_readiness(e: RuntimeEvidence) -> ReadinessResult:
    current=e.is_current()
    safe=e.python_engine_imports and e.simulation_root_is_safe and e.detection_algorithms_pass and e.incident_storage_available and e.cleanup_verified
    degraded=e.degraded_observer_available and e.system_engine_running and e.incident_storage_available and e.limitations_reported and e.no_active_protection_claim
    observe=current and all((e.sensor_artifact_exists,e.sensor_signature_valid,e.sensor_installed,e.entitlement_embedded,e.entitlement_accepted,e.tcc_approval_present,e.endpoint_security_connected,e.endpoint_security_subscriptions_active,e.endpoint_security_live_event_seen,e.sequence_tracking_active,e.sensor_heartbeat_fresh)) and not e.endpoint_security_sequence_gap_detected
    containment=observe and all((e.containment_helper_installed,e.containment_helper_running,e.containment_ipc_authenticated,e.containment_identity_revalidation,e.containment_lease_watchdog_passed,e.live_fixture_pause_passed,e.live_fixture_resume_passed,e.live_fixture_termination_passed,e.crash_recovery_passed,e.no_orphaned_suspended_fixture))
    full=containment and all((e.production_policy_valid,e.production_rules_valid,e.policy_signature_valid,e.rule_package_signature_valid,e.self_integrity_valid,(e.notifier_required and e.notifier_running and e.notifier_authenticated) or e.no_user_policy_valid,e.durable_incident_vault_available,e.service_restart_verified,e.boot_prelogin_coverage_verified,e.current_uat_no_required_blocker))
    return ReadinessResult(safe,degraded,observe,containment,full)

def source_health(mode: ProtectionMode=ProtectionMode.OBSERVE,evidence: RuntimeEvidence|None=None) -> AntiRansomwareHealth:
    if evidence is None:
        from .sensor_inspector import inspect_runtime_environment
        evidence=inspect_runtime_environment()
    e=evidence
    r=evaluate_readiness(e); errors=[]; blocked=[]
    def add(code,component,message,key): errors.append(UnderlyingError(code,component,message)); blocked.append(key)
    if not e.sensor_installed: add("AR001","endpoint_security_sensor","The production sensor is not installed.","native_sensor_missing")
    elif not e.sensor_loaded: add("AR002","endpoint_security_sensor","The installed sensor is not loaded.","native_sensor_not_loaded")
    elif not e.sensor_running: add("AR003","endpoint_security_sensor","The installed sensor is not running.","native_sensor_not_running")
    if not e.entitlement_accepted: add("AR004","endpoint_security_entitlement","The signed sensor does not have an accepted Endpoint Security entitlement.","endpoint_security_entitlement_missing")
    if not e.tcc_approval_present: add("AR005","privacy_approval","Required macOS privacy approval is not verified.","privacy_approval_missing")
    if not e.endpoint_security_connected: add("AR006","endpoint_security_connection","A live Endpoint Security client connection is not verified.","endpoint_security_not_connected")
    if not r.active_containment_ready: add("AR016","containment","The signed privileged containment chain is unavailable or not live-tested.","containment_unavailable")
    prototype = e.sensor_details.get("development_observer", {}) if isinstance(e.sensor_details, dict) else {}
    prototype_running = bool(prototype.get("running"))
    fallback_observe_ready = r.degraded_observation_ready and prototype_running
    sensor_mode=SensorMode.ENDPOINT_SECURITY_AUTH_AND_NOTIFY if r.full_active_protection else SensorMode.ENDPOINT_SECURITY_NOTIFY_ONLY if r.endpoint_security_observe_ready else SensorMode.DEGRADED_OBSERVATION_ONLY
    state=ProtectionState.FULL_ACTIVE_PROTECTION if r.full_active_protection else ProtectionState.ENDPOINT_SECURITY_OBSERVE_READY if r.endpoint_security_observe_ready else ProtectionState.OBSERVE_READY if fallback_observe_ready else ProtectionState.DEGRADED
    containment_state=ContainmentState.AVAILABLE if r.active_containment_ready else ContainmentState.IMPLEMENTED_NOT_INSTALLED if not e.containment_helper_installed else ContainmentState.HELPER_NOT_RUNNING if not e.containment_helper_running else ContainmentState.IPC_UNAVAILABLE
    error_code = "" if r.full_active_protection else "AR016" if r.endpoint_security_observe_ready else "AR022"
    now=datetime.now(timezone.utc).isoformat(); transition=StateTransition("INITIALIZING",state.value,"canonical readiness evaluation",error_code,now,"anti_ransomware.health",e.current_build_id,"1.0",("live_runtime_evidence",) if e.is_current() else ())
    repair=(
        {"step":1,"title":"Build or obtain the signed production sensor","status":"required" if not e.sensor_signature_valid else "complete","responsible_role":"release engineer or project owner","administrator_approval_required":False,"verification":f'codesign --verify --strict "{EXPECTED_SENSOR_PATH}"'},
        {"step":2,"title":"Verify Apple Endpoint Security entitlement","status":"blocked_by_apple_approval" if not e.entitlement_accepted else "complete","responsible_role":"Apple Developer team member","administrator_approval_required":False,"verification":f'codesign -d --entitlements - --xml "{EXPECTED_SENSOR_PATH}"'},
        {"step":3,"title":"Install and register active protection","status":"not_started" if not e.sensor_installed else "complete","responsible_role":"administrator or MDM operator","administrator_approval_required":True,"installation_offer":"msaa anti-ransomware install --plan --json","verification":"msaa anti-ransomware status --json"},
        {"step":4,"title":"Approve the required macOS privacy permission","status":"not_granted" if not e.tcc_approval_present else "complete","responsible_role":"local administrator or MDM/PPPC operator","administrator_approval_required":True,"system_settings":"Privacy & Security > Full Disk Access (for the exact signed MSAA component)","managed_deployment":"Deploy the reviewed PPPC profile for the exact Team ID and signing identifier.","restart_may_be_required":True,"verification":"msaa anti-ransomware status --json"},
        {"step":5,"title":"Verify the live Endpoint Security connection","status":"complete" if e.endpoint_security_connected else "blocked_by_earlier_steps" if not e.entitlement_accepted or not e.tcc_approval_present else "required","responsible_role":"test-host operator","administrator_approval_required":False,"verification":"msaa anti-ransomware status --json"},
        {"step":6,"title":"Install and authenticate the containment helper","status":"not_available" if not e.containment_helper_installed else "required","responsible_role":"release engineer and administrator","administrator_approval_required":True,"verification":"msaa anti-ransomware containment doctor"},
        {"step":7,"title":"Run the harmless signed-fixture functional test","status":"blocked_by_earlier_steps" if not e.endpoint_security_connected else "required","responsible_role":"authorized disposable-host operator","administrator_approval_required":True,"verification":"msaa anti-ransomware containment test --signed-fixture"},
    )
    contributions=() if e.entitlement_accepted else ({"external_gate":"APPLE_ENDPOINT_SECURITY_ENTITLEMENT","responsible_role":"Apple Developer Account Holder","required":"Approved entitlement and signed sensor artifact","secrets_not_requested":["private key","p12 password","Apple Account password"]},)
    yara_active = bool(prototype.get("yara_active"))
    hash_active = bool(prototype.get("hash_active"))
    definition_detection = yara_active or hash_active
    message="[MSAA Anti-Ransomware] real-time protection and containment are active." if r.full_active_protection else "[MSAA Anti-Ransomware] the signed Endpoint Security sensor is connected and observing live events. Production containment remains unavailable until the privileged containment chain is installed and live-tested." if r.endpoint_security_observe_ready else "[MSAA Anti-Ransomware] fallback behavioral observation and signed definition matching are operational in the system daemon. Endpoint Security enforcement, complete attribution, and preemptive containment still require the privileged production sensor." if prototype_running and definition_detection else "[MSAA Anti-Ransomware] fallback behavioral observation is operational in the system daemon. Install or update the signed threat database for YARA and hash matching; production enforcement still requires Endpoint Security." if prototype_running else "[MSAA Anti-Ransomware] protection is not fully active. Endpoint Security enforcement is unavailable. Development observation may detect delayed filesystem behavior, but complete attribution and preemptive containment are unavailable."
    badge = state.value if r.endpoint_security_observe_ready else "Fallback Behavioral + Definition Detection Operational — Enforcement Not Installed" if prototype_running and definition_detection else "Fallback Behavioral Detection Operational — Definition Matching Unavailable" if prototype_running else "Development Observation — Active Protection Not Installed"
    limitations = () if r.full_active_protection else ("Notify-only Endpoint Security coverage; no preemptive authorization.","Production containment is not installed and live-tested.","Event loss remains possible and is surfaced as a sequence gap.") if r.endpoint_security_observe_ready else ("Delayed events and incomplete process/root attribution.","No preemptive authorization or production containment.","Event loss is possible; this is not Endpoint Security parity.")
    sensor_details = dict(e.sensor_details)
    sensor_details["adaptive_ransomware_detector"] = {
        "available": True,
        "active": bool(e.system_engine_running and e.endpoint_security_subscriptions_active),
        "model_version": ADAPTIVE_MODEL_VERSION,
        "signature_independent": True,
        "requires_process_attribution": True,
        "degraded_observer_supported": False,
    }
    return AntiRansomwareHealth(state,mode,sensor_mode,e.sensor_artifact_exists,e.sensor_installed,e.sensor_loaded,e.sensor_running,e.sensor_signature_valid,e.sensor_team_id,e.sensor_signing_identifier,e.sensor_cdhash,e.sensor_architecture,e.sensor_version,e.sensor_heartbeat_fresh,e.entitlement_embedded,e.entitlement_accepted,not e.entitlement_accepted,e.tcc_approval_present,e.tcc_approval_present,e.privacy_approval_source,e.endpoint_security_connected,e.endpoint_security_client_result,e.endpoint_security_subscriptions_active,e.endpoint_security_live_event_seen,e.endpoint_security_sequence_gap_detected,e.system_engine_running,e.system_engine_heartbeat_fresh,containment_state,e.containment_helper_installed,e.containment_helper_running,e.containment_ipc_authenticated,e.containment_identity_revalidation,r.active_containment_ready,e.notifier_required,e.notifier_running,e.notifier_authenticated,r.safe_simulation_ready,r.degraded_observation_ready,r.endpoint_security_observe_ready,r.active_containment_ready,r.full_active_protection,tuple(blocked),("APPLE_ENDPOINT_SECURITY_ENTITLEMENT",) if not e.entitlement_accepted else (),tuple(repair),tuple(contributions),tuple(errors),error_code,message,badge,limitations, (transition,),sensor_details,e.self_integrity_valid,e.policy_signature_valid,e.rule_package_signature_valid)
