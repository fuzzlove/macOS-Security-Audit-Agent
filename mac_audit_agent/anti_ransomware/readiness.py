from __future__ import annotations

from dataclasses import dataclass
from mac_audit_agent.compat.enum import StrEnum
from .health import RuntimeEvidence, evaluate_readiness as evaluate_protection_readiness


class ReadinessLevel(StrEnum):
    ALGORITHM_TESTED = "ALGORITHM_TESTED"
    SAFE_SIMULATION_TESTED = "SAFE_SIMULATION_TESTED"
    DEGRADED_OBSERVATION_READY = "DEGRADED_OBSERVATION_READY"
    ENDPOINT_SECURITY_OBSERVE_READY = "ENDPOINT_SECURITY_OBSERVE_READY"
    ACTIVE_CONTAINMENT_READY = "ACTIVE_CONTAINMENT_READY"
    MANAGED_DEPLOYMENT_READY = "MANAGED_DEPLOYMENT_READY"
    SCHOOL_PROFILE_READY = "SCHOOL_PROFILE_READY"
    GOVERNMENT_PROFILE_READY = "GOVERNMENT_PROFILE_READY"
    PUBLIC_RELEASE_READY = "PUBLIC_RELEASE_READY"


@dataclass(frozen=True)
class ReadinessEvidence:
    algorithms_passed: bool = False
    safe_simulation_passed: bool = False
    degraded_observer_passed: bool = False
    signed_entitled_sensor: bool = False
    live_es_events: bool = False
    durable_incidents: bool = False
    authenticated_ipc: bool = False
    live_containment: bool = False
    containment_watchdog: bool = False
    signed_installer: bool = False
    deployment_lifecycle_tested: bool = False
    accessibility_verified: bool = False
    low_resource_qualified: bool = False
    government_profile_tested: bool = False
    performance_qualified: bool = False
    all_release_gaps_closed: bool = False


def evaluate_readiness(evidence: ReadinessEvidence) -> dict[str, bool]:
    algorithm = evidence.algorithms_passed
    simulation = algorithm and evidence.safe_simulation_passed
    degraded = simulation and evidence.degraded_observer_passed
    canonical=evaluate_protection_readiness(RuntimeEvidence(build_id="compat",current_build_id="compat",boot_session_id="compat",current_boot_session_id="compat",fresh=True,sensor_artifact_exists=evidence.signed_entitled_sensor,sensor_installed=evidence.signed_entitled_sensor,sensor_loaded=evidence.signed_entitled_sensor,sensor_running=evidence.signed_entitled_sensor,sensor_signature_valid=evidence.signed_entitled_sensor,entitlement_embedded=evidence.signed_entitled_sensor,entitlement_accepted=evidence.signed_entitled_sensor,tcc_approval_present=evidence.signed_entitled_sensor,endpoint_security_connected=evidence.live_es_events,endpoint_security_subscriptions_active=evidence.live_es_events,endpoint_security_live_event_seen=evidence.live_es_events,sequence_tracking_active=evidence.live_es_events,sensor_heartbeat_fresh=evidence.live_es_events,incident_storage_available=evidence.durable_incidents,containment_helper_installed=evidence.authenticated_ipc,containment_helper_running=evidence.authenticated_ipc,containment_ipc_authenticated=evidence.authenticated_ipc,containment_identity_revalidation=evidence.live_containment,containment_lease_watchdog_passed=evidence.containment_watchdog,live_fixture_pause_passed=evidence.live_containment,live_fixture_resume_passed=evidence.live_containment,live_fixture_termination_passed=evidence.live_containment,crash_recovery_passed=evidence.live_containment,no_orphaned_suspended_fixture=evidence.live_containment))
    es_observe=canonical.endpoint_security_observe_ready
    containment=canonical.active_containment_ready
    managed = containment and evidence.signed_installer and evidence.deployment_lifecycle_tested
    school = managed and evidence.accessibility_verified and evidence.low_resource_qualified
    government = managed and evidence.government_profile_tested
    public = managed and school and government and evidence.performance_qualified and evidence.all_release_gaps_closed
    values = (algorithm, simulation, degraded, es_observe, containment, managed, school, government, public)
    return dict(zip((level.value for level in ReadinessLevel), values, strict=True))
