from mac_audit_agent.anti_ransomware.readiness import ReadinessEvidence, evaluate_readiness


def test_readiness_levels_do_not_collapse_or_infer_active_protection():
    result = evaluate_readiness(ReadinessEvidence(algorithms_passed=True, safe_simulation_passed=True, degraded_observer_passed=True))
    assert result["ALGORITHM_TESTED"]
    assert result["SAFE_SIMULATION_TESTED"]
    assert result["DEGRADED_OBSERVATION_READY"]
    assert not result["ENDPOINT_SECURITY_OBSERVE_READY"]
    assert not result["ACTIVE_CONTAINMENT_READY"]
    assert not result["PUBLIC_RELEASE_READY"]


def test_active_containment_requires_all_live_predicates():
    evidence = ReadinessEvidence(signed_entitled_sensor=True, live_es_events=True, durable_incidents=True, authenticated_ipc=True, live_containment=True)
    assert not evaluate_readiness(evidence)["ACTIVE_CONTAINMENT_READY"]
    evidence = ReadinessEvidence(**(evidence.__dict__ | {"containment_watchdog": True}))
    assert evaluate_readiness(evidence)["ACTIVE_CONTAINMENT_READY"]
