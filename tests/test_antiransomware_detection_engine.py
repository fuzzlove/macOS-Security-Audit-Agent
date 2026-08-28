from mac_audit_agent.anti_ransomware.behavior_engine import BehaviorSignal, RansomwareBehaviorEngine, RiskState


def test_weak_signal_is_not_probable():
    result = RansomwareBehaviorEngine().evaluate([BehaviorSignal("rename", .4, 20, "rename burst")])
    assert result.risk_state is RiskState.SUSPICIOUS


def test_correlated_strong_signals_are_probable():
    signals = [BehaviorSignal("rewrite", .9, 40, "rewrite burst", high_confidence=True),
               BehaviorSignal("entropy", .9, 35, "entropy increased", high_confidence=True)]
    assert RansomwareBehaviorEngine().evaluate(signals).risk_state is RiskState.PROBABLE


def test_contained_requires_correlated_detection_and_explicit_policy_result():
    signals = [BehaviorSignal("rewrite", .9, 40, "rewrite burst", high_confidence=True),
               BehaviorSignal("entropy", .9, 35, "entropy increased", high_confidence=True)]
    result = RansomwareBehaviorEngine().evaluate(signals, containment_applied=True)
    assert result.risk_state is RiskState.CONTAINED
    assert result.to_dict()["threat_state"] == "CONTAINED"


def test_missing_sensor_does_not_claim_normal_threat_state():
    result = RansomwareBehaviorEngine().evaluate([], sensor_available=False)
    assert result.to_dict()["threat_state"] == "UNKNOWN"
