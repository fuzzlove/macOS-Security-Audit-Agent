from mac_audit_agent.anti_ransomware.models import DetectionSignal
from mac_audit_agent.anti_ransomware.risk_engine import decide


def test_explainable_high_confidence_and_continuity_exclusion():
    signals = [DetectionSignal("encrypted_burst", 60, "five encrypted-looking outputs"), DetectionSignal("canary", 30, "approved synthetic canary changed")]
    normal = decide(signals)
    excluded = decide(signals, critical_continuity=True)
    assert normal.score == 90 and normal.automatic_response_eligible
    assert excluded.score == 90 and not excluded.automatic_response_eligible
    assert excluded.recommended_response == "manual_review"
