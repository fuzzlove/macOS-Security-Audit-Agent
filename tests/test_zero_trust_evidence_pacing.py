from mac_audit_agent.zero_trust.evidence_pacing import EvidenceMark,detect_rapid_collection

def test_distinct_controls_in_short_window_trigger_review():
    marks=[EvidenceMark(f"control-{index}",f"2026-07-20T10:00:{index:02d}+00:00") for index in range(4)]
    result=detect_rapid_collection(marks,minimum_distinct_controls=4,window_seconds=120)
    assert result["detected"] and result["distinct_controls"]==4

def test_repeated_same_control_and_spread_out_work_do_not_trigger():
    repeated=[EvidenceMark("same",f"2026-07-20T10:00:{index:02d}+00:00") for index in range(4)]
    spread=[EvidenceMark(f"c-{index}",f"2026-07-20T10:{index*3:02d}:00+00:00") for index in range(4)]
    assert not detect_rapid_collection(repeated)["detected"]
    assert not detect_rapid_collection(spread)["detected"]
