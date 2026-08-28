from mac_audit_agent.anti_ransomware.standards_mapping import map_readiness


def test_framework_classifications_remain_separate():
    values = map_readiness(audit_logging=False, recovery_ready=False, containment_policy=False)
    classifications = {item.classification for item in values}
    assert {"cmmc_readiness_issue", "nist_control_gap", "cisa_ransomware_guidance_gap"} <= classifications
    assert all("not certification" in item.disclaimer for item in values)
