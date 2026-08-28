from mac_audit_agent.anti_ransomware.advisory_sources import advisory_source_status


def test_government_sources_have_explicit_non_confabulating_roles():
    status = advisory_source_status()
    sources = {item["organization"]: item for item in status["sources"]}
    assert {"CISA", "NIST NVD", "FBI", "DoD Cyber Exchange", "INTERPOL"} <= set(sources)
    assert sources["NIST NVD"]["automation"] == "vulnerability_correlation"
    assert sources["FBI"]["automation"] == "human_review_only"
    assert sources["INTERPOL"]["automation"] == "human_review_only"
    assert status["automatic_rule_generation_from_narrative"] is False
    assert status["human_approval_required_before_rule_activation"] is True
    assert status["network_retrieval_by_privileged_sensor"] is False
