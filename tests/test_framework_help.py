from mac_audit_agent.help.help_registry import get_help_topic,search_help_topics


def test_framework_help_topics_cover_each_matrix_and_evidence_expectations():
    topic_ids={"framework_coverage","framework_nist_csf","framework_mitre_attack","framework_nist_800_53","framework_cmmc_dod","framework_evidence_expectations"}
    topics=[get_help_topic(topic_id) for topic_id in topic_ids]
    assert all(topics)
    assert all(topic.what_you_should_do for topic in topics)
    assert "C3PAO" in get_help_topic("framework_cmmc_dod").content
    assert "examine" in get_help_topic("framework_nist_800_53").content.lower()
    assert "not maturity levels" in get_help_topic("framework_nist_csf").content
    assert "100 percent" in get_help_topic("framework_mitre_attack").content
    assert {topic.topic_id for topic in search_help_topics("client")} & topic_ids


def test_framework_help_keeps_assurance_limitations_explicit():
    overview=get_help_topic("framework_coverage")
    cmmc=get_help_topic("framework_cmmc_dod")
    assert any("does not certify" in note for note in overview.safety_notes)
    assert any("Do not label" in note for note in cmmc.safety_notes)
