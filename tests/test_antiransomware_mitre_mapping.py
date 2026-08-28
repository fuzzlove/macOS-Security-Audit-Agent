from mac_audit_agent.anti_ransomware.mitre_mapping import map_behaviors


def test_mapping_has_confidence_and_requires_exfiltration_evidence():
    mapped = map_behaviors(["encryption_burst", "supported_exfiltration"], {"encryption_burst": ["event-1"]})
    assert [item.technique_id for item in mapped] == ["T1486"]
    assert mapped[0].confidence
