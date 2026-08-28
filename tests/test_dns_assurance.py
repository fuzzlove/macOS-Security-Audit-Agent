import json

from mac_audit_agent.dns_assurance import assess_dns_configuration, export_dns_report, load_dns_threat_intelligence, normalize_dns_servers


def test_dns_remains_concern_until_client_validation():
    collected=assess_dns_configuration(["1.1.1.1"],["1.1.1.1"],evidence_collected=True,client_validated=False)
    validated=assess_dns_configuration(["1.1.1.1"],["1.1.1.1"],evidence_collected=True,client_validated=True)
    assert collected.status=="concern" and validated.status=="validated"


def test_unapproved_and_invalid_addresses():
    assert normalize_dns_servers(["1.1.1.1","invalid","1.1.1.1"])==("1.1.1.1",)
    assert assess_dns_configuration(["8.8.8.8"],["1.1.1.1"],evidence_collected=True,client_validated=True).status=="concern"


def test_provenance_backed_threat_match_is_red_flag(tmp_path):
    path=tmp_path/"intel.json"; path.write_text(json.dumps({"schema_version":"1.0","source_name":"Approved internal intelligence","source_url":"https://intel.example/evidence","retrieved_at":"2026-07-20T00:00:00Z","indicators":[{"address":"203.0.113.10","reason":"Reported resolver","reference":"case-1"}]}))
    intelligence,status=load_dns_threat_intelligence(path); result=assess_dns_configuration(["203.0.113.10"],["203.0.113.10"],evidence_collected=True,client_validated=True,intelligence=intelligence,intelligence_status=status)
    assert result.status=="red flag" and result.threat_matches[0]["source_name"]=="Approved internal intelligence"
    for suffix in (".json", ".html", ".docx", ".xlsx"):
        export_dns_report(result,tmp_path/("dns"+suffix)); assert (tmp_path/("dns"+suffix)).is_file()


def test_malformed_intelligence_is_rejected(tmp_path):
    path=tmp_path/"bad.json"; path.write_text('{"indicators":[]}')
    try: load_dns_threat_intelligence(path)
    except ValueError: pass
    else: raise AssertionError("unprovenanced intelligence accepted")
