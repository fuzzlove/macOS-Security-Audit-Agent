import json,pytest
from mac_audit_agent.supply_chain_trust_graph import *
from mac_audit_agent.models import ScanResult
from mac_audit_agent.reporting import export_scan_result_html,export_scan_result_json

TS="2026-07-17T10:00:00Z"
def software(**kw):
 d={"software_id":"app-1","name":"Example Tool","version":"1.0","bundle_identifier":"com.example.tool","developer":"Example Corp","team_id":"TEAM1","signature_status":"valid","notarized":True,"certificate_id":"cert-1","certificate_valid":True,"sha256":"a"*64,"package_source":"vendor","source_verified":True,"dependencies":[{"name":"lib-a","version":"1.2","source":"PyPI","evidence_reference":["lock:1"]}],"evidence_reference":["inventory:app-1","signature:app-1"]};d.update(kw);return d

def test_inventory_developer_certificate_dependency_graph():
 g=SupplyChainTrustGraphEngine().build([software(build_identity="build-42")],timestamp=TS);types={x.entity_type for x in g.entities};rels={x.relationship_type for x in g.relationships}
 assert {"software","developer","certificate","build","package_source","dependency"}.issubset(types);assert {"developed_by","signed_by","built_as","distributed_by","depends_on"}.issubset(rels)
 assert next(x for x in g.entities if x.entity_type=="developer").attributes["trust_score"]==90
 assert g.software_trust[0].trust_score>=85 and SupplyChainTrustGraphEngine.verify_integrity(g)

def test_unsigned_is_review_not_malicious():
 g=SupplyChainTrustGraphEngine().build([software(signature_status="unsigned",notarized=False,certificate_id="")],timestamp=TS);r=g.software_trust[0]
 assert r.trust_state=="review" and any("not automatically malicious" in x for x in r.reasons)

def test_invalid_certificate_reduces_trust():
 good=SupplyChainTrustGraphEngine().build([software()],timestamp=TS).software_trust[0]
 bad=SupplyChainTrustGraphEngine().build([software(certificate_valid=False,signature_status="invalid")],timestamp=TS).software_trust[0]
 assert bad.trust_score<good.trust_score and bad.trust_state=="high_risk"

def test_vulnerable_dependency_correlation():
 vuln={"component":"lib-a","cve_id":"CVE-2026-12345","severity":"critical","evidence_reference":["advisory:1"]}
 g=SupplyChainTrustGraphEngine().build([software()],vulnerabilities=[vuln],timestamp=TS)
 assert any(x.entity_type=="vulnerability" for x in g.entities);assert any(x.relationship_type=="affected_by" for x in g.relationships);assert g.software_trust[0].trust_score<100

def test_cyclonedx_and_spdx_sbom_ingestion():
 cycl={"bomFormat":"CycloneDX","evidence_reference":["sbom:cdx"],"components":[{"bom-ref":"a","name":"a","version":"1"},{"bom-ref":"b","name":"b","version":"2"}],"dependencies":[{"ref":"a","dependsOn":["b"]}]}
 spdx={"spdxVersion":"SPDX-2.3","evidence_reference":["sbom:spdx"],"packages":[{"SPDXID":"SPDXRef-A","name":"a","versionInfo":"1"},{"SPDXID":"SPDXRef-B","name":"b","versionInfo":"2"}],"relationships":[{"spdxElementId":"SPDXRef-A","relationshipType":"DEPENDS_ON","relatedSpdxElement":"SPDXRef-B"}]}
 assert SupplyChainTrustGraphEngine().build([],sbom=cycl,timestamp=TS).sbom_status=="cyclonedx_parsed"
 assert SupplyChainTrustGraphEngine().build([],sbom=spdx,timestamp=TS).sbom_status=="spdx_parsed"

def test_typosquatting_relationship_is_qualified():
 finding={"package_name":"requ3sts","target_package":"requests","confidence":"high","evidence_reference":["typo:1"]}
 g=SupplyChainTrustGraphEngine().build([software(dependencies=[{"name":"requ3sts","version":"1","evidence_reference":["lock:1"]}])],typosquatting=[finding],timestamp=TS)
 rel=next(x for x in g.relationships if x.relationship_type=="similar_to");assert "does not establish maliciousness" in rel.explanation

def test_update_identity_change_reduces_trust():
 change={"software_id":"app-1","previous_certificate":"cert-1","current_certificate":"cert-2","previous_source":"vendor","current_source":"mirror","evidence_reference":["update:1"]}
 base=SupplyChainTrustGraphEngine().build([software()],timestamp=TS).software_trust[0].trust_score
 changed=SupplyChainTrustGraphEngine().build([software()],update_history=[change],timestamp=TS).software_trust[0].trust_score
 graph=SupplyChainTrustGraphEngine().build([software()],update_history=[change],timestamp=TS)
 assert changed==base-20 and any(x.relationship_type=="updated_from" for x in graph.relationships)

def test_intelligence_requires_source_fields_and_does_not_claim_malice():
 invalid={"indicator_type":"hash","indicator_value":"a"*64,"source":"","timestamp":TS,"confidence":"high","reference":""}
 valid={"indicator_type":"hash","indicator_value":"a"*64,"source":"vendor intel","timestamp":TS,"confidence":"high","reference":"https://example.invalid/advisory"}
 e=SupplyChainTrustGraphEngine();base=e.build([software()],threat_intelligence=[invalid],timestamp=TS).software_trust[0];matched=e.build([software()],threat_intelligence=[valid],timestamp=TS).software_trust[0]
 assert matched.trust_score==base.trust_score-25 and "malicious" not in " ".join(matched.reasons).lower()
 graph=e.build([software()],threat_intelligence=[valid],timestamp=TS)
 assert any(x.relationship_type=="matched_intelligence" and "not proof of compromise" in x.explanation for x in graph.relationships)

def test_spdx_does_not_create_dangling_relationships():
 sbom={"spdxVersion":"SPDX-2.3","evidence_reference":["sbom:1"],"packages":[{"SPDXID":"SPDXRef-A","name":"a"}],"relationships":[{"spdxElementId":"SPDXRef-A","relationshipType":"DEPENDS_ON","relatedSpdxElement":"SPDXRef-Missing"}]}
 graph=SupplyChainTrustGraphEngine().build([],sbom=sbom,timestamp=TS)
 assert not graph.relationships

def test_sensitive_attributes_removed():
 g=SupplyChainTrustGraphEngine().build([software(password="no",access_token="secret")],timestamp=TS);p=json.dumps(g.to_dict());assert '"password"' not in p and '"access_token"' not in p

def test_ai_and_incident_remain_decision_support():
 e=SupplyChainTrustGraphEngine();g=e.build([software(signature_status="invalid",certificate_valid=False)],timestamp=TS);ctx=e.analyst_context(g,"app-1");incident=e.incident_context(g,"app-1")
 assert "Do not infer malicious" in ctx["guardrail"] and incident["authorization_required"] and not incident["automatic_removal"]

def test_repository_tamper_detection(tmp_path):
 g=SupplyChainTrustGraphEngine().build([software()],timestamp=TS);r=SupplyChainTrustRepository(tmp_path/"g.db");r.save(g);assert r.latest()["graph_id"]==g.graph_id
 r.conn.execute("UPDATE supply_trust_graphs SET payload_json=replace(payload_json,'\"trust_score\":88','\"trust_score\":1')");r.conn.commit()
 with pytest.raises(ValueError):r.latest()
 r.close()

def test_reports_and_dashboard_show_trust_and_sbom(tmp_path):
 g=SupplyChainTrustGraphEngine().build([software()],timestamp=TS);artifact={"graph":g.to_dict()};scan=ScanResult("s1",TS,"mac","analyst",collected_artifacts={"supply_chain_trust_graph":artifact});jp=export_scan_result_json(scan,tmp_path/"g.json");hp=export_scan_result_html(scan,tmp_path/"g.html");p=json.loads(jp.read_text());h=hp.read_text();assert p["supply_chain_trust_graph"]["graph"]["software_trust"] and p["report_summary"]["supply_chain_trust_graph"]["graph"]["sbom_status"]=="not_provided";assert "Supply Chain Trust Graph" in h and "not automatically malicious" in h
 from PySide6.QtWidgets import QApplication
 from mac_audit_agent.ui.supply_chain_trust_graph_panel import SupplyChainTrustGraphPanel
 app=QApplication.instance() or QApplication([]);panel=SupplyChainTrustGraphPanel();panel.set_graph(artifact);assert panel.table.rowCount()==1 and "Software: 1" in panel.summary.text();panel.close()
