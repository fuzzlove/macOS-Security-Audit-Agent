import json,pytest
from mac_audit_agent.software_attestation import *
from mac_audit_agent.models import ScanResult
from mac_audit_agent.reporting import export_scan_result_html,export_scan_result_json

TS="2026-07-17T12:00:00Z";GOOD="a"*64;BAD="b"*64
def app(**kw):
 d={"application_id":"app-1","name":"Example.app","bundle_identifier":"com.example.app","version":"1.0","build_number":"10","developer":"Example Corp","team_id":"TEAM1","certificate_id":"cert-1","signature_status":"valid","sha256":GOOD,"notarization_status":"accepted","gatekeeper_status":"accepted","installation_source":"vendor","installation_date":"2026-01-01","first_seen":TS,"sbom_available":True,"evidence_reference":["inventory:1","signature:1","hash:1"]};d.update(kw);return d
def baseline(**kw):
 d={"baseline_id":"base-1","profile":"government","application_id":"app-1","approved_versions":["1.0"],"approved_hashes":[GOOD],"approved_developers":["Example Corp"],"approved_team_ids":["TEAM1"],"approved_sources":["vendor"],"require_valid_signature":True,"require_notarization":True,"require_sbom":True,"evidence_reference":["approval:1"]};d.update(kw);return TrustedSoftwareBaseline(**d)

def test_valid_signed_application_is_verified_and_integrity_bound():
 a=SoftwareAttestationEngine().attest([app()],[baseline()],device_id="mac-1",profile="government",timestamp=TS);r=a.results[0]
 assert r.trust_state=="verified" and r.trust_score==100 and r.integrity_status=="verified";assert SoftwareAttestationEngine.verify_integrity(a)
 assert all(x.result=="approved" for x in r.policy_results)

def test_modified_hash_is_failed_without_compromise_claim():
 r=SoftwareAttestationEngine().attest([app(sha256=BAD)],[baseline()],device_id="mac-1",timestamp=TS).results[0]
 assert r.integrity_status=="modified" and r.trust_state=="failed" and "binary_hash_changed" in r.change_types
 assert "compromise" not in " ".join(r.reasons).lower()

def test_bundle_and_resource_changes_preserve_responsible_process_context():
 b=baseline(approved_bundle_hashes=("bundle-good",),approved_resource_hashes=("resource-good",));r=SoftwareAttestationEngine().attest([app(bundle_hash="bundle-bad",resource_hash="resource-bad",responsible_process="vendor-updater")],[b],device_id="mac-1",timestamp=TS).results[0]
 assert r.integrity_status=="modified" and {"bundle_hash_changed","resource_hash_changed"}.issubset(r.change_types);assert r.application.responsible_process=="vendor-updater"

def test_invalid_signature_and_developer_change_are_detected():
 r=SoftwareAttestationEngine().attest([app(signature_status="invalid",developer="Unknown",team_id="OTHER")],[baseline()],device_id="mac-1",timestamp=TS).results[0]
 assert r.identity_status=="failed" and {"signature_failure","provenance_changed"}.issubset(r.change_types)
 assert any(x.administrator_approval_required for x in r.policy_results) and r.to_event()["hash_after"]==GOOD

def test_missing_baseline_is_review_not_false_failure():
 r=SoftwareAttestationEngine().attest([app()],[],device_id="mac-1",timestamp=TS).results[0]
 assert r.trust_state=="review" and "No approved baseline" in r.unknowns[0]

def test_dependency_vulnerability_and_behavior_reduce_confidence():
 graph={"software_trust":[{"software_id":"app-1","trust_state":"high_risk","evidence_reference":["graph:1"]}]};exposure={"exposures":[{"affected_component":"Example.app","severity":"critical","exploit_status":"known_exploited","evidence_reference":["kev:1"]}]};posture={"risk_paths":[{"application":"app-1","behavior":"persistence","evidence_reference":["path:1"]}]}
 base=SoftwareAttestationEngine().attest([app()],[baseline()],device_id="mac-1",timestamp=TS).results[0];r=SoftwareAttestationEngine().attest([app()],[baseline()],device_id="mac-1",trust_graph=graph,exposure_assessment=exposure,posture_graph=posture,timestamp=TS).results[0]
 assert r.trust_score<base.trust_score and r.exposure_status=="elevated" and r.behavior_status=="review";assert {"graph:1","kev:1","path:1"}.issubset(r.evidence_reference)

def test_sensitive_input_is_not_persisted_and_evidence_request_is_controlled():
 e=SoftwareAttestationEngine();r=e.attest([app(access_token="secret",password="no")],[baseline(approved_hashes=(BAD,))],device_id="mac-1",timestamp=TS).results[0]
 assert "access_token" not in json.dumps(r.to_dict()) and not e.evidence_request(r)["automatic_collection"] and e.evidence_request(r)["authorization_required"]

def test_repository_verifies_integrity_and_detects_tamper(tmp_path):
 a=SoftwareAttestationEngine().attest([app()],[baseline()],device_id="mac-1",timestamp=TS);repo=SoftwareAttestationRepository(tmp_path/"a.db");repo.save(a);assert repo.latest()["assessment_id"]==a.assessment_id
 repo.conn.execute("UPDATE software_attestation_assessments SET payload_json=replace(payload_json,'\"trust_score\":100','\"trust_score\":1')");repo.conn.commit()
 with pytest.raises(ValueError):repo.latest()
 repo.close()

def test_reports_and_dashboard_present_attestation_without_actions(tmp_path):
 assessment=SoftwareAttestationEngine().attest([app()],[baseline()],device_id="mac-1",profile="government",timestamp=TS);artifact={"assessment":assessment.to_dict()};scan=ScanResult("s1",TS,"mac","analyst",collected_artifacts={"software_attestation":artifact});jp=export_scan_result_json(scan,tmp_path/"a.json");hp=export_scan_result_html(scan,tmp_path/"a.html");payload=json.loads(jp.read_text());html=hp.read_text()
 assert payload["software_attestation"]["assessment"]["results"] and payload["report_summary"]["software_attestation"]["assessment"]["profile"]=="government";assert "Software Attestation" in html and "does not by itself prove compromise" in html
 from PySide6.QtWidgets import QApplication
 from mac_audit_agent.ui.software_attestation_panel import SoftwareAttestationPanel
 application=QApplication.instance() or QApplication([]);panel=SoftwareAttestationPanel();panel.set_assessment(artifact);assert panel.table.rowCount()==1 and "Verified: 1" in panel.summary.text();labels=[x.text().lower() for x in panel.findChildren(type(panel.summary))];assert any("no software is modified" in x for x in labels);panel.close()
