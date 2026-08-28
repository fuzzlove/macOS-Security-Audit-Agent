from pathlib import Path
from mac_audit_agent.supply_chain_security import *
from mac_audit_agent.not_signed.models import *
from mac_audit_agent.storage import AuditDatabase
def item(tmp_path,classification):
 p=tmp_path/"tool";p.write_text("fixture");return InstalledSoftwareItem("i","Fixture",p,None,"com.test","1",None,SigningAssessment(classification,classification not in {SoftwareTrustClassification.UNSIGNED,SoftwareTrustClassification.INVALID},None,None))
def test_unsigned_is_review_not_malware_and_shared(tmp_path:Path):
 shared=AuditDatabase(tmp_path/"a.db");e=SupplyChainEngine(SupplyChainStore(tmp_path/"s.db"),shared);f=e.assess_application(item(tmp_path,SoftwareTrustClassification.UNSIGNED),"a"*64)[0];assert f.severity=="medium" and "Do not remove solely" in f.recommendation;assert shared.recent_background_monitor_events(1)
def test_modified_trusted_application_is_critical(tmp_path:Path):
 e=SupplyChainEngine(SupplyChainStore(tmp_path/"s.db"));f=e.assess_application(item(tmp_path,SoftwareTrustClassification.DEVELOPER_ID_NOTARIZED),"b"*64,"a"*64)[0];assert f.severity=="critical" and len(f.evidence)==2
def test_local_package_inventory_no_execution(tmp_path:Path):
 (tmp_path/"package.json").write_text('{"dependencies":{"safe-package":"1.0.0"}}');a=SupplyChainEngine(SupplyChainStore(tmp_path/"s.db")).inventory_project(tmp_path);assert a.occurrences[0].declared_identifier=="safe-package"
def test_exact_advisory_match_only(tmp_path:Path):
 e=SupplyChainEngine(SupplyChainStore(tmp_path/"s.db"));assert not e.match_advisories([{"ecosystem":"npm","name":"x","version":"2"}],[{"ecosystem":"npm","name":"x","version":"1","advisory_id":"CVE-X"}]);assert e.match_advisories([{"ecosystem":"npm","name":"x","version":"1"}],[{"ecosystem":"npm","name":"x","version":"1","advisory_id":"CVE-X"}])[0].cve_reference==["CVE-X"]
def test_install_script_static_analysis_does_not_execute(tmp_path:Path):
 marker=tmp_path/"executed";e=SupplyChainEngine(SupplyChainStore(tmp_path/"s.db"));f=e.analyze_install_script("x",f"curl https://example.invalid/x; touch {marker}; launchctl load x","npm");assert f.severity in {"high","critical"} and not marker.exists()
def test_report_is_hashed_and_restricted(tmp_path:Path):
 e=SupplyChainEngine(SupplyChainStore(tmp_path/"s.db"));e.analyze_install_script("x","curl https://example.invalid","npm");p=e.report(tmp_path/"r.json");assert p.is_file() and p.with_suffix(".json.sha256").is_file() and p.stat().st_mode&0o077==0
