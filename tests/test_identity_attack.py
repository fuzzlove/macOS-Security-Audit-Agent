from pathlib import Path
import json,pytest
from mac_audit_agent.identity_attack import *
from mac_audit_agent.storage import AuditDatabase
def detector(tmp_path):
 shared=AuditDatabase(tmp_path/"audit.sqlite3");return shared,IdentityAttackDetector(IdentityEventStore(tmp_path/"identity.sqlite3"),shared)
def test_keychain_and_browser_require_trusted_metadata_and_never_secrets(tmp_path:Path):
 _,d=detector(tmp_path);base={"trusted_process_telemetry":True,"signature_status":"unsigned","process_path":"/private/tmp/x","username":"u"}
 assert d.process({**base,"event_type":"keychain_access","resource_accessed":"login.keychain-db"}).mitre_attack==["T1555.001"]
 assert d.process({**base,"event_type":"browser_credential_access","resource_accessed":"Safari credential store metadata"}).mitre_attack==["T1555.003"]
 with pytest.raises(IdentityDetectionError):d.process({**base,"event_type":"keychain_access","password":"no"})
def test_account_admin_change_is_critical_and_shared(tmp_path:Path):
 shared,d=detector(tmp_path);e=d.process({"event_type":"account_change","administrator_added":True,"username":"actor","identity_action":"admin_added"});assert e.severity=="critical" and e.mitre_attack==["T1098"];assert shared.recent_background_monitor_events(limit=1)[0].event_id==e.event_id
def test_ssh_change_and_privilege_false_positive_context(tmp_path:Path):
 _,d=detector(tmp_path);assert d.process({"event_type":"ssh_identity_change","username":"u","resource_accessed":"authorized_keys fingerprint changed"}).severity=="high"
 assert d.process({"event_type":"privilege_escalation","failure_count":5,"approved_maintenance":True,"username":"admin"}) is None
def test_authentication_aggregates_counts_not_passwords(tmp_path:Path):
 _,d=detector(tmp_path);e=d.process({"event_type":"authentication_event","failure_count":8,"new_source":True,"username":"u"});assert "T1078" in e.mitre_attack;assert "password" not in json.dumps(e.to_dict()).lower() or "no attempted passwords collected" in json.dumps(e.to_dict()).lower()
def test_identity_commands_require_behavioral_context(tmp_path:Path):
 _,d=detector(tmp_path);assert d.process({"event_type":"identity_command","commands":["id"],"signature_status":"apple"}) is None;assert d.process({"event_type":"identity_command","commands":["id","groups"],"signature_status":"unsigned"}).mitre_attack==["T1087"]
def test_baseline_detects_new_admin_without_credentials(tmp_path:Path):
 b=IdentityBaseline(tmp_path/"b.json");b.save([{"username":"a","admin":False}],[]);c=b.compare_accounts([{"username":"a","admin":True},{"username":"b","admin":False}]);assert c["new_admins"][0]["username"]=="a" and c["new_accounts"][0]["username"]=="b"
