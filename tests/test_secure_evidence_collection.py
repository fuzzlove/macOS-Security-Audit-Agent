from pathlib import Path
import json,zipfile,pytest
from mac_audit_agent.secure_evidence_collection import *
def repo(tmp_path):return EvidenceRepository(tmp_path/"repository",tmp_path/"evidence.sqlite3","test-1")
def test_collection_hash_manifest_permissions_and_chain(tmp_path:Path):
 r=repo(tmp_path);c=r.create_case("analyst","Ransomware investigation","critical",["alert-1"]);result=r.collect_snapshot(c.case_id,"analyst",{"processes":lambda:[{"pid":1,"path":"/bin/test"}],"network":lambda:[]});a=result["artifacts"][0];assert r.verify(a["evidence_id"],"analyst")=="MATCH";assert Path(a["artifact_path"]).stat().st_mode&0o077==0;assert r.verify_custody_chain();assert Path(result["manifest"]).is_file()
def test_modification_is_detected_and_export_blocked(tmp_path:Path):
 r=repo(tmp_path);c=r.create_case("a","case","high");a=r.add_json(c.case_id,"x.json",{"safe":True},"a","test");Path(a.artifact_path).write_text("tampered");assert r.verify(a.evidence_id,"a")=="MODIFIED"
 with pytest.raises(EvidenceError,match="blocked"):r.export_zip(c.case_id,tmp_path/"x.zip","a")
def test_custody_records_view_verify_export_and_zip_manifest(tmp_path:Path):
 r=repo(tmp_path);c=r.create_case("a","case","high");r.add_json(c.case_id,"x.json",{"safe":True},"a","test");z=r.export_zip(c.case_id,tmp_path/"case.zip","a");assert z.is_file() and z.with_suffix(".zip.sha256").is_file();assert any(x["action"]=="EXPORTED" for x in r.timeline(c.case_id));assert "manifest/evidence_manifest.json" in zipfile.ZipFile(z).namelist()
def test_partial_collection_failure_is_visible(tmp_path:Path):
 r=repo(tmp_path);c=r.create_case("a","case","medium");result=r.collect_snapshot(c.case_id,"a",{"denied":lambda:(_ for _ in()).throw(PermissionError("denied"))});assert result["errors"]["denied"]["error_type"]=="PermissionError";assert any(x["action"]=="COLLECTION_FAILED" for x in r.timeline(c.case_id))
def test_secret_fields_are_rejected(tmp_path:Path):
 r=repo(tmp_path);c=r.create_case("a","case","medium")
 with pytest.raises(EvidenceError,match="secret-bearing"):r.add_json(c.case_id,"bad.json",{"password":"no"},"a","test")
