from pathlib import Path
from mac_audit_agent.not_signed.actions import create_removal_plan
from mac_audit_agent.not_signed.models import InstalledSoftwareItem,SigningAssessment,SoftwareTrustClassification
from mac_audit_agent.not_signed.protected_items import protected_path,protected_process
from mac_audit_agent.not_signed.signing_assessor import SigningAssessor,parse_codesign,parse_spctl
from mac_audit_agent.not_signed.trust_store import TrustStore
from mac_audit_agent.performance.subprocess_runner import BoundedCommandResult
def result(code,out="",err=""): return BoundedCommandResult([],code,out,err,"","")
def test_codesign_and_gatekeeper_parsers_distinguish_developer_and_notarization():
    code=parse_codesign(result(0,"","Identifier=x\nTeamIdentifier=TEAM\nAuthority=Developer ID Application: Example\nCDHash=abc")); gate=parse_spctl(result(0,"","accepted\nsource=Notarized Developer ID")); assert code["valid"] and code["team_id"]=="TEAM" and gate["notarized"] is True
def test_unsigned_and_modified_are_distinct():
    assert parse_codesign(result(1,"","code object is not signed at all"))["unsigned"] is True
    assert parse_codesign(result(1,"","a sealed resource is missing or invalid; modified"))["modified"] is True
def test_platform_signature_is_not_misclassified_as_ad_hoc():
    code=parse_codesign(result(0,"","Identifier=com.apple.Finder\nTeamIdentifier=not set\nSignature=adhoc\nCodeDirectory v=20500 size=1 flags=0x20000(platform) hashes=1"))
    code["valid"]=True
    classification=SigningAssessor._classify(Path("/System/Library/CoreServices/Finder.app"),code,{"accepted":None,"source":"Apple System","revoked":False},False)
    assert code["platform_binary"] is True
    assert classification == SoftwareTrustClassification.APPLE_PLATFORM
def test_explicit_ad_hoc_third_party_stays_ad_hoc(tmp_path):
    code=parse_codesign(result(0,"","Identifier=local.tool\nTeamIdentifier=not set\nSignature=adhoc"))
    code["valid"]=True
    assert SigningAssessor._classify(tmp_path/"tool",code,{"accepted":None,"source":"","revoked":False},False) == SoftwareTrustClassification.AD_HOC
def test_protected_paths_and_processes():
    assert protected_path(Path("/System/Applications/Finder.app"))[0]; assert protected_process(1,"launchd",Path("/sbin/launchd"))[0]
def test_removal_plan_never_selects_protected_or_user_data(tmp_path):
    assessment=SigningAssessment(SoftwareTrustClassification.UNSIGNED,False,False,False); item=InstalledSoftwareItem("x","x",tmp_path/"x",None,None,None,None,assessment)
    plan=create_removal_plan(item); assert plan.reversible and not plan.requires_admin and plan.selected_files==()
def test_trust_invalidates_on_any_identity_change():
    record={"file_hash":"a","bundle_id":"b","team_id":"c","canonical_path":"/x"}; assert TrustStore.valid(record,file_hash="a",bundle_id="b",team_id="c",canonical_path="/x"); assert not TrustStore.valid(record,file_hash="z",bundle_id="b",team_id="c",canonical_path="/x")
