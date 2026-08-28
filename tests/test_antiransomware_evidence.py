import json
from mac_audit_agent.anti_ransomware.evidence import create_evidence_bundle


def test_evidence_is_metadata_only_and_hash_backed(tmp_path):
    result = create_evidence_bundle(tmp_path / "evidence.json", detection={"path": str(tmp_path), "file_content": "secret"})
    payload = json.loads((tmp_path / "evidence.json").read_text())
    assert payload["privacy"]["file_contents_included"] is False
    assert "file_content" not in payload["detection"]
    assert len(result["sha256"]) == 64
