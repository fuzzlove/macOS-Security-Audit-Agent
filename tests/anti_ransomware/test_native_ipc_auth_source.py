from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_native_authentication_uses_audit_token_and_code_requirement_not_pid():
    source = (ROOT / "native/anti_ransomware_sensor/ipc_peer_auth.m").read_text(encoding="utf-8")
    assert "kSecGuestAttributeAudit" in source
    assert "SecCodeCopyGuestWithAttributes" in source
    assert "SecCodeCheckValidity" in source
    assert "kSecCodeInfoTeamIdentifier" in source
    assert "kSecCodeInfoIdentifier" in source
    assert "kSecCodeSignatureAdhoc" in source
    assert "getpid(" not in source and "pid_t" not in source
