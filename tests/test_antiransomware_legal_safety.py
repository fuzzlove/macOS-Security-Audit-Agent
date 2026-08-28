import pytest
from mac_audit_agent.anti_ransomware.containment_policy import ContainmentPolicy
from mac_audit_agent.anti_ransomware.legal_safety import record_acceptance


def test_stronger_mode_requires_confirmation(tmp_path):
    with pytest.raises(PermissionError):
        record_acceptance(tmp_path / "acceptance.json", "strict_local_protection", confirmed=False)


def test_default_policy_is_non_destructive():
    policy = ContainmentPolicy()
    assert not policy.delete_files and policy.require_local_confirmation
