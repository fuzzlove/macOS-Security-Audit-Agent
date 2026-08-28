from mac_audit_agent.anti_ransomware.status import get_status


def test_status_never_overclaims_protection():
    status = get_status()
    assert status["guaranteed_protection"] is False
    if status["state"] != "fully_protected":
        assert status["limitations"]
