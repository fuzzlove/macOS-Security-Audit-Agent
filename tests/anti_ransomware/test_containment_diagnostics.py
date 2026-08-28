import json

from mac_audit_agent.anti_ransomware.cli import main
from mac_audit_agent.anti_ransomware.containment_diagnostics import containment_status


def test_source_diagnostics_do_not_claim_active_containment():
    status=containment_status()
    assert status["ACTIVE_CONTAINMENT_READY"] is False
    assert status["safety"]["arbitrary_pid_api"] is False
    assert status["state"] == "BLOCKED_CREDENTIALS"


def test_containment_cli_is_read_only_json_and_has_no_pid_action(capsys):
    assert main(["containment","doctor","--json"]) == 1
    payload=json.loads(capsys.readouterr().out)
    assert payload["operation"] == "doctor" and payload["ACTIVE_CONTAINMENT_READY"] is False
