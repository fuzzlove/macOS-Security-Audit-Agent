from mac_audit_agent.quality.audit_models import AuditReport, FunctionalCheck


def _report() -> AuditReport:
    return AuditReport(run_id="test", hostname="redacted", started_at="now")


def test_declared_alignment_contract_cannot_pass() -> None:
    report = _report()
    report.add(FunctionalCheck("settings.user_alert_agent_deliverability", "monitor", "alignment", "alignment", "blocker").passed(evidence={"deliverable": False}))
    assert report.checks[0].status == "BLOCKER"


def test_unrelated_nested_failure_does_not_override_check_contract() -> None:
    report = _report()
    report.add(FunctionalCheck("x", "monitor", "health", "health").passed(evidence={"rows": [{"status": "FAIL"}]}))
    assert report.checks[0].status == "PASS"


def test_unverified_required_work_prevents_readiness() -> None:
    report = _report()
    report.add(FunctionalCheck("x", "ui", "geometry", "geometry").not_verified("No display available"))
    assert report.readiness_decision == "NOT READY FOR USER TESTING"
    assert report.checks[0].duration_ms > 0
