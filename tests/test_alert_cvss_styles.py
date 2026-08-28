from mac_audit_agent.alert_styles import cvss_alert_severity, get_alert_style, resolve_alert_severity


def test_cvss_bands_select_distinct_accessible_alert_styles() -> None:
    assert cvss_alert_severity(0) == "info"
    assert cvss_alert_severity(3.9) == "low"
    assert cvss_alert_severity(4.0) == "medium"
    assert cvss_alert_severity(7.0) == "high"
    assert cvss_alert_severity(9.0) == "critical"
    assert get_alert_style("critical").background == "#7A0000"


def test_explicit_cvss_evidence_controls_overlay_criticality() -> None:
    assert resolve_alert_severity("low", cvss_score=9.8) == "critical"
    assert resolve_alert_severity("critical", cvss_score=2.0) == "low"
