import pytest

from mac_audit_agent.zero_trust import ZeroTrustPostureEngine
from mac_audit_agent.zero_trust.routes import POSTURE_ROUTES, route_for_signal


def test_every_posture_signal_has_review_and_validation_route() -> None:
    signals = ZeroTrustPostureEngine().calculate({}).signals
    assert {signal.signal_id for signal in signals} == set(POSTURE_ROUTES)
    for signal in signals:
        route = route_for_signal(signal.signal_id)
        assert route.page and route.validation and route.explanation
        assert route.automatic_method
        assert len(route.manual_steps) >= 2
        assert route.evidence_fields


def test_routes_land_on_specific_authoritative_sections() -> None:
    assert route_for_signal("unsigned_applications").view_filter == "Unsigned Only"
    assert route_for_signal("unapproved_persistence_items").page == "Persistence Intelligence"
    assert route_for_signal("suspicious_outbound_connections").page == "Network Intelligence"
    assert route_for_signal("firewall_enabled").page == "Firewall"
    assert "FileVault" in route_for_signal("filevault_enabled").automatic_method
    assert any("unknown" in step.lower() for step in route_for_signal("secure_boot_verified").manual_steps)


def test_unknown_signal_cannot_silently_fall_back() -> None:
    with pytest.raises(ValueError, match="No evidence route"):
        route_for_signal("missing_control")
