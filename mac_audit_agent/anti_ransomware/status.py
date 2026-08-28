"""Shared CLI/UI anti-ransomware status contract."""

from .health import source_health
from mac_audit_agent.protection.status import resolve_active_protection_status


def get_status() -> dict:
    health = source_health()
    protection = resolve_active_protection_status()
    state = (
        "fully_protected"
        if health.full_active_protection
        else "active_containment_ready"
        if health.active_containment_ready
        else "endpoint_security_observe_ready"
        if health.endpoint_security_observe_ready
        else "fallback_observe_ready"
        if health.state.value == "OBSERVE_READY"
        else "degraded_observation_mode"
    )
    return {"state": state, "anti_ransomware": health.to_dict(), "active_protection": protection.to_dict(),
            "limitations": list(health.limitations), "guaranteed_protection": False}


__all__ = ["get_status"]
