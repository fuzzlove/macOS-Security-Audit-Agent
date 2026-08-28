from __future__ import annotations
from .health import AntiRansomwareHealth, source_health

def repair_plan(status: AntiRansomwareHealth|None=None) -> dict:
    health=status or source_health()
    return {"schema_version":"1.0","destructive":False,"requires_sudo_invocation":False,"current_state":health.state.value,"steps":list(health.repair_actions),"external_gates":list(health.external_gates),"prohibited_actions":["modify TCC database","disable SIP or Gatekeeper","run GUI as root","fabricate entitlement"],"fallback":{"available":health.degraded_observation_ready,"label":health.status_badge,"limitations":list(health.limitations)}}
