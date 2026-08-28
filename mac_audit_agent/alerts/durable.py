from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from mac_audit_agent.security_controls.evidence import EvidenceStore


@dataclass
class AlertMetrics:
    alerts_created_total:int=0
    alerts_ui_rendered_total:int=0
    alerts_native_requested_total:int=0
    alerts_native_failed_total:int=0
    alerts_restored_after_restart_total:int=0
    alerts_acknowledged_total:int=0
    critical_alerts_unacknowledged:int=0
    alert_render_latency_ms:list[float]=field(default_factory=list)
    event_persistence_latency_ms:list[float]=field(default_factory=list)


def persistence_policy(severity:str)->str:
    return {"critical":"acknowledgment_required","high":"acknowledgment_required","medium":"view_or_acknowledgment_required","low":"queue","informational":"auto_collapse_allowed"}.get(severity.lower(),"queue")


class DurableAlertController:
    """Thread-neutral controller; a Qt adapter must invoke render on GUI thread."""
    def __init__(self,store:EvidenceStore,renderer:Callable[[dict],bool]|None=None)->None:
        self.store,self.renderer=store,renderer; self.metrics=AlertMetrics(); self.active:dict[str,dict]={}

    def restore(self)->list[dict]:
        pending=self.store.pending_alerts()
        for alert in pending:self.active[alert["event_id"]]=alert
        self.metrics.alerts_restored_after_restart_total+=len(pending)
        self.metrics.critical_alerts_unacknowledged=sum(1 for item in pending if item["severity"]=="critical")
        return pending

    def present(self,alert:dict)->bool:
        event_id=str(alert["event_id"]); self.active[event_id]=alert; self.metrics.alerts_created_total+=1
        started=datetime.now(timezone.utc)
        rendered=bool(self.renderer and self.renderer(alert))
        self.store.record_delivery(event_id,"ui_render",rendered,"" if rendered else "UI_RENDERER_UNAVAILABLE")
        if rendered:self.metrics.alerts_ui_rendered_total+=1
        self.metrics.alert_render_latency_ms.append((datetime.now(timezone.utc)-started).total_seconds()*1000)
        if str(alert.get("severity"))=="critical":self.metrics.critical_alerts_unacknowledged+=1
        return rendered

    def acknowledge(self,event_id:str,*,actor:str,reason:str,device_identity:str)->None:
        self.store.acknowledge(event_id,actor=actor,reason=reason,device_identity=device_identity)
        alert=self.active.pop(event_id,None);self.metrics.alerts_acknowledged_total+=1
        if alert and alert.get("severity")=="critical":self.metrics.critical_alerts_unacknowledged=max(0,self.metrics.critical_alerts_unacknowledged-1)

    def synthetic_payload(self,severity:str="critical")->dict[str,object]:
        return {"event_id":f"synthetic-{datetime.now(timezone.utc).timestamp()}","severity":severity,"title":"SYNTHETIC TEST EVENT — NO REAL SECURITY CHANGE DETECTED","description":"Local alert-delivery self-test; no security control was modified.","authorization_status":"AUTHORIZED","risk_score":0.0,"test_event":True}
