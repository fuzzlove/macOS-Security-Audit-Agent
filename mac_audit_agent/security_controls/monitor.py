from __future__ import annotations

import time
from dataclasses import replace
from datetime import datetime, timezone
from uuid import uuid4

from .authorization import AuthorizedChangeWindow, evaluate_authorization
from .diff_engine import changed_fields, state_digest
from .evidence import EvidenceStore
from .models import ActorIdentity, AuthorizationStatus, ProcessIdentity, SecurityControlChangeEvent, SecurityControlState
from .registry import CONTROL_REGISTRY
from .severity import assess_risk


def sortable_event_id(now:datetime|None=None)->str:
    timestamp=int((now or datetime.now(timezone.utc)).timestamp()*1000)
    return f"{timestamp:013d}-{uuid4()}"


class SecurityControlMonitor:
    def __init__(self,store:EvidenceStore)->None: self.store=store

    def compare_and_record(self,previous:SecurityControlState,current:SecurityControlState,*,actor:ActorIdentity|None=None,process:ProcessIdentity|None=None,authorization:AuthorizedChangeWindow|None=None,authorization_key:bytes|None=None,reduces_security:bool=True)->SecurityControlChangeEvent|None:
        fields=changed_fields(previous.normalized_value,current.normalized_value)
        if not fields:return None
        definition=CONTROL_REGISTRY[current.control_id]
        auth=evaluate_authorization(authorization,control_id=current.control_id,process=process,verification_key=authorization_key,now=current.collected_at_utc)
        risk=assess_risk(category=current.category,authorization_status=auth.value,reduces_security=reduces_security,process_trusted=None if process is None else process.signing_status in {"valid","apple","trusted"},remote_session=None if actor is None else actor.remote_session,confidence=min(previous.confidence,current.confidence))
        now=datetime.now(timezone.utc); event_id=sortable_event_id(now)
        missing=tuple(name for name,value in (("actor attribution",actor),("process attribution",process)) if value is None)
        event=SecurityControlChangeEvent(event_id,1,"security_control_changed",current.control_id,current.category,now,None,state_digest(previous.normalized_value),state_digest(current.normalized_value),previous.normalized_value,current.normalized_value,fields,auth.value,authorization.authorization_id if auth==AuthorizationStatus.AUTHORIZED and authorization else None,actor,process,(previous.source,current.source),min(previous.confidence,current.confidence),None,None,risk.score,risk.severity,risk.rationale,definition.attack_mappings,None,now,now,1,"unacknowledged","",missing,risk.scoring_version)
        digest=self.store.append_event(event)
        return replace(event,integrity_digest=digest)

    def handle_fsevents_gap(self,details:str="event stream gap") -> dict[str,object]:
        return {"requires_reconciliation":True,"sensor_health_event":True,"severity":"high","error_code":"FSEVENTS_GAP","details":details,"detected_monotonic":time.monotonic()}
