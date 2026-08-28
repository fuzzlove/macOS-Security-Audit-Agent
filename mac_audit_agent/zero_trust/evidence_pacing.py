from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime,timezone

@dataclass(frozen=True)
class EvidenceMark:
    control_id:str
    timestamp:str

def detect_rapid_collection(marks:list[EvidenceMark],*,minimum_distinct_controls:int=4,window_seconds:int=120)->dict:
    parsed=[]
    for mark in marks:
        try:value=datetime.fromisoformat(mark.timestamp.replace("Z","+00:00"));value=value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        except (ValueError,TypeError):continue
        parsed.append((value,mark.control_id))
    if not parsed:return {"detected":False,"distinct_controls":0,"window_seconds":window_seconds,"controls":[]}
    parsed.sort();latest=parsed[-1][0];inside=[(time,control) for time,control in parsed if 0<=(latest-time).total_seconds()<=window_seconds];controls=sorted({control for _time,control in inside});return {"detected":len(controls)>=minimum_distinct_controls,"distinct_controls":len(controls),"window_seconds":window_seconds,"controls":controls,"first_mark":inside[0][0].isoformat() if inside else "","last_mark":latest.isoformat()}
