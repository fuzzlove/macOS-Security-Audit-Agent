from __future__ import annotations

import json

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QGridLayout, QLabel, QPushButton, QVBoxLayout, QWidget

from mac_audit_agent.security_controls.diff_engine import safe_text

SEVERITY_SYMBOLS={"critical":"⛔","high":"▲","medium":"◆","low":"●","informational":"ℹ"}


class AlertCard(QWidget):
    view_details_requested=Signal(str);acknowledge_requested=Signal(str);open_incident_requested=Signal(str);copy_identifier_requested=Signal(str)

    def __init__(self,alert:dict,parent:QWidget|None=None)->None:
        super().__init__(parent);self.alert=dict(alert);event_id=safe_text(alert.get("event_id",""),256);severity=safe_text(alert.get("severity","informational"),32).lower()
        self.setAccessibleName(f"{severity.title()} security alert {event_id}");self.setObjectName(f"alertCard_{severity}")
        layout=QVBoxLayout(self);header=QLabel(f"{SEVERITY_SYMBOLS.get(severity,'◆')} {severity.upper()} — {safe_text(alert.get('control_name') or alert.get('title') or 'Security Control Change',256)}");header.setWordWrap(True);layout.addWidget(header)
        context=[]
        process=safe_text(alert.get("related_process") or alert.get("process_name") or "",512);path=safe_text(alert.get("related_path") or "",1024)
        if process:context.append(f"Responsible process: {process}")
        if path:context.append(f"Persistence path: {path}")
        try:metadata=json.loads(str(alert.get("metadata_json") or "{}"))
        except (TypeError,ValueError):metadata={}
        if isinstance(metadata,dict):
            signing_id=safe_text(metadata.get("process_signing_id") or "",256);team_id=safe_text(metadata.get("process_team_id") or "",64)
            if signing_id or team_id:context.append(f"Code signing: {signing_id or 'unknown signing ID'}{f' (team {team_id})' if team_id else ''}")
            ancestry=metadata.get("process_ancestry",[])
            if isinstance(ancestry,list) and ancestry:
                names=[safe_text(item.get("name") or item.get("path") or item.get("pid") or "",128) for item in ancestry[:5] if isinstance(item,dict)]
                if names:context.append("Process ancestry: "+" → ".join(names))
        details=QLabel("\n".join((safe_text(alert.get("description","")),f"Detected: {safe_text(alert.get('timestamp') or alert.get('detected_at_utc') or '')}",f"Authorization: {safe_text(alert.get('authorization_status','AUTHORIZATION_UNKNOWN'))}",f"MSAA incident risk: {safe_text(alert.get('risk_score') or alert.get('msaa_incident_risk_score') or 'unknown')}",f"Evidence confidence: {safe_text(alert.get('confidence','unknown'))}",*context)));details.setWordWrap(True);details.setObjectName("alertContextDetails");layout.addWidget(details)
        buttons=QGridLayout();self.view_details=QPushButton("View Complete Event Details");self.acknowledge=QPushButton("Acknowledge Security Alert");self.open_incident=QPushButton("Open Related Incident");self.copy_identifier=QPushButton("Copy Event Identifier")
        self.view_details.setToolTip("Opens the complete persisted event. This does not acknowledge the alert, suppress notifications, or modify evidence.")
        self.acknowledge.setToolTip("Starts authenticated acknowledgment. Evidence remains immutable and future notifications are not suppressed.")
        self.open_incident.setToolTip("Opens or creates the related investigation workflow. This modifies incident workflow state but not evidence.")
        self.copy_identifier.setToolTip("Copies only the display-safe event identifier. This does not modify state or evidence.")
        self.open_incident.setVisible(severity in {"high","critical"})
        for index,button in enumerate((self.view_details,self.acknowledge,self.open_incident,self.copy_identifier)):buttons.addWidget(button,index//2,index%2)
        layout.addLayout(buttons)
        self.view_details.clicked.connect(lambda:self.view_details_requested.emit(event_id));self.acknowledge.clicked.connect(lambda:self.acknowledge_requested.emit(event_id));self.open_incident.clicked.connect(lambda:self.open_incident_requested.emit(event_id));self.copy_identifier.clicked.connect(lambda:self.copy_identifier_requested.emit(event_id))
