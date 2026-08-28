from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QCheckBox, QFileDialog, QFormLayout, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPushButton, QTableWidget, QTableWidgetItem, QTextBrowser, QVBoxLayout, QWidget

from mac_audit_agent.dns_assurance import assess_dns_configuration, export_dns_report, load_dns_threat_intelligence, normalize_dns_servers
from mac_audit_agent.models import BackgroundMonitorEvent, utc_now_iso
from mac_audit_agent.professional_report import PROFESSIONAL_REPORT_FILTER, selected_report_path


class DNSAssurancePanel(QWidget):
    refresh_requested = Signal()
    assessment_changed = Signal(object)
    def __init__(self, audit_database, parent=None):
        super().__init__(parent); self.db=audit_database; self.observed=[]; self.collected_at=""; self.intelligence={}; self.intelligence_status="not configured"
        layout=QVBoxLayout(self); intro=QLabel("Compare the Mac's observed DNS resolvers with the client-approved scope. Collection produces a Concern until the client validates the configuration. Threat-intelligence matches are red flags requiring immediate client notification and independent validation; they are not proof of compromise."); intro.setWordWrap(True); layout.addWidget(intro)
        form=QFormLayout(); self.approved=QLineEdit(self.db.get_background_monitor_state("dns_assurance_approved_servers", "")); self.approved.setPlaceholderText("Client-approved resolver IPs, comma separated"); form.addRow("Approved DNS servers",self.approved); layout.addLayout(form)
        controls=QHBoxLayout(); self.refresh=QPushButton("Collect Current DNS Configuration"); self.evidence=QCheckBox("Evidence collected"); self.client=QCheckBox("Validated by client"); self.import_intel=QPushButton("Import Approved DNS Threat Intelligence"); self.export=QPushButton("Export DNS Report"); controls.addWidget(self.refresh); controls.addWidget(self.evidence); controls.addWidget(self.client); controls.addWidget(self.import_intel); controls.addWidget(self.export); layout.addLayout(controls)
        self.status=QLabel(); self.status.setWordWrap(True); layout.addWidget(self.status); self.table=QTableWidget(0,3); self.table.setHorizontalHeaderLabels(("Observed Resolver","Approval State","Threat Intelligence")); layout.addWidget(self.table); self.details=QTextBrowser(); layout.addWidget(self.details)
        self.refresh.clicked.connect(self.refresh_requested.emit); self.approved.editingFinished.connect(self._policy_changed); self.evidence.toggled.connect(self._evidence_changed); self.client.toggled.connect(self._client_changed); self.import_intel.clicked.connect(self._import); self.export.clicked.connect(self._export)
        self.evidence.blockSignals(True); self.client.blockSignals(True); self.evidence.setChecked(self.db.get_background_monitor_state("dns_assurance_evidence", "0")=="1"); self.client.setChecked(self.db.get_background_monitor_state("dns_assurance_client_validated", "0")=="1"); self.evidence.blockSignals(False); self.client.blockSignals(False); self.render()
    def set_network_snapshot(self,payload):
        posture=(payload or {}).get("posture",{}) if isinstance(payload,dict) else {}; self.observed=list(posture.get("dns_servers",[]) or []); self.collected_at=str((payload or {}).get("timestamp",utc_now_iso())); self.render()
    def _policy_changed(self): self.db.set_background_monitor_state("dns_assurance_approved_servers", ",".join(normalize_dns_servers(self.approved.text().split(",")))); self.render()
    def _event(self,event_type,evidence,metadata): self.db.record_background_monitor_event(BackgroundMonitorEvent(event_id=f"{event_type}-{uuid4().hex}",timestamp=utc_now_iso(),event_type=event_type,severity="high" if event_type=="dns_configuration_red_flag" else "info",source="dns_assurance",evidence=evidence,confidence="high",metadata_json=json.dumps(metadata,sort_keys=True),notification_decision="log_only"),dedupe_window_seconds=0)
    def _evidence_changed(self,value):
        self.db.set_background_monitor_state("dns_assurance_evidence","1" if value else "0"); self._event("dns_evidence_collected",f"DNS evidence state changed to {'collected' if value else 'not collected'}.",{"evidence_collected":value,"observed_servers":self.observed,"qualification":"Collection does not prove client approval."}); self.render()
    def _client_changed(self,value):
        if value and not self.evidence.isChecked(): self.client.blockSignals(True); self.client.setChecked(False); self.client.blockSignals(False); QMessageBox.warning(self,"Client Validation","Collect and export DNS evidence before recording client validation."); return
        self.db.set_background_monitor_state("dns_assurance_client_validated","1" if value else "0"); self._event("dns_client_validation_changed",f"DNS client validation state changed to {value}.",{"client_validated":value}); self.render()
    def _import(self):
        path,_=QFileDialog.getOpenFileName(self,"Import Approved DNS Threat Intelligence","","JSON (*.json)");
        if not path:return
        try:self.intelligence,self.intelligence_status=load_dns_threat_intelligence(Path(path))
        except (ValueError,OSError) as exc:QMessageBox.warning(self,"DNS Intelligence Rejected",str(exc));return
        self.render()
    def result(self): return assess_dns_configuration(self.observed,self.approved.text().split(","),evidence_collected=self.evidence.isChecked(),client_validated=self.client.isChecked(),intelligence=self.intelligence,intelligence_status=self.intelligence_status,collected_at=self.collected_at)
    def render(self):
        result=self.result(); self.status.setText(f"Status: {result.status.upper()} — {result.explanation}"); self.table.setRowCount(len(result.observed_servers))
        for row,address in enumerate(result.observed_servers):
            threat=next((item for item in result.threat_matches if item['address']==address),None); values=(address,"approved" if address in result.approved_servers else "not approved",threat.get("reason","") if threat else "no configured match")
            for column,value in enumerate(values):self.table.setItem(row,column,QTableWidgetItem(value))
        self.details.setPlainText(json.dumps(result.to_dict(),indent=2,sort_keys=True)); self.assessment_changed.emit(result)
        if result.threat_matches:
            fingerprint=json.dumps(list(result.threat_matches),sort_keys=True); previous=self.db.get_background_monitor_state("dns_assurance_last_red_flag","")
            if fingerprint!=previous:self.db.set_background_monitor_state("dns_assurance_last_red_flag",fingerprint);self._event("dns_configuration_red_flag","Observed DNS resolver matched configured threat intelligence.",{"matches":list(result.threat_matches),"notify_client_immediately":True})
    def _export(self):
        path,selected=QFileDialog.getSaveFileName(self,"Export DNS Configuration Report","msaa-dns-configuration-report.html",PROFESSIONAL_REPORT_FILTER+";;JSON Evidence (*.json)");
        if not path:return
        destination=Path(path)
        if destination.suffix.lower() not in {".html",".docx",".xlsx",".json"}:destination=Path(path).with_suffix(".json" if "JSON" in selected else selected_report_path(path,selected).suffix)
        try:export_dns_report(self.result(),destination)
        except (ValueError,OSError) as exc:QMessageBox.warning(self,"DNS Export Failed",str(exc));return
        QMessageBox.information(self,"DNS Report Exported",f"DNS evidence report exported to {destination}.")
