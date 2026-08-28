from PySide6.QtCore import Signal
from PySide6.QtWidgets import QLabel,QPushButton,QTableWidget,QTableWidgetItem,QHBoxLayout,QVBoxLayout,QWidget
class SoftwareAttestationPanel(QWidget):
 action_requested=Signal(str,str)
 def __init__(self,parent=None):
  super().__init__(parent);layout=QVBoxLayout(self);self.summary=QLabel("Software Attestation: no assessment attached");layout.addWidget(self.summary);self.table=QTableWidget(0,6);self.table.setHorizontalHeaderLabels(("Application","Trust","Identity","Integrity","Provenance","Changes"));self.table.horizontalHeader().setStretchLastSection(True);layout.addWidget(self.table);buttons=QHBoxLayout()
  for label,action in (("Verify Software","verify_software"),("View Evidence","view_evidence"),("Compare Hashes","compare_hashes"),("Review Trust","review_trust"),("Generate Report","generate_report")):
   button=QPushButton(label);button.clicked.connect(lambda _=False,a=action:self.action_requested.emit(a,self._selected()));buttons.addWidget(button)
  layout.addLayout(buttons);layout.addWidget(QLabel("Attestation is evidence-based decision support. Blocking requires administrator approval; no software is modified or removed."))
 def set_assessment(self,payload):
  assessment=payload.get("assessment",payload) if isinstance(payload,dict) else {};rows=[x for x in assessment.get("results",[]) if isinstance(x,dict)];verified=sum(x.get("trust_state")=="verified" for x in rows);failed=sum(x.get("trust_state")=="failed" for x in rows);self.summary.setText(f"Profile: {assessment.get('profile','not collected')} · Verified: {verified} · Failed: {failed} · Review: {len(rows)-verified-failed}");self.table.setRowCount(len(rows))
  for row,item in enumerate(rows):
   app=item.get("application",{});values=(app.get("name",app.get("application_id","")),f"{item.get('trust_score','')} / {item.get('trust_state','')}",item.get("identity_status",""),item.get("integrity_status",""),item.get("provenance_status",""),"; ".join(item.get("change_types",[])))
   for column,value in enumerate(values):self.table.setItem(row,column,QTableWidgetItem(str(value)))
 def _selected(self):
  row=self.table.currentRow();item=self.table.item(row,0) if row>=0 else None;return item.text() if item else ""
