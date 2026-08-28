from PySide6.QtCore import Signal
from PySide6.QtWidgets import QLabel,QPushButton,QTableWidget,QTableWidgetItem,QHBoxLayout,QVBoxLayout,QWidget

class SecurityControlValidationPanel(QWidget):
 action_requested=Signal(str,str)
 def __init__(self,parent=None):
  super().__init__(parent);layout=QVBoxLayout(self);self.summary=QLabel("Security Control Validation: no assessment attached");self.summary.setWordWrap(True);layout.addWidget(self.summary)
  self.table=QTableWidget(0,7);self.table.setHorizontalHeaderLabels(("Control","Result","Expected","Actual","Severity","Evidence","Remediation"));self.table.horizontalHeader().setStretchLastSection(True);layout.addWidget(self.table)
  buttons=QHBoxLayout()
  for label,action in (("Run Assessment","run_assessment"),("Compare Baseline","compare_baseline"),("View Evidence","view_evidence"),("Generate Report","generate_report"),("Review Remediation","review_remediation")):
   button=QPushButton(label);button.clicked.connect(lambda _=False,a=action:self.action_requested.emit(a,self._selected()));buttons.addWidget(button)
  layout.addLayout(buttons);self.notice=QLabel("Validation is evidence-based decision support. Missing evidence never passes a control; remediation requires authorization.");self.notice.setWordWrap(True);layout.addWidget(self.notice)
 def set_assessment(self,payload):
  a=payload.get("assessment",payload) if isinstance(payload,dict) else {};results=[x for x in a.get("results",[]) if isinstance(x,dict)]
  self.summary.setText(f"Compliance Score: {a.get('compliance_score','not collected')}% · Profile: {a.get('profile_id','not collected')} · Passed: {a.get('passed_controls',0)} · Failed: {a.get('failed_controls',0)} · Not assessed: {a.get('not_assessed_controls',0)} · Excepted: {a.get('excepted_controls',0)} · Status: {a.get('posture_status','not collected')}")
  self.table.setRowCount(len(results))
  for row,item in enumerate(results):
   values=(item.get("control_id",""),item.get("result",""),item.get("expected_state",""),item.get("actual_state",""),item.get("severity",""),", ".join(str(x) for x in item.get("evidence_reference",[])),item.get("remediation",""))
   for col,value in enumerate(values):self.table.setItem(row,col,QTableWidgetItem(str(value)))
  self.table.resizeColumnsToContents()
 def _selected(self):
  row=self.table.currentRow();item=self.table.item(row,0) if row>=0 else None;return item.text() if item else ""
