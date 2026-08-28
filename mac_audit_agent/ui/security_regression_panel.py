from PySide6.QtCore import Signal
from PySide6.QtWidgets import QLabel,QPushButton,QTableWidget,QTableWidgetItem,QHBoxLayout,QVBoxLayout,QWidget
class SecurityRegressionPanel(QWidget):
 action_requested=Signal(str,str)
 def __init__(self,parent=None):
  super().__init__(parent);layout=QVBoxLayout(self);self.summary=QLabel("Security Regression Detection: no assessment attached");layout.addWidget(self.summary);self.table=QTableWidget(0,7);self.table.setHorizontalHeaderLabels(("Component","Category","Impact","Severity","Risk Δ","Changed By","Process"));self.table.horizontalHeader().setStretchLastSection(True);layout.addWidget(self.table);buttons=QHBoxLayout()
  for label,action in (("Compare States","compare_states"),("Investigate Change","investigate_change"),("View Evidence","view_evidence"),("Approve Exception","approve_exception"),("Generate Report","generate_report")):
   button=QPushButton(label);button.clicked.connect(lambda _=False,a=action:self.action_requested.emit(a,self._selected()));buttons.addWidget(button)
  layout.addLayout(buttons);layout.addWidget(QLabel("Changes are not assumed malicious. Exceptions and response actions require analyst or administrator authorization."))
 def set_assessment(self,payload):
  assessment=payload.get("assessment",payload) if isinstance(payload,dict) else {};rows=[x for x in assessment.get("regressions",[]) if isinstance(x,dict)];risks=sum(x.get("security_impact")=="security_regression" for x in rows);improvements=sum(x.get("security_impact")=="security_improvement" for x in rows);self.summary.setText(f"Score: {assessment.get('previous_score','?')} → {assessment.get('current_score','?')} · Regressions: {risks} · Improvements: {improvements}");self.table.setRowCount(len(rows))
  for row,item in enumerate(rows):
   for column,value in enumerate((item.get("affected_component",""),item.get("category",""),item.get("security_impact",""),item.get("severity",""),item.get("risk_score_change",""),item.get("changed_by",""),item.get("responsible_process",""))):self.table.setItem(row,column,QTableWidgetItem(str(value)))
 def _selected(self):
  row=self.table.currentRow();item=self.table.item(row,0) if row>=0 else None;return item.text() if item else ""
