from PySide6.QtCore import Signal
from PySide6.QtWidgets import QLabel,QPushButton,QTableWidget,QTableWidgetItem,QHBoxLayout,QVBoxLayout,QWidget
class CyberResiliencePanel(QWidget):
 action_requested=Signal(str)
 def __init__(self,parent=None):
  super().__init__(parent);layout=QVBoxLayout(self);self.summary=QLabel("Cyber Resilience Score: no assessment attached");layout.addWidget(self.summary);self.table=QTableWidget(0,3);self.table.setHorizontalHeaderLabels(("Category","Score","Weight"));self.table.horizontalHeader().setStretchLastSection(True);layout.addWidget(self.table);self.weaknesses=QLabel("Weaknesses: not measured");self.weaknesses.setWordWrap(True);layout.addWidget(self.weaknesses);buttons=QHBoxLayout()
  for label,action in (("View Details","view_details"),("Compare History","compare_history"),("Generate Report","generate_report"),("Run Validation","run_validation")):
   button=QPushButton(label);button.clicked.connect(lambda _=False,a=action:self.action_requested.emit(a));buttons.addWidget(button)
  layout.addLayout(buttons);layout.addWidget(QLabel("Preparedness scores do not guarantee incident outcomes or replace incident responders and security leadership."))
 def set_assessment(self,payload):
  assessment=payload.get("assessment",payload) if isinstance(payload,dict) else {};scores=assessment.get("category_scores",{});weights={"detection":20,"response":18,"containment":12,"recovery":18,"identity":10,"supply_chain":10,"vulnerability":6,"configuration":6};self.summary.setText(f"Overall Resilience: {assessment.get('overall_score','not measured')}/100 · Evidence coverage: {assessment.get('evidence_coverage_percent','not measured')}% · Model: {assessment.get('calculation_version','unknown')}");self.table.setRowCount(len(scores))
  for row,(category,score) in enumerate(scores.items()):
   for column,value in enumerate((category.replace("_"," ").title(),score,weights.get(category,""))):self.table.setItem(row,column,QTableWidgetItem(str(value)))
  weaknesses=assessment.get("weaknesses",[]);self.weaknesses.setText("Weaknesses: "+("; ".join(weaknesses[:5]) if weaknesses else "none in measured controls"))
