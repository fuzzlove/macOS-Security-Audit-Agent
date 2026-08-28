from PySide6.QtCore import Signal
from PySide6.QtWidgets import QLabel,QPushButton,QTableWidget,QTableWidgetItem,QHBoxLayout,QVBoxLayout,QWidget
class SupplyChainTrustGraphPanel(QWidget):
 action_requested=Signal(str,str)
 def __init__(self,parent=None):
  super().__init__(parent);l=QVBoxLayout(self);self.summary=QLabel("Supply Chain Trust Graph: no graph attached");l.addWidget(self.summary);self.table=QTableWidget(0,5);self.table.setHorizontalHeaderLabels(("Software","Trust Score","State","Reasons","Unknowns"));self.table.horizontalHeader().setStretchLastSection(True);l.addWidget(self.table);b=QHBoxLayout()
  for label,a in (("Investigate Software","investigate_software"),("View Dependency Tree","view_dependency_tree"),("Verify Signature","verify_signature"),("Export SBOM","export_sbom"),("Generate Report","generate_report")):
   x=QPushButton(label);x.clicked.connect(lambda _=False,v=a:self.action_requested.emit(v,self._selected()));b.addWidget(x)
  l.addLayout(b);self.notice=QLabel("Trust is evidence-based decision support. No software is blocked or removed automatically.");l.addWidget(self.notice)
 def set_graph(self,p):
  g=p.get("graph",p) if isinstance(p,dict) else {};rows=[x for x in g.get("software_trust",[]) if isinstance(x,dict)];self.summary.setText(f"Software: {len(rows)} · SBOM: {g.get('sbom_status','not collected')} · Risk relationships: {len(g.get('risk_relationships',[]))}");self.table.setRowCount(len(rows))
  for r,x in enumerate(rows):
   for c,v in enumerate((x.get("software_id",""),x.get("trust_score",""),x.get("trust_state",""),"; ".join(x.get("reasons",[])),"; ".join(x.get("unknowns",[])))):self.table.setItem(r,c,QTableWidgetItem(str(v)))
 def _selected(self):
  r=self.table.currentRow();x=self.table.item(r,0) if r>=0 else None;return x.text() if x else ""
