from __future__ import annotations

import json
import os

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QAbstractItemView, QFileDialog, QHBoxLayout, QLabel, QMessageBox, QPlainTextEdit, QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget

from mac_audit_agent.alerts.resilient_pipeline import pipeline_for


class AlertCenterPanel(QWidget):
    """Read-only incident view; authorization-changing actions stay out of this surface."""

    def __init__(self, db, parent=None) -> None:
        super().__init__(parent); self.db=db; self.pipeline=pipeline_for(db)
        layout=QVBoxLayout(self); title=QLabel("MSAA Resilient Alert Center"); title.setStyleSheet("font-size: 20px; font-weight: 700;"); layout.addWidget(title)
        layout.addWidget(QLabel("Duplicate notifications are consolidated. Every accepted receipt remains accounted for in the security event ledger or an explicit compaction record."))
        status_row=QHBoxLayout(); self.health=QLabel(); self.pressure=QLabel(); refresh=QPushButton("Refresh"); refresh.clicked.connect(self.refresh); status_row.addWidget(self.health); status_row.addWidget(self.pressure); status_row.addStretch(1); status_row.addWidget(refresh); layout.addLayout(status_row)
        self.table=QTableWidget(0,8); self.table.setHorizontalHeaderLabels(["Severity","Rule","Occurrences","First seen","Last seen","Lifecycle","Aggregation","Affected entities"]); self.table.setSelectionBehavior(QAbstractItemView.SelectRows); self.table.setEditTriggers(QAbstractItemView.NoEditTriggers); self.table.setAccessibleName("Active consolidated security incidents"); layout.addWidget(self.table)
        actions=QHBoxLayout()
        for label,callback in (("View Events",self.view_events),("View Suppressions",self.view_suppressions),("Export Review",self.export_review)):
            button=QPushButton(label); button.clicked.connect(callback); actions.addWidget(button)
        actions.addStretch(1); layout.addLayout(actions)
        self.details=QPlainTextEdit(); self.details.setReadOnly(True); self.details.setAccessibleName("Alert pipeline event and policy details"); layout.addWidget(self.details)
        self.timer=QTimer(self); self.timer.timeout.connect(self.refresh); self.timer.start(5000); self.refresh()

    def refresh(self) -> None:
        health=self.pipeline.store.health(); degraded=self.pipeline.degraded_status(); self.health.setText(f"Pipeline: {health['status'].upper()} · Integrity: {'VERIFIED' if health['integrity_ok'] else 'FAILED'} · Logging fallback: {'ACTIVE' if degraded['event_store_failed'] else 'standby'}"); self.pressure.setText(f"Queue {health['pending_notifications']}/{health['notification_capacity']} · Active {health['active_fingerprints']}/{health['maximum_active_fingerprints']} · Storage {health['storage_bytes']}/{health['storage_limit_bytes']} bytes")
        rows=self.db.conn.execute("SELECT * FROM resilient_alert_aggregates WHERE lifecycle!='RESOLVED' ORDER BY CASE highest_severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,last_seen DESC LIMIT 500").fetchall(); self.table.setRowCount(len(rows))
        for index,row in enumerate(rows):
            entities=sum(len(json.loads(str(row[name] or "[]"))) for name in ("unique_users_json","unique_processes_json","unique_destinations_json"))
            values=[row["highest_severity"],row["rule_id"],row["occurrence_count"],row["first_seen"],row["last_seen"],row["lifecycle"],"Consolidating" if row["occurrence_count"]>1 else "Single",entities]
            for column,value in enumerate(values): self.table.setItem(index,column,QTableWidgetItem(str(value)))
        self.table.resizeColumnsToContents()

    def _selected_fingerprint(self) -> str:
        row=self.table.currentRow()
        if row<0: return ""
        rule=self.table.item(row,1).text(); last=self.table.item(row,4).text()
        result=self.db.conn.execute("SELECT fingerprint FROM resilient_alert_aggregates WHERE rule_id=? AND last_seen=? LIMIT 1",(rule,last)).fetchone()
        return str(result["fingerprint"]) if result else ""

    def view_events(self) -> None:
        fingerprint=self._selected_fingerprint()
        if not fingerprint: self.details.setPlainText("Select an active alert first."); return
        rows=[{key:value for key,value in dict(row).items() if key not in {"canonical_json","previous_integrity_hash","integrity_hash"}} for row in self.db.conn.execute("SELECT * FROM resilient_security_events WHERE fingerprint=? ORDER BY sequence_number DESC LIMIT 500",(fingerprint,))]
        self.details.setPlainText(json.dumps({"fingerprint":fingerprint,"events":rows,"note":"Raw sensitive event bodies are not displayed in this view."},indent=2,sort_keys=True))

    def view_suppressions(self) -> None:
        self.details.setPlainText(json.dumps({"active_suppressions":self.pipeline.suppressions.list(),"authorization":"Create or revoke suppressions through the privileged MSAA CLI/service workflow."},indent=2,sort_keys=True))

    def export_review(self) -> None:
        destination,_=QFileDialog.getSaveFileName(self,"Export alert pipeline review","msaa-alert-review.json","JSON (*.json)")
        if not destination: return
        payload={"health":{**self.pipeline.store.health(),**self.pipeline.degraded_status()},"integrity":self.pipeline.store.verify_integrity(),"active":[dict(row) for row in self.db.conn.execute("SELECT * FROM resilient_alert_aggregates ORDER BY last_seen DESC LIMIT 1000")],"suppressions":self.pipeline.suppressions.list()}
        try:
            descriptor=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|getattr(os,"O_NOFOLLOW",0),0o600)
            try: os.write(descriptor,(json.dumps(payload,indent=2,sort_keys=True)+"\n").encode())
            finally: os.close(descriptor)
            QMessageBox.information(self,"Alert Review Exported",destination)
        except OSError as exc: QMessageBox.warning(self,"Export Failed",str(exc))
