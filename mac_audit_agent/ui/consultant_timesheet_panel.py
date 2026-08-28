from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QComboBox, QFileDialog, QFormLayout, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPushButton, QTableWidget, QTableWidgetItem, QTextEdit, QVBoxLayout, QWidget

from mac_audit_agent.consultant_timesheet import ConsultantTimesheetRepository, STANDARD_SUGGESTIONS, export_timesheet, range_bounds


class ConsultantTimesheetPanel(QWidget):
    def __init__(self, audit_database, parent=None):
        super().__init__(parent); self.repo = ConsultantTimesheetRepository(audit_database); self.active_entry = self.repo.active()
        layout = QVBoxLayout(self)
        intro = QLabel("Track user-initiated billable assessment time, daily progress, external tools, and standards-oriented goals. Clock and note events are local audit evidence, not independent proof of continuous activity or client acceptance."); intro.setWordWrap(True); layout.addWidget(intro)
        form = QFormLayout(); self.contractor = QLineEdit(); self.engagement = QLineEdit(); form.addRow("Work/contractor name", self.contractor); form.addRow("Engagement", self.engagement); layout.addLayout(form)
        clock = QHBoxLayout(); self.start_button = QPushButton("Start Assessment"); self.stop_button = QPushButton("Stop Assessment"); self.elapsed = QLabel("Not clocked in"); self.start_button.setToolTip("Create a timestamped clock-in entry in the local SQL database and event log."); self.stop_button.setToolTip("Save notes, timestamp clock-out, calculate elapsed billable time, and record the stop event."); clock.addWidget(self.start_button); clock.addWidget(self.stop_button); clock.addWidget(self.elapsed, 1); layout.addLayout(clock)
        self.notes = QTextEdit(); self.goals = QTextEdit(); self.completed = QTextEdit(); self.struggles = QTextEdit(); self.tools = QTextEdit()
        self.notes.setPlaceholderText("Work performed today"); self.goals.setPlaceholderText("Assessment goals"); self.completed.setPlaceholderText("Completed outcomes"); self.struggles.setPlaceholderText("Blockers, uncertainty, or evidence gaps"); self.tools.setPlaceholderText("Other approved programs, tools, ticket systems, or evidence sources used")
        notes_form = QFormLayout(); notes_form.addRow("Work notes", self.notes); notes_form.addRow("Goals", self.goals); notes_form.addRow("Completed", self.completed); notes_form.addRow("Struggles", self.struggles); notes_form.addRow("Other tools used", self.tools); layout.addLayout(notes_form)
        standards = QHBoxLayout(); self.standard = QComboBox(); self.standard.addItems([name for name, _description in STANDARD_SUGGESTIONS]); self.suggestion = QLabel(); self.suggestion.setWordWrap(True); standards.addWidget(self.standard); standards.addWidget(self.suggestion, 1); layout.addLayout(standards)
        self.save_button = QPushButton("Save Progress Notes"); self.save_button.setToolTip("Save the current notes to the active or selected entry and write a local event-log record."); layout.addWidget(self.save_button)
        self.table = QTableWidget(0, 6); self.table.setHorizontalHeaderLabels(("Start", "End", "Hours", "Contractor", "Engagement", "Standards Focus")); self.table.setAccessibleName("Consultant weekly timesheet history"); layout.addWidget(self.table)
        export_row = QHBoxLayout(); self.period = QComboBox(); self.period.addItems(("Daily", "Weekly", "Monthly", "All")); self.format = QComboBox(); self.format.addItems(("Excel (.xlsx)", "Word (.docx)", "PDF (.pdf)", "Text (.txt)", "HTML (.html)")); self.export_button = QPushButton("Export Timesheet"); export_row.addWidget(QLabel("Export range")); export_row.addWidget(self.period); export_row.addWidget(self.format); export_row.addWidget(self.export_button); layout.addLayout(export_row)
        self.timer = QTimer(self); self.timer.setInterval(1000); self.timer.timeout.connect(self._update_elapsed); self.start_button.clicked.connect(self.start); self.stop_button.clicked.connect(self.stop); self.save_button.clicked.connect(self.save); self.export_button.clicked.connect(self.export); self.standard.currentIndexChanged.connect(self._update_suggestion); self.table.cellClicked.connect(self._load_row)
        self._update_suggestion(); self.refresh(); self._sync_active(); self.timer.start()

    def _update_suggestion(self): self.suggestion.setText(STANDARD_SUGGESTIONS[self.standard.currentIndex()][1])
    def _sync_active(self):
        active = self.active_entry is not None; self.start_button.setEnabled(not active); self.stop_button.setEnabled(active); self.save_button.setEnabled(active)
        if active: self.contractor.setText(self.active_entry.contractor_name); self.engagement.setText(self.active_entry.engagement_name)
        self._update_elapsed()
    def _update_elapsed(self):
        if not self.active_entry: self.elapsed.setText("Not clocked in"); return
        started = datetime.fromisoformat(self.active_entry.started_at.replace("Z", "+00:00")); seconds = max(0, int((datetime.now(timezone.utc) - started).total_seconds())); hours, remainder = divmod(seconds, 3600); minutes, secs = divmod(remainder, 60); self.elapsed.setText(f"Clocked in · {hours:02d}:{minutes:02d}:{secs:02d} · {self.active_entry.engagement_name}")
    def start(self):
        try: self.active_entry = self.repo.start(self.contractor.text(), self.engagement.text())
        except ValueError as exc: QMessageBox.warning(self, "Start Assessment", str(exc)); return
        self._sync_active(); self.refresh()
    def _values(self): return {"work_notes":self.notes.toPlainText(),"goals":self.goals.toPlainText(),"completed":self.completed.toPlainText(),"struggles":self.struggles.toPlainText(),"tools_used":self.tools.toPlainText(),"standards_focus":self.standard.currentText()}
    def save(self):
        if not self.active_entry: QMessageBox.information(self,"Save Timesheet","Start an assessment before saving progress notes."); return
        self.active_entry = self.repo.save_notes(self.active_entry.entry_id, **self._values()); self.refresh(); QMessageBox.information(self,"Timesheet Saved","Progress notes were saved to the local timesheet and event log.")
    def stop(self):
        if not self.active_entry: return
        self.active_entry = self.repo.save_notes(self.active_entry.entry_id, **self._values()); stopped = self.repo.stop(self.active_entry.entry_id); self.active_entry = None; self._sync_active(); self.refresh(); QMessageBox.information(self,"Assessment Stopped",f"Recorded {stopped.duration_seconds/3600:.2f} billable hours. Review the entry before export.")
    def refresh(self):
        self.entries = self.repo.list_entries(); self.table.setRowCount(len(self.entries))
        for row, entry in enumerate(self.entries):
            for column, value in enumerate((entry.started_at,entry.ended_at or "Active",f"{entry.duration_seconds/3600:.2f}",entry.contractor_name,entry.engagement_name,entry.standards_focus)): self.table.setItem(row,column,QTableWidgetItem(str(value)))
        self.table.resizeColumnsToContents()
    def _load_row(self, row, _column):
        if row < 0 or row >= len(self.entries): return
        entry=self.entries[row]; self.contractor.setText(entry.contractor_name); self.engagement.setText(entry.engagement_name); self.notes.setPlainText(entry.work_notes); self.goals.setPlainText(entry.goals); self.completed.setPlainText(entry.completed); self.struggles.setPlainText(entry.struggles); self.tools.setPlainText(entry.tools_used); index=self.standard.findText(entry.standards_focus); self.standard.setCurrentIndex(max(0,index))
    def export(self):
        since,until=range_bounds(self.period.currentText()); entries=self.repo.list_entries(since=since,until=until)
        if not entries: QMessageBox.information(self,"Export Timesheet","No entries exist in the selected period."); return
        suffix={0:".xlsx",1:".docx",2:".pdf",3:".txt",4:".html"}[self.format.currentIndex()]; path,_=QFileDialog.getSaveFileName(self,"Export Consultant Timesheet",f"consultant-timesheet-{self.period.currentText().lower()}{suffix}",f"Timesheet (*{suffix})")
        if not path:return
        try: export_timesheet(entries,Path(path)); self.repo.record_export(period=self.period.currentText(),format_name=suffix,entry_count=len(entries),output_name=path)
        except (ImportError,ValueError,OSError) as exc: QMessageBox.warning(self,"Timesheet Export Failed",str(exc)); return
        QMessageBox.information(self,"Timesheet Exported",f"Exported {len(entries)} entries to {path}.")
