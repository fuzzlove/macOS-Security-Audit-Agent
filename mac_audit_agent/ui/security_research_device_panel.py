from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal, Slot
from PySide6.QtWidgets import QCheckBox, QComboBox, QFileDialog, QHBoxLayout, QLabel, QMessageBox, QProgressBar, QPushButton, QStackedWidget, QTextEdit, QVBoxLayout, QWidget

from mac_audit_agent.models import BackgroundMonitorEvent, utc_now_iso
from mac_audit_agent.security_research_device import PROFILES, evaluate_automatic_tasks, export_assessment, profile_by_id, tasks_for_profile


class _Signals(QObject):
    completed = Signal(object)
    failed = Signal(str)


class _ValidationWorker(QRunnable):
    def __init__(self) -> None:
        super().__init__(); self.signals = _Signals()

    @Slot()
    def run(self) -> None:
        try: self.signals.completed.emit(evaluate_automatic_tasks())
        except Exception as exc: self.signals.failed.emit(f"{type(exc).__name__}: {exc}")


class SecurityResearchDevicePanel(QWidget):
    def __init__(self, db, parent: QWidget | None = None) -> None:
        super().__init__(parent); self.db = db; self._index = 0; self._states: dict[str, dict] = {}; self._worker = None
        layout = QVBoxLayout(self)
        self.step_indicator = QLabel("Step 1 of 3 — Select Scope")
        self.step_indicator.setObjectName("securityResearchWizardStep")
        self.step_indicator.setAccessibleName("Security Research Device wizard progress")
        self.step_indicator.setStyleSheet("font-size: 18px; font-weight: 700;")
        layout.addWidget(self.step_indicator)
        self.wizard_pages = QStackedWidget()
        self.wizard_pages.setObjectName("securityResearchWizardPages")
        layout.addWidget(self.wizard_pages, 1)

        scope_page = QWidget()
        scope_layout = QVBoxLayout(scope_page)
        warning = QLabel("Evidence-backed macOS hardening for authorized research. MSAA does not certify government compliance, provide authorization, or guarantee protection from theft or compromise.")
        warning.setWordWrap(True); warning.setAccessibleName("Security Research Device limitations"); scope_layout.addWidget(warning)
        scope_title = QLabel("Choose the smallest review profile that matches the written research scope")
        scope_title.setWordWrap(True); scope_title.setStyleSheet("font-size: 16px; font-weight: 650;"); scope_layout.addWidget(scope_title)
        self.profile = QComboBox(); self.profile.addItems([p.title for p in PROFILES]); self.profile.currentIndexChanged.connect(self._profile_changed)
        self.profile.setToolTip("Choose controls proportional to the authorized research. Higher profiles add evidence requirements; they do not grant government approval.")
        scope_layout.addWidget(self.profile)
        self.profile_description = QLabel(); self.profile_description.setWordWrap(True); scope_layout.addWidget(self.profile_description)
        self.authorization_checkbox = QCheckBox("I confirm I am authorized to assess this Mac and will stay within the approved research scope.")
        self.authorization_checkbox.setObjectName("securityResearchAuthorizationCheckbox")
        self.authorization_checkbox.setToolTip("This is a local workflow acknowledgement, not independent proof of authorization.")
        scope_layout.addWidget(self.authorization_checkbox)
        self.start_wizard_button = QPushButton("Start Guided Review")
        self.start_wizard_button.setObjectName("startSecurityResearchWizardButton")
        self.start_wizard_button.setProperty("role", "primary")
        self.start_wizard_button.setEnabled(False)
        self.authorization_checkbox.toggled.connect(self.start_wizard_button.setEnabled)
        self.start_wizard_button.clicked.connect(self._start_wizard)
        scope_layout.addWidget(self.start_wizard_button)
        scope_layout.addStretch(1)
        self.wizard_pages.addWidget(scope_page)

        task_page = QWidget()
        task_layout = QVBoxLayout(task_page)
        self.progress = QProgressBar(); self.progress.setAccessibleName("Security Research Device task progress"); task_layout.addWidget(self.progress)
        self.title = QLabel(); self.title.setStyleSheet("font-size: 18px; font-weight: 600;"); self.title.setWordWrap(True); task_layout.addWidget(self.title)
        self.status = QLabel(); self.status.setWordWrap(True); task_layout.addWidget(self.status)
        self.details = QTextEdit(); self.details.setReadOnly(True); self.details.setAccessibleName("Current Security Research Device task guidance"); task_layout.addWidget(self.details, 1)
        row = QHBoxLayout()
        self.previous = QPushButton("Back to Scope"); self.previous.clicked.connect(self._previous_task); row.addWidget(self.previous)
        self.verify = QPushButton("Run Read-Only Checks"); self.verify.setToolTip("Collect FileVault, Secure Boot, SIP, and firewall evidence asynchronously. No setting is changed."); self.verify.clicked.connect(self._validate); row.addWidget(self.verify)
        self.collected = QPushButton("Record Evidence Collected"); self.collected.setToolTip("Record a timestamped manual assertion. This does not make a failed or unknown control pass."); self.collected.clicked.connect(self._record_collected); row.addWidget(self.collected)
        self.next = QPushButton("Next Task"); self.next.setProperty("role", "primary"); self.next.clicked.connect(self._next_task); row.addWidget(self.next)
        task_layout.addLayout(row)
        self.wizard_pages.addWidget(task_page)

        summary_page = QWidget()
        summary_layout = QVBoxLayout(summary_page)
        summary_title = QLabel("Review assessment evidence")
        summary_title.setStyleSheet("font-size: 18px; font-weight: 700;")
        summary_layout.addWidget(summary_title)
        self.summary = QTextEdit(); self.summary.setReadOnly(True); self.summary.setAccessibleName("Security Research Device assessment summary"); summary_layout.addWidget(self.summary, 1)
        summary_actions = QHBoxLayout()
        self.back_to_tasks_button = QPushButton("Back to Controls"); self.back_to_tasks_button.clicked.connect(self._show_task_page); summary_actions.addWidget(self.back_to_tasks_button)
        self.export_button = QPushButton("Export Assessment JSON"); self.export_button.setProperty("buttonVariant", "export"); self.export_button.clicked.connect(self._export); summary_actions.addWidget(self.export_button)
        self.restart_wizard_button = QPushButton("Start New Review"); self.restart_wizard_button.clicked.connect(self._restart_wizard); summary_actions.addWidget(self.restart_wizard_button)
        summary_layout.addLayout(summary_actions)
        self.wizard_pages.addWidget(summary_page)
        self._profile_changed(0)

    def _tasks(self): return tasks_for_profile(PROFILES[self.profile.currentIndex()].profile_id)

    def _profile_changed(self, _index: int) -> None:
        self._index = 0; profile = PROFILES[self.profile.currentIndex()]; self.profile_description.setText(profile.description)
        for task in tasks_for_profile(profile.profile_id):
            raw = self.db.get_background_monitor_state(f"security_research_device:{profile.profile_id}:{task.task_id}", "")
            if raw:
                try: self._states[task.task_id] = json.loads(raw)
                except (json.JSONDecodeError, TypeError): self._states[task.task_id] = {"status": "unknown", "persistence_error": True}
        self._render()
        self._audit("security_research_profile_selected", "info", {"profile_id": profile.profile_id})

    def _render(self) -> None:
        tasks = self._tasks(); self._index = min(self._index, len(tasks)-1); task = tasks[self._index]; state = self._states.get(task.task_id, {"status": "not assessed"})
        self.progress.setRange(0, len(tasks)); self.progress.setValue(self._index + 1); self.progress.setFormat(f"Task {self._index + 1} of {len(tasks)}")
        if self.wizard_pages.currentIndex() == 1:
            self.step_indicator.setText(f"Step 2 of 3 — Review Controls (Task {self._index + 1} of {len(tasks)})")
        self.title.setText(task.title); self.status.setText(f"Current result: {state.get('status', 'not assessed').upper()}")
        manual = "\n".join(f"{i+1}. {step}" for i, step in enumerate(task.manual_steps))
        self.details.setPlainText(f"Why it matters\n{task.purpose}\n\nHow to verify manually\n{manual}\n\nRemediation preview\n{task.remediation}\n\nRollback / recovery\n{task.rollback}\n\nOperational impact\nAdministrator: {'required' if task.requires_admin else 'not necessarily required'}; MDM: {'recommended/required by profile' if task.requires_mdm else 'not required'}; restart may be required: {'yes' if task.restart_may_be_required else 'no'}\n\nMappings (not certification)\n" + "\n".join(task.mappings))
        self.previous.setText("Back to Scope" if self._index == 0 else "Previous Task")
        self.next.setText("Review Summary" if self._index == len(tasks) - 1 else "Next Task")

    def _move(self, amount: int) -> None: self._index += amount; self._render()

    def _previous_task(self) -> None:
        if self._index > 0:
            self._move(-1)
            return
        self.wizard_pages.setCurrentIndex(0)
        self.step_indicator.setText("Step 1 of 3 — Select Scope")

    def _start_wizard(self) -> None:
        if not self.authorization_checkbox.isChecked():
            return
        self._index = 0
        self.wizard_pages.setCurrentIndex(1)
        self._audit("security_research_wizard_started", "info", {"profile_id": PROFILES[self.profile.currentIndex()].profile_id})
        self._render()

    def _next_task(self) -> None:
        if self._index < len(self._tasks()) - 1:
            self._move(1)
            return
        self._show_summary()

    def _show_task_page(self) -> None:
        self.wizard_pages.setCurrentIndex(1)
        self._render()

    def _show_summary(self) -> None:
        tasks = self._tasks()
        assessed = 0
        passed = failed = unknown = 0
        lines: list[str] = []
        for task in tasks:
            state = self._states.get(task.task_id, {})
            status = str(state.get("status", "not assessed")).strip().lower().replace("_", " ")
            manual_recorded = bool(state.get("manual_evidence_collected_at"))
            if status not in {"", "not assessed", "not_assessed"} or manual_recorded:
                assessed += 1
            if status == "pass": passed += 1
            elif status == "fail": failed += 1
            elif status in {"unknown", "manual review required"}: unknown += 1
            marker = status.upper() if status else "NOT ASSESSED"
            if manual_recorded:
                marker += " · EVIDENCE RECORDED"
            lines.append(f"[{marker}] {task.title}")
        remaining = len(tasks) - assessed
        self.summary.setPlainText(
            f"Profile: {PROFILES[self.profile.currentIndex()].title}\n"
            f"Reviewed: {assessed} of {len(tasks)} ({round(assessed / len(tasks) * 100)}%)\n"
            f"Automatic results: {passed} pass · {failed} fail · {unknown} unknown/manual review\n"
            f"Remaining without recorded assessment: {remaining}\n\n"
            "A manual evidence record is an assessor assertion, not a passing result. Resolve failed and unknown controls or document approved exceptions before relying on this assessment. This export is evidence support, not certification.\n\n"
            + "\n".join(lines)
        )
        self.wizard_pages.setCurrentIndex(2)
        self.step_indicator.setText("Step 3 of 3 — Review & Export")
        self._audit("security_research_wizard_reviewed", "info", {"profile_id": PROFILES[self.profile.currentIndex()].profile_id, "assessed": assessed, "total": len(tasks)})

    def _restart_wizard(self) -> None:
        self.authorization_checkbox.setChecked(False)
        self.wizard_pages.setCurrentIndex(0)
        self.step_indicator.setText("Step 1 of 3 — Select Scope")

    def _validate(self) -> None:
        self.verify.setEnabled(False); self.status.setText("Collecting bounded read-only evidence…")
        worker = _ValidationWorker(); worker.signals.completed.connect(self._validation_done); worker.signals.failed.connect(self._validation_failed); self._worker = worker; QThreadPool.globalInstance().start(worker)

    def _validation_done(self, results: object) -> None:
        self.verify.setEnabled(True); self._states.update(dict(results)); self._audit("security_research_validation_completed", "info", {"results": {k: v.get("status") for k, v in dict(results).items()}}); self._render()

    def _validation_failed(self, message: str) -> None:
        self.verify.setEnabled(True); self.status.setText("Validation unavailable; controls remain unknown."); self._audit("security_research_validation_failed", "medium", {"error_type": message.split(":", 1)[0]})

    def _record_collected(self) -> None:
        task = self._tasks()[self._index]; now = utc_now_iso(); current = self._states.setdefault(task.task_id, {"status": "manual review required"}); current["manual_evidence_collected_at"] = now
        self.db.set_background_monitor_state(f"security_research_device:{profile_by_id(PROFILES[self.profile.currentIndex()].profile_id).profile_id}:{task.task_id}", json.dumps(current, sort_keys=True))
        self._audit("security_research_evidence_collected", "info", {"task_id": task.task_id, "automatic_status": current.get("status", "unknown")}); self.status.setText(f"Evidence collection recorded at {now}. This is not independent proof of effectiveness.")

    def _audit(self, event_type: str, severity: str, metadata: dict) -> None:
        event = BackgroundMonitorEvent(event_id=str(uuid4()), timestamp=utc_now_iso(), event_type=event_type, severity=severity, source="security_research_device", evidence="Security Research Device workflow event", confidence="high", recommendation="Review the associated task evidence and authorization scope.", metadata_json=json.dumps(metadata, sort_keys=True))
        self.db.record_background_monitor_event(event, dedupe_window_seconds=0)

    def _export(self) -> None:
        filename, _ = QFileDialog.getSaveFileName(self, "Export Security Research Device assessment", str(Path.home() / "MSAA-Security-Research-Device.json"), "JSON (*.json)")
        if not filename: return
        try:
            export_assessment(Path(filename), profile_id=PROFILES[self.profile.currentIndex()].profile_id, states=self._states); self._audit("security_research_assessment_exported", "info", {"format": "json"}); QMessageBox.information(self, "Export complete", "The assessment was exported. Review it before sharing; it is not a certification.")
        except OSError as exc: QMessageBox.critical(self, "Export failed", str(exc))
