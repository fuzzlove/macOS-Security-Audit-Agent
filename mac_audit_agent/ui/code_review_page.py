from __future__ import annotations

import json
from pathlib import Path

from PySide6.QtCore import QObject, QThread, Qt, Signal, Slot
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from mac_audit_agent.code_review.analyzer import CodeReviewAnalyzer
from mac_audit_agent.code_review.findings import CodeReviewReport
from mac_audit_agent.code_review.language_rules import supported_language_names
from mac_audit_agent.code_review.reporting import export_csv, export_html, export_json, export_professional
from mac_audit_agent.code_review.vulnerability_db import load_knowledge
from mac_audit_agent.professional_report import PROFESSIONAL_REPORT_FILTER, selected_report_path


class _ReviewWorker(QObject):
    completed = Signal(object)
    failed = Signal(str)

    def __init__(self, path: Path) -> None:
        super().__init__()
        self.path = path

    @Slot()
    def run(self) -> None:
        try:
            thread = QThread.currentThread()
            self.completed.emit(CodeReviewAnalyzer().scan_project(
                self.path, cancelled=thread.isInterruptionRequested,
            ))
        except Exception as exc:
            self.failed.emit(str(exc))


class CodeReviewPage(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.report: CodeReviewReport | None = None
        self._thread: QThread | None = None
        self._worker: _ReviewWorker | None = None
        self.setAccessibleName("Code Review")
        layout = QVBoxLayout(self)
        heading = QLabel("Code Review Intelligence")
        heading.setStyleSheet("font-size: 22px; font-weight: 750;")
        description = QLabel(
            "Review complete multi-language software projects for evidence-backed security weaknesses across "
            "Python, Swift, Objective-C, C/C++, Rust, Go, Java/Kotlin, JavaScript/TypeScript, shell, Ruby, PHP, "
            "Perl, C#, Lua, and SQL. "
            "Findings include CWE, CVSS vector, analyst context, impact, remediation, and official references. "
            "Python receives syntax-tree analysis; other supported languages receive bounded language-aware source analysis. "
            "Static analysis supports analyst review and does not prove exploitability."
        )
        description.setWordWrap(True)
        layout.addWidget(heading)
        layout.addWidget(description)

        controls = QHBoxLayout()
        self.scan_button = QPushButton("Scan Project…")
        self.scan_button.setProperty("role", "primary")
        self.scan_button.clicked.connect(self.choose_project)
        self.export_button = QPushButton("Export Report…")
        self.export_button.setEnabled(False)
        self.export_button.clicked.connect(self.export_report)
        controls.addWidget(self.scan_button)
        controls.addWidget(self.export_button)
        controls.addStretch(1)
        layout.addLayout(controls)

        self.summary = QLabel(
            "No project has been reviewed. Supported languages: "
            + ", ".join(supported_language_names())
            + "."
        )
        self.summary.setWordWrap(True)
        layout.addWidget(self.summary)
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs, 1)
        self.findings_table = self._finding_table()
        self.critical_table = self._finding_table()
        self.tabs.addTab(self.findings_table, "Findings")
        self.tabs.addTab(self.critical_table, "Critical Issues")
        self.details = QTextBrowser()
        self.details.setAccessibleName("Selected code review finding details")
        self.tabs.addTab(self.details, "Analyst Details")
        self.knowledge = QTextBrowser()
        self.knowledge.setPlainText(self._knowledge_text())
        self.tabs.addTab(self.knowledge, "Vulnerability Knowledge")
        self.compliance = QTextBrowser()
        self.tabs.addTab(self.compliance, "Compliance Mapping")
        self.reports = QTextBrowser()
        self.reports.setPlainText("Run a review, then export JSON, HTML, or CSV.")
        self.tabs.addTab(self.reports, "Reports")

    def _finding_table(self) -> QTableWidget:
        table = QTableWidget(0, 9)
        table.setHorizontalHeaderLabels(["Severity", "CVSS", "Confidence", "Language", "CWE", "Title", "File", "Line", "Required Action"])
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.currentCellChanged.connect(lambda row, _column, _previous_row, _previous_column, source=table: self._show_detail(source, row))
        table.horizontalHeader().setStretchLastSection(True)
        return table

    def choose_project(self) -> None:
        selected = QFileDialog.getExistingDirectory(self, "Select Project for Secure Code Review", str(Path.home()))
        if selected:
            self.scan_project(Path(selected))

    def scan_project(self, path: Path) -> None:
        if self._thread and self._thread.isRunning():
            return
        self.scan_button.setEnabled(False)
        self.summary.setText(f"Reviewing {path}…")
        thread = QThread(self)
        worker = _ReviewWorker(path)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.completed.connect(self._scan_completed)
        worker.failed.connect(self._scan_failed)
        worker.completed.connect(thread.quit)
        worker.failed.connect(thread.quit)
        worker.completed.connect(worker.deleteLater)
        worker.failed.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(lambda: setattr(self, "_thread", None))
        self._thread = thread
        self._worker = worker
        thread.finished.connect(lambda: setattr(self, "_worker", None))
        thread.start()

    def shutdown(self, timeout_ms: int = 3000) -> bool:
        thread = self._thread
        if thread is None or not thread.isRunning():
            return True
        thread.requestInterruption(); thread.quit()
        if thread.wait(timeout_ms):
            return True
        return False

    def closeEvent(self, event) -> None:
        self.shutdown()
        super().closeEvent(event)

    @Slot(object)
    def _scan_completed(self, report: CodeReviewReport) -> None:
        self.report = report
        counts = report.counts()
        highest = next((name for name in ("critical", "high", "medium", "low") if counts.get(name)), "none")
        self.summary.setText(
            f"Files reviewed: {report.files_reviewed} | Findings: {len(report.findings)} | "
            f"Critical: {counts['critical']} | High: {counts['high']} | Medium: {counts['medium']} | "
            f"Risk rating: {highest.upper()}"
        )
        self._populate(self.findings_table, list(report.findings))
        self._populate(self.critical_table, [item for item in report.findings if item.severity in {"critical", "high"}])
        compliance = {
            item.finding_id: item.compliance for item in report.findings if item.compliance
        }
        self.compliance.setPlainText(json.dumps(compliance, indent=2, sort_keys=True))
        self.reports.setPlainText(json.dumps({"project": report.project_path, "summary": counts, "limitations": report.limitations}, indent=2))
        self.export_button.setEnabled(True)
        self.scan_button.setEnabled(True)

    @Slot(str)
    def _scan_failed(self, message: str) -> None:
        self.scan_button.setEnabled(True)
        self.summary.setText("Code review failed. No risk conclusion was produced.")
        QMessageBox.warning(self, "Code Review Failed", message)

    def _populate(self, table: QTableWidget, findings: list) -> None:
        display_limit = 2000
        findings = findings[:display_limit]
        table.setRowCount(len(findings))
        for row, finding in enumerate(findings):
            action = "; ".join(finding.remediation.get("immediate", ()))
            values = (
                finding.severity.upper(), finding.cvss_score, finding.confidence, finding.language,
                finding.cwe, finding.title, finding.affected_file, finding.line, action,
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                if column == 0:
                    item.setData(Qt.UserRole, finding.to_dict())
                table.setItem(row, column, item)
        table.resizeColumnToContents(0)
        table.resizeColumnToContents(1)

    def _show_detail(self, table: QTableWidget, row: int) -> None:
        item = table.item(row, 0)
        if not item:
            return
        payload = dict(item.data(Qt.UserRole) or {})
        self.details.setPlainText(json.dumps(payload, indent=2, sort_keys=True))
        self.tabs.setCurrentWidget(self.details)

    def _knowledge_text(self) -> str:
        knowledge = load_knowledge()
        return json.dumps({
            "integrity": knowledge.integrity,
            "cvss": knowledge.cvss,
            "cwe_catalog": knowledge.cwes,
            "note": "CVE identifiers are displayed only after authoritative advisory matching; MSAA does not synthesize CVEs.",
        }, indent=2, sort_keys=True)

    def export_report(self) -> None:
        if not self.report:
            return
        destination, selected_filter = QFileDialog.getSaveFileName(
            self, "Export Code Review Report", "msaa-code-review.html",
            PROFESSIONAL_REPORT_FILTER + ";;JSON Evidence (*.json);;CSV Data (*.csv)",
        )
        if not destination:
            return
        path = Path(destination)
        if path.suffix.lower() not in {".html", ".docx", ".xlsx", ".json", ".csv"}:
            path = Path(destination).with_suffix(".json" if "JSON" in selected_filter else ".csv" if "CSV" in selected_filter else selected_report_path(destination, selected_filter).suffix)
        if "JSON" in selected_filter or path.suffix.lower() == ".json":
            export_json(self.report, path)
        elif "CSV" in selected_filter or path.suffix.lower() == ".csv":
            export_csv(self.report, path)
        elif path.suffix.lower() == ".html":
            export_html(self.report, path)
        else:
            export_professional(self.report, path)
        self.reports.setPlainText(f"Report exported to:\n{path}")


__all__ = ["CodeReviewPage"]
