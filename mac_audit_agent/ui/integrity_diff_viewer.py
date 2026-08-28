from __future__ import annotations

import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from PySide6.QtCore import QTimer, Qt
from PySide6.QtGui import QCursor, QGuiApplication
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from mac_audit_agent.integrity.change_authorization import AuthorizedChangeRegistry
from mac_audit_agent.integrity.strict_verifier import FileIntegrityChange, IntegrityDiffReport
from mac_audit_agent.integrity.wrapper_adapter import IntegrityWrapperAdapter, WrapperIntegrityStatus
from mac_audit_agent.runtime.app_paths import application_integrity_root
from mac_audit_agent.storage import AuditDatabase


class IntegrityDiffViewer(QDialog):
    def __init__(self, report: IntegrityDiffReport, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.report = report
        self.setWindowTitle("Integrity Diff Viewer")
        self.resize(1100, 720)
        self._build_ui()
        self._load_rows(report.all_changes or report.unchanged_files)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        heading = QLabel(f"Integrity Status: {self.report.status.upper()} | Severity: {self.report.severity_level}")
        heading.setStyleSheet("font-size: 18px; font-weight: 700;")
        heading.setWordWrap(True)
        layout.addWidget(heading)

        summary = QTextBrowser()
        summary.setMaximumHeight(96)
        summary.setPlainText(self.report.explanation_summary)
        layout.addWidget(summary)

        controls = QHBoxLayout()
        self.search_field = QLineEdit()
        self.search_field.setPlaceholderText("Search file path, change type, severity, or explanation")
        self.search_field.textChanged.connect(self._filter_rows)
        controls.addWidget(self.search_field, 1)
        layout.addLayout(controls)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["File Path", "Expected Hash", "Actual Hash", "Change Type", "Severity", "Risk Explanation"])
        self.table.setSortingEnabled(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table, 1)

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)

    def _load_rows(self, changes: list[FileIntegrityChange]) -> None:
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        for change in changes:
            row = self.table.rowCount()
            self.table.insertRow(row)
            values = [
                change.file_path,
                _short_hash(change.expected_hash),
                _short_hash(change.actual_hash),
                change.change_type,
                change.severity,
                change.risk_explanation,
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setData(Qt.UserRole, change.to_dict())
                self.table.setItem(row, column, item)
        self.table.setSortingEnabled(True)
        self.table.resizeColumnsToContents()

    def _filter_rows(self, query: str) -> None:
        needle = query.strip().lower()
        for row in range(self.table.rowCount()):
            haystack = " ".join(self.table.item(row, column).text() for column in range(self.table.columnCount()) if self.table.item(row, column)).lower()
            self.table.setRowHidden(row, bool(needle and needle not in haystack))


class IntegrityLaunchGateDialog(QDialog):
    def __init__(self, report: IntegrityDiffReport, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.report = report
        self.user_action_taken = "none"
        self.setWindowTitle("Integrity Verification Failed")
        self.resize(1180, 760)
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        title = QLabel("Integrity Verification Failed")
        title.setStyleSheet("font-size: 24px; font-weight: 800; color: #B42318;")
        layout.addWidget(title)

        body = QLabel(
            f"{self.report.explanation_summary}\n\n"
            f"Detected at: {self.report.timestamp}\n"
            "MSAA cannot be considered trusted until you explicitly review these changes."
        )
        body.setWordWrap(True)
        layout.addWidget(body)

        self.viewer = IntegrityDiffViewer(self.report, self)
        self.viewer.setWindowFlags(Qt.Widget)
        layout.addWidget(self.viewer)

        self.ack_checkbox = QCheckBox("I acknowledge these changes are expected and authorize this specific diff snapshot.")
        self.reject_checkbox = QCheckBox("I reject these changes and want to stop before normal startup.")
        self.ack_checkbox.toggled.connect(self._sync_buttons)
        self.reject_checkbox.toggled.connect(self._sync_buttons)
        layout.addWidget(self.ack_checkbox)
        layout.addWidget(self.reject_checkbox)

        buttons_row = QHBoxLayout()
        self.proceed_button = QPushButton("Proceed")
        self.proceed_button.setEnabled(False)
        self.full_diff_button = QPushButton("View Full Diff Report")
        self.export_button = QPushButton("Export Evidence Snapshot")
        self.reinstall_button = QPushButton("Reinstall From Trusted Source")
        reinstall_help = "Replace an untrusted or damaged installation with a verified MSAA release while preserving diagnostic evidence."
        self.reinstall_button.setToolTip(reinstall_help)
        self.reinstall_button.setAccessibleName("Reinstall MSAA from a trusted source")
        self.reinstall_button.setAccessibleDescription(reinstall_help)
        self.stop_button = QPushButton("Stop / Quarantine Mode")
        self.proceed_button.clicked.connect(self._proceed)
        self.full_diff_button.clicked.connect(self._open_full_diff)
        self.export_button.clicked.connect(self._export_snapshot)
        self.reinstall_button.clicked.connect(self._reinstall_guidance)
        self.stop_button.clicked.connect(self.reject)
        for button in [self.proceed_button, self.full_diff_button, self.export_button, self.reinstall_button, self.stop_button]:
            buttons_row.addWidget(button)
        layout.addLayout(buttons_row)

    def _sync_buttons(self) -> None:
        if self.ack_checkbox.isChecked() and self.reject_checkbox.isChecked():
            sender = self.sender()
            if sender is self.ack_checkbox:
                self.reject_checkbox.setChecked(False)
            else:
                self.ack_checkbox.setChecked(False)
        self.proceed_button.setEnabled(self.ack_checkbox.isChecked() and not self.reject_checkbox.isChecked())

    def _proceed(self) -> None:
        if not self.ack_checkbox.isChecked():
            return
        self.user_action_taken = "authorized_expected_changes"
        self.accept()

    def _open_full_diff(self) -> None:
        IntegrityDiffViewer(self.report, self).exec()

    def _export_snapshot(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Export Integrity Evidence Snapshot", "integrity-diff-report.json", "JSON Files (*.json)")
        if not path:
            return
        Path(path).write_text(json.dumps(self.report.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
        self.user_action_taken = "exported_evidence_snapshot"

    def _reinstall_guidance(self) -> None:
        QMessageBox.information(
            self,
            "Reinstall From Trusted Source",
            "Stop MSAA, preserve this diff report, then reinstall from a trusted release or source checkout. Do not regenerate a manifest from the modified state unless you explicitly trust the source.",
        )


def run_launch_integrity_gate(
    *,
    parent: QWidget | None = None,
    root: Path | None = None,
    manifest_path: Path | None = None,
    db: AuditDatabase | None = None,
    authorization_registry: AuthorizedChangeRegistry | None = None,
) -> bool:
    debug_startup = os.environ.get("MSAA_DEBUG_STARTUP") == "1"
    trace = lambda message: print(f"MSAA integrity gate: {message}", file=sys.stderr, flush=True) if debug_startup else None
    trace("verification started")
    base = Path(root).resolve(strict=False) if root is not None else application_integrity_root()
    status = IntegrityWrapperAdapter(base).get_integrity_status_for_ui()
    trace(f"verification completed with status={status.status} code={status.result_code or status.failure_code}")
    report = _strict_report_from_wrapper(status, manifest_path=manifest_path)
    if db is not None:
        db.record_integrity_history(report, user_action_taken="launch_verification")
    if report.status == "verified":
        return True

    registry = authorization_registry or AuthorizedChangeRegistry()
    authorized = registry.has_authorization_for_report(report)
    # Keep the launch gate independent from the not-yet-established main-window
    # native surface. A parented QDialog becomes a macOS sheet and may never map
    # when Homebrew Python is transitioning from accessory to regular policy.
    dialog = IntegrityLaunchGateDialog(report, None)
    dialog.setWindowModality(Qt.ApplicationModal)
    dialog.setWindowFlag(Qt.WindowStaysOnTopHint, True)
    trace("dialog constructed")
    if authorized:
        dialog.setWindowTitle("Authorized Changes Present")
    QTimer.singleShot(0, lambda: _present_dialog(dialog))
    trace("opening dialog")
    if dialog.exec() != QDialog.Accepted:
        trace("dialog rejected or closed")
        if db is not None:
            db.record_integrity_history(report, user_action_taken="rejected_or_stopped")
        return False
    registry.authorize(report, user_confirmation="I ACKNOWLEDGE THESE CHANGES", reason="Launch-time explicit acknowledgement")
    trace("dialog accepted")
    if db is not None:
        db.record_integrity_history(report, user_action_taken=dialog.user_action_taken)
    return True


def _present_dialog(dialog: QDialog) -> None:
    """Make a launch gate discoverable instead of leaving only a tray icon visible."""
    dialog.show()
    screen = QGuiApplication.screenAt(QCursor.pos()) or QGuiApplication.primaryScreen()
    if screen is not None:
        available = screen.availableGeometry()
        frame = dialog.frameGeometry()
        frame.moveCenter(available.center())
        dialog.move(frame.topLeft())
    dialog.raise_()
    dialog.activateWindow()
    try:
        from mac_audit_agent.runtime.macos_foreground import activate_as_regular_application
        activate_as_regular_application()
    except (ImportError, OSError):
        pass
    handle = dialog.windowHandle()
    if handle is not None:
        handle.requestActivate()
    if os.environ.get("MSAA_DEBUG_STARTUP") == "1":
        geometry = dialog.frameGeometry()
        print(
            "MSAA integrity gate: presentation "
            f"visible={dialog.isVisible()} exposed={bool(handle and handle.isExposed())} "
            f"geometry={geometry.x()},{geometry.y()},{geometry.width()}x{geometry.height()} "
            f"screen={screen.name() if screen is not None else 'none'}",
            file=sys.stderr,
            flush=True,
        )


def _strict_report_from_wrapper(status: WrapperIntegrityStatus, *, manifest_path: Path | None = None) -> IntegrityDiffReport:
    verified = status.status == "verified" and status.result_code == "VALID"
    timestamp = datetime.now(timezone.utc).isoformat()
    report = IntegrityDiffReport(
        run_id=f"wrapper-integrity-{uuid.uuid4().hex}",
        timestamp=timestamp,
        status="verified" if verified else "failed",
        severity_level="INFO" if verified else "CRITICAL",
        requires_user_acknowledgement=not verified,
        explanation_summary=(
            f"Integrity verified. {int(status.authority.get('checked_files', 0) or 0)} tracked files match the signed manifest."
            if verified
            else f"{status.result_code or status.failure_code}: {status.reason or 'Integrity validation failed.'}"
        ),
        manifest_path=str(manifest_path or status.manifest_path),
        manifest_id=status.manifest_sha256,
        manifest_signature_valid=bool(status.signature_valid),
    )
    for rel_path in status.source_modified_files:
        change = _wrapper_change(rel_path, "MODIFIED_HASH", "Protected source file hash differs from the signed manifest.")
        report.hash_mismatches.append(change)
        report.changed_files.append(change)
    for rel_path in status.missing_files:
        change = _wrapper_change(rel_path, "MISSING", "Required protected file is missing.")
        report.missing_files.append(change)
        report.changed_files.append(change)
    for rel_path in status.extra_files:
        change = _wrapper_change(rel_path, "EXTRA_FILE", "Unexpected protected-scope file is present.")
        report.extra_files.append(change)
        report.changed_files.append(change)
    return report


def _wrapper_change(path: str, change_type: str, risk: str) -> FileIntegrityChange:
    return FileIntegrityChange(
        file_path=path,
        change_type=change_type,  # type: ignore[arg-type]
        severity="CRITICAL" if change_type == "MISSING" else "HIGH",
        risk_explanation=risk,
        category="core",
    )


def _short_hash(value: str) -> str:
    if not value:
        return ""
    return value if len(value) <= 18 else f"{value[:12]}...{value[-6:]}"
