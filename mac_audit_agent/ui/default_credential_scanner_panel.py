"""Authorized default HTTP credential validation console."""

from __future__ import annotations

import threading
from pathlib import Path

from PySide6.QtCore import QObject, QRunnable, Qt, QThreadPool, Signal, Slot
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from mac_audit_agent.default_credential_scanner.engine import DefaultCredentialScanner
from mac_audit_agent.default_credential_scanner.export import export_credential_findings
from mac_audit_agent.default_credential_scanner.models import (
    CredentialFinding,
    CredentialScanReport,
)
from mac_audit_agent.default_credential_scanner.resources import (
    SOURCE_REPOSITORY,
    FingerprintManager,
)
from mac_audit_agent.default_credential_scanner.storage import (
    DefaultCredentialRepository,
)
from mac_audit_agent.default_credential_scanner.targets import parse_authorized_targets
from mac_audit_agent.ui.responsive_actions import ResponsiveActionRow


class _WorkerSignals(QObject):
    completed = Signal(object)
    failed = Signal(str)
    progress = Signal(int, int, str)


class _FingerprintWorker(QRunnable):
    def __init__(self, manager: FingerprintManager) -> None:
        super().__init__()
        self.manager = manager
        self.signals = _WorkerSignals()

    @Slot()
    def run(self) -> None:
        try:
            self.signals.completed.emit(self.manager.install_or_update())
        except Exception as exc:  # noqa: BLE001 - worker boundary reports a diagnostic
            self.signals.failed.emit(f"{type(exc).__name__}: {exc}")


class _ScanWorker(QRunnable):
    def __init__(self, scanner: DefaultCredentialScanner, targets: tuple, authorization: str, category: str) -> None:
        super().__init__()
        self.scanner = scanner
        self.targets = targets
        self.authorization = authorization
        self.category = category
        self.cancel_event = threading.Event()
        self.signals = _WorkerSignals()

    def cancel(self) -> None:
        self.cancel_event.set()

    @Slot()
    def run(self) -> None:
        try:
            report = self.scanner.scan(
                self.targets,
                authorization_reference=self.authorization,
                category=self.category,
                progress=lambda current, total, target: self.signals.progress.emit(current, total, target),
                cancelled=self.cancel_event.is_set,
            )
            self.signals.completed.emit(report)
        except Exception as exc:  # noqa: BLE001 - worker boundary reports a diagnostic
            self.signals.failed.emit(f"{type(exc).__name__}: {exc}")


class DefaultCredentialScannerPanel(QFrame):
    """Validate explicitly listed HTTP services without performing discovery."""

    nmap_install_requested = Signal()
    findings_detected = Signal(object)

    def __init__(self, data_root: Path, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("defaultCredentialScannerPanel")
        self.data_root = Path(data_root)
        self.fingerprint_manager = FingerprintManager(self.data_root / "fingerprints")
        self.repository = DefaultCredentialRepository(self.data_root / "default_credentials.sqlite3")
        self.pool = QThreadPool.globalInstance()
        self._worker: _ScanWorker | _FingerprintWorker | None = None
        self._report: CredentialScanReport | None = None
        self._findings: list[CredentialFinding] = []
        self._revealed = False
        self._build_ui()
        self.refresh_readiness()
        self._load_saved_findings()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)

        purpose = QLabel(
            "Validate common vendor-default HTTP credentials on servers you explicitly list. "
            "MSAA performs real authentication attempts; it does not discover targets, brute-force passwords, or expand the approved scope."
        )
        purpose.setWordWrap(True)
        purpose.setProperty("textRole", "body")
        layout.addWidget(purpose)

        authorization_box = QGroupBox("Authorized scope")
        authorization_layout = QVBoxLayout(authorization_box)
        form = QFormLayout()
        form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapLongRows)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        self.targets = QPlainTextEdit()
        self.targets.setObjectName("defaultCredentialTargets")
        self.targets.setPlaceholderText("One authorized HTTP(S) server per line\nhttps://router.example.test\nhttp://192.0.2.10:8080/admin/")
        self.targets.setMinimumHeight(108)
        self.targets.setAccessibleDescription("Explicit HTTP or HTTPS targets only; no ranges or automatic discovery.")
        self.authorization = QLineEdit()
        self.authorization.setPlaceholderText("Ticket, statement of work, lab approval, or owner authorization")
        self.category = QComboBox()
        self.category.addItem("All applicable fingerprints", "")
        for category in ("web", "routers", "security", "industrial", "printer", "storage", "virtualization", "console"):
            self.category.addItem(category.replace("_", " ").title(), category)
        form.addRow("HTTP(S) servers", self.targets)
        form.addRow("Authorization reference", self.authorization)
        form.addRow("Fingerprint category", self.category)
        authorization_layout.addLayout(form)
        self.authorization_confirm = QCheckBox(
            "Authorization confirmed for every listed server"
        )
        authorization_layout.addWidget(self.authorization_confirm)
        authorization_detail = QLabel(
            "By selecting this, I confirm I own or have written authorization to test every listed server and understand that MSAA performs real login attempts."
        )
        authorization_detail.setWordWrap(True)
        authorization_detail.setProperty("textRole", "muted")
        authorization_layout.addWidget(authorization_detail)
        layout.addWidget(authorization_box)

        readiness_box = QGroupBox("Scanner readiness")
        readiness_layout = QVBoxLayout(readiness_box)
        self.readiness = QLabel("Checking Nmap and fingerprint data…")
        self.readiness.setWordWrap(True)
        self.readiness.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        readiness_layout.addWidget(self.readiness)
        readiness_actions = ResponsiveActionRow()
        self.check_button = QPushButton("Check Readiness")
        self.fingerprint_button = QPushButton("Install / Update Fingerprints")
        self.nmap_button = QPushButton("Install Nmap")
        for button in (self.check_button, self.fingerprint_button, self.nmap_button):
            readiness_actions.add_button(button)
        readiness_layout.addWidget(readiness_actions)
        attribution = QLabel(
            f"Fingerprint source: Default HTTP Login Hunter / NNdefaccts (GPLv3-or-later) — {SOURCE_REPOSITORY}"
        )
        attribution.setWordWrap(True)
        attribution.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        attribution.setProperty("textRole", "muted")
        readiness_layout.addWidget(attribution)
        layout.addWidget(readiness_box)

        scan_actions = ResponsiveActionRow()
        self.scan_button = QPushButton("Scan Authorized Targets")
        self.scan_button.setProperty("actionRole", "primary")
        self.stop_button = QPushButton("Stop After Current Target")
        self.stop_button.setEnabled(False)
        self.export_button = QPushButton("Export Remediation Report")
        self.export_button.setEnabled(False)
        for button in (self.scan_button, self.stop_button, self.export_button):
            scan_actions.add_button(button)
        layout.addWidget(scan_actions)

        self.progress = QProgressBar()
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        self.progress.setTextVisible(True)
        layout.addWidget(self.progress)
        self.status = QLabel("No authorized validation is running.")
        self.status.setWordWrap(True)
        self.status.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(self.status)

        results_box = QGroupBox("Saved findings and remediation")
        results_layout = QVBoxLayout(results_box)
        result_controls = QHBoxLayout()
        self.reveal = QCheckBox("Reveal credentials for remediation")
        self.disposition = QComboBox()
        self.disposition.addItem("Open", "open")
        self.disposition.addItem("Remediated", "remediated")
        self.disposition.addItem("Accepted exception", "accepted_exception")
        self.disposition.addItem("False positive", "false_positive")
        self.apply_disposition = QPushButton("Apply to Selected Finding")
        result_controls.addWidget(self.reveal)
        result_controls.addStretch(1)
        result_controls.addWidget(self.disposition)
        result_controls.addWidget(self.apply_disposition)
        results_layout.addLayout(result_controls)
        self.table = QTableWidget(0, 9)
        self.table.setObjectName("defaultCredentialResults")
        self.table.setHorizontalHeaderLabels(
            ("Target", "Product", "Path", "Username", "Password", "Severity", "Confidence", "Status", "Detected")
        )
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.setMinimumHeight(260)
        results_layout.addWidget(self.table)
        caveat = QLabel(
            "An accepted default credential proves that credential worked at collection time. It does not prove compromise or prior use. "
            "Passwords stay masked in the interface and encrypted in local storage unless an operator explicitly reveals or exports them."
        )
        caveat.setWordWrap(True)
        caveat.setProperty("textRole", "muted")
        results_layout.addWidget(caveat)
        layout.addWidget(results_box, 1)

        self.check_button.clicked.connect(self.refresh_readiness)
        self.fingerprint_button.clicked.connect(self.update_fingerprints)
        self.nmap_button.clicked.connect(self.nmap_install_requested)
        self.scan_button.clicked.connect(self.start_scan)
        self.stop_button.clicked.connect(self.stop_scan)
        self.export_button.clicked.connect(self.export_report)
        self.reveal.toggled.connect(self._toggle_reveal)
        self.apply_disposition.clicked.connect(self._apply_disposition)

    @Slot()
    def refresh_readiness(self) -> None:
        fingerprint = self.fingerprint_manager.status()
        scanner = DefaultCredentialScanner(self.fingerprint_manager.path)
        state = scanner.readiness()
        nmap_text = str(state.get("nmap_path") or "not installed")
        fingerprint_text = (
            f"validated ({fingerprint.size:,} bytes; SHA-256 {fingerprint.sha256[:12]}…)"
            if fingerprint.ready else f"not ready — {fingerprint.error}"
        )
        self.readiness.setText(f"Nmap: {nmap_text}\nFingerprint data: {fingerprint_text}")
        ready = bool(state.get("ready") and fingerprint.ready)
        self.scan_button.setEnabled(ready and self._worker is None)
        self.nmap_button.setVisible(not bool(state.get("nmap_path")))

    @Slot()
    def update_fingerprints(self) -> None:
        if self._worker is not None:
            return
        answer = QMessageBox.question(
            self,
            "Download Default Credential Fingerprints",
            "MSAA will download the GPL-licensed NNdefaccts fingerprint dataset over verified HTTPS from the Default HTTP Login Hunter repository, validate its size and structure, and install it in private local storage. Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        worker = _FingerprintWorker(self.fingerprint_manager)
        self._worker = worker
        self._set_busy(True, "Downloading and validating fingerprint data…")
        worker.signals.completed.connect(self._fingerprints_done)
        worker.signals.failed.connect(self._worker_failed)
        self.pool.start(worker)

    @Slot(object)
    def _fingerprints_done(self, status: object) -> None:
        self._worker = None
        self._set_busy(False, "Fingerprint data installed and validated.")
        self.refresh_readiness()

    @Slot()
    def start_scan(self) -> None:
        if self._worker is not None:
            return
        try:
            parsed_targets = parse_authorized_targets(self.targets.toPlainText())
            authorization = self.authorization.text().strip()
            if not authorization:
                raise ValueError("Enter the ticket, statement of work, or other authorization reference.")
            if not self.authorization_confirm.isChecked():
                raise PermissionError("Confirm ownership or written authorization for every listed server.")
            scanner = DefaultCredentialScanner(self.fingerprint_manager.path)
            if not scanner.readiness()["ready"]:
                raise RuntimeError("Install Nmap and validated fingerprints before scanning.")
        except Exception as exc:  # noqa: BLE001 - GUI boundary reports scope/readiness failures
            QMessageBox.warning(self, "Authorized Scope Required", str(exc))
            return
        summary = "\n".join(f"• {target.url}" for target in parsed_targets[:12])
        if len(parsed_targets) > 12:
            summary += f"\n• …and {len(parsed_targets) - 12} more"
        answer = QMessageBox.warning(
            self,
            "Confirm Active Credential Validation",
            f"MSAA will attempt documented default credentials against exactly these {len(parsed_targets)} HTTP(S) server(s):\n\n{summary}\n\n"
            "This may create authentication logs or lockouts on poorly configured products. Confirm the approved window and scope before continuing.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        worker = _ScanWorker(scanner, parsed_targets, authorization, str(self.category.currentData() or ""))
        self._worker = worker
        self.progress.setRange(0, len(parsed_targets))
        self.progress.setValue(0)
        self._set_busy(True, "Authorized default credential validation started…")
        worker.signals.progress.connect(self._scan_progress)
        worker.signals.completed.connect(self._scan_completed)
        worker.signals.failed.connect(self._worker_failed)
        self.pool.start(worker)

    @Slot(int, int, str)
    def _scan_progress(self, current: int, total: int, target: str) -> None:
        self.progress.setRange(0, max(1, total))
        self.progress.setValue(max(0, current - 1))
        self.status.setText(f"Testing authorized target {current} of {total}: {target}")

    @Slot(object)
    def _scan_completed(self, payload: object) -> None:
        self._worker = None
        report = payload if isinstance(payload, CredentialScanReport) else None
        if report is None:
            self._set_busy(False, "Scanner returned an invalid result.")
            return
        self._report = report
        try:
            self.repository.save(report)
        except Exception as exc:  # noqa: BLE001 - scan evidence survives repository enrichment failure
            QMessageBox.warning(self, "Credential Evidence Storage Failed", f"The scan completed, but its encrypted finding store could not be updated: {exc}")
        self._load_saved_findings()
        self.progress.setValue(self.progress.maximum())
        summary = f"Completed {len(report.target_results)} authorized target(s); found {len(report.findings)} accepted default credential(s)."
        if report.errors:
            summary += f" {len(report.errors)} target or scanner error(s) require review."
        self._set_busy(False, summary)
        if report.findings:
            self.findings_detected.emit(tuple(report.findings))

    @Slot(str)
    def _worker_failed(self, message: str) -> None:
        self._worker = None
        self._set_busy(False, f"Operation failed: {message}")
        QMessageBox.warning(self, "Default Credential Scanner Failed", message)
        self.refresh_readiness()

    @Slot()
    def stop_scan(self) -> None:
        if isinstance(self._worker, _ScanWorker):
            self._worker.cancel()
            self.stop_button.setEnabled(False)
            self.status.setText("Cancellation requested. The current bounded target operation will finish before the scan stops.")

    def _set_busy(self, busy: bool, message: str) -> None:
        self.scan_button.setEnabled(not busy)
        self.fingerprint_button.setEnabled(not busy)
        self.check_button.setEnabled(not busy)
        self.stop_button.setEnabled(busy and isinstance(self._worker, _ScanWorker))
        self.status.setText(message)
        if not busy:
            self.refresh_readiness()

    def _load_saved_findings(self) -> None:
        try:
            self._findings = self.repository.findings()
        except Exception as exc:  # noqa: BLE001 - GUI must remain usable when local storage is damaged
            self._findings = []
            self.status.setText(f"Saved credential evidence could not be loaded: {exc}")
        self._populate_table()
        self.export_button.setEnabled(bool(self._findings) and self._worker is None)

    def _populate_table(self) -> None:
        self.table.setRowCount(len(self._findings))
        for row, finding in enumerate(self._findings):
            values = (
                finding.target_url,
                finding.product,
                finding.path,
                finding.username,
                finding.password if self._revealed else finding.masked_password,
                finding.severity.upper(),
                finding.confidence.upper(),
                finding.status.replace("_", " ").title(),
                finding.detected_at,
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                if column == 0:
                    item.setData(Qt.ItemDataRole.UserRole, finding.finding_id)
                if column == 4 and not self._revealed:
                    item.setToolTip("Credential masked. Use the explicit reveal control only during remediation.")
                self.table.setItem(row, column, item)

    @Slot(bool)
    def _toggle_reveal(self, enabled: bool) -> None:
        if enabled:
            answer = QMessageBox.warning(
                self,
                "Reveal Sensitive Credentials",
                "Revealing credentials can expose passwords on screen or in screenshots. Continue only for authorized remediation in a private workspace.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Cancel,
            )
            if answer != QMessageBox.StandardButton.Yes:
                self.reveal.blockSignals(True)
                self.reveal.setChecked(False)
                self.reveal.blockSignals(False)
                return
        self._revealed = enabled
        self._populate_table()

    @Slot()
    def _apply_disposition(self) -> None:
        row = self.table.currentRow()
        if row < 0 or not self.table.item(row, 0):
            QMessageBox.information(self, "Select a Finding", "Select one saved finding before applying a remediation disposition.")
            return
        finding_id = str(self.table.item(row, 0).data(Qt.ItemDataRole.UserRole) or "")
        try:
            self.repository.set_status(finding_id, str(self.disposition.currentData()))
            self._load_saved_findings()
            self.status.setText("Finding disposition updated; the original scan evidence was preserved.")
        except Exception as exc:  # noqa: BLE001 - disposition errors are reported without closing the panel
            QMessageBox.warning(self, "Disposition Failed", str(exc))

    @Slot()
    def export_report(self) -> None:
        if not self._findings:
            return
        answer = QMessageBox.warning(
            self,
            "Export Plaintext Credentials",
            "This remediation report contains plaintext usernames and passwords. Restrict access, rotate every listed credential, and securely delete the export when it is no longer required. Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        destination, _ = QFileDialog.getSaveFileName(
            self,
            "Export Default Credential Remediation Report",
            "MSAA-default-credential-remediation.html",
            "HTML (*.html);;JSON (*.json);;CSV (*.csv);;Text (*.txt)",
        )
        if not destination:
            return
        try:
            path = export_credential_findings(self._findings, Path(destination))
            QMessageBox.information(self, "Sensitive Report Exported", f"Protected mode-0600 report written to:\n{path}")
        except Exception as exc:  # noqa: BLE001 - export boundary reports filesystem/format errors
            QMessageBox.warning(self, "Export Failed", str(exc))


__all__ = ["DefaultCredentialScannerPanel"]
