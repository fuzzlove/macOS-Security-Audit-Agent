from __future__ import annotations

import json
import tempfile
from pathlib import Path

from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from mac_audit_agent.apple_diagnostics import (
    APPLE_DIAGNOSTICS_SUPPORT_URL,
    AppleEvidencePackage,
    capture_watermarked_screenshot,
    collect_apple_diagnostic_context,
    export_apple_evidence_package,
    redact_payload,
    verify_apple_evidence_package,
)


class AppleDiagnosticsPanel(QWidget):
    """User-initiated Apple Diagnostics context and screenshot evidence collection."""

    def __init__(self, parent: QWidget | None = None, *, app_version: str = "") -> None:
        super().__init__(parent)
        self.app_version = app_version
        self.last_package: AppleEvidencePackage | None = None

        layout = QVBoxLayout(self)
        title = QLabel("Apple Diagnostics")
        title.setObjectName("appleDiagnosticsTitle")
        title.setStyleSheet("font-size: 20px; font-weight: 800;")
        layout.addWidget(title)
        purpose = QLabel(
            "Collect a user-approved primary-display screenshot plus bounded macOS, hardware, and diagnostic context for an evidence package. "
            "The image receives a visible red MSAA evidence watermark before it is hashed."
        )
        purpose.setWordWrap(True)
        layout.addWidget(purpose)
        integrity = QLabel(
            "Tamper-evident, not immutable: every artifact and the final ZIP are protected by SHA-256 receipts and read-only permissions. "
            "Any later change fails verification when the original receipt is retained. This is not an Apple-signed diagnostic result."
        )
        integrity.setObjectName("appleDiagnosticsIntegrityQualification")
        integrity.setWordWrap(True)
        integrity.setStyleSheet("padding: 10px; border: 2px solid #B42318; color: #B42318; font-weight: 700;")
        layout.addWidget(integrity)

        form = QFormLayout()
        self.case_id = QLineEdit()
        self.case_id.setPlaceholderText("Required, for example INC-2026-001")
        self.reference_code = QLineEdit()
        self.reference_code.setPlaceholderText("Optional; enter the code shown by Apple Diagnostics")
        self.symptoms = QLineEdit()
        self.symptoms.setPlaceholderText("Brief symptom or evidence purpose")
        self.peripherals = QLineEdit()
        self.peripherals.setPlaceholderText("Optional peripherals connected during collection")
        self.redaction = QComboBox()
        self.redaction.addItem("Standard — redact user, network, serial, and environment identifiers", "standard")
        self.redaction.addItem("Minimal — also reduce user file paths", "minimal")
        self.redaction.addItem("Full Technical — no automatic redaction", "full technical")
        form.addRow("Case / ticket ID", self.case_id)
        form.addRow("Apple Diagnostics reference code", self.reference_code)
        form.addRow("Symptoms / purpose", self.symptoms)
        form.addRow("Connected peripherals", self.peripherals)
        form.addRow("Privacy redaction", self.redaction)
        layout.addLayout(form)

        self.capture_consent = QCheckBox(
            "I reviewed the visible primary display and authorize this screenshot and bounded diagnostic context collection."
        )
        self.capture_consent.setObjectName("appleDiagnosticsCaptureConsent")
        layout.addWidget(self.capture_consent)
        privacy = QLabel(
            "The screenshot can contain notifications, names, documents, or other private content. Nothing is uploaded automatically. "
            "Review the package before sharing it with Apple, a vendor, or an analyst."
        )
        privacy.setWordWrap(True)
        layout.addWidget(privacy)

        actions = QHBoxLayout()
        self.capture_button = QPushButton("Capture & Seal Apple Diagnostics Evidence")
        self.capture_button.setObjectName("captureAppleDiagnosticsEvidenceButton")
        self.capture_button.setToolTip("Capture the primary display, add a red watermark, collect bounded read-only context, hash the artifacts, and create a local ZIP.")
        self.capture_button.clicked.connect(self.capture_and_seal)
        self.verify_button = QPushButton("Verify Last Evidence Package")
        self.verify_button.setObjectName("verifyAppleDiagnosticsEvidenceButton")
        self.verify_button.setEnabled(False)
        self.verify_button.clicked.connect(self.verify_last_package)
        self.instructions_button = QPushButton("Open Official Apple Diagnostics Instructions")
        self.instructions_button.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(APPLE_DIAGNOSTICS_SUPPORT_URL)))
        actions.addWidget(self.capture_button)
        actions.addWidget(self.verify_button)
        actions.addWidget(self.instructions_button)
        actions.addStretch(1)
        layout.addLayout(actions)

        self.status = QLabel("No Apple Diagnostics evidence package has been collected in this session.")
        self.status.setObjectName("appleDiagnosticsEvidenceStatus")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        self.details = QPlainTextEdit()
        self.details.setReadOnly(True)
        self.details.setPlaceholderText("Collection and verification details will appear here.")
        layout.addWidget(self.details)

    def capture_and_seal(self) -> None:
        case_id = self.case_id.text().strip()
        if not case_id:
            QMessageBox.warning(self, "Case ID Required", "Enter a case or ticket ID before collecting evidence.")
            return
        if not self.capture_consent.isChecked():
            QMessageBox.warning(self, "Collection Authorization Required", "Review the visible display and check the authorization box before capture.")
            return
        if QMessageBox.question(
            self,
            "Capture Visible Primary Display",
            "Capture the currently visible primary display now? The resulting image may contain sensitive content and will be watermarked in red.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        ) != QMessageBox.Yes:
            return
        output = QFileDialog.getExistingDirectory(self, "Choose Apple Diagnostics Evidence Folder", str(Path.home() / "Documents"))
        if not output:
            return

        self.capture_button.setEnabled(False)
        self.status.setText("Collecting bounded diagnostic context and sealing the evidence package…")
        QApplication.processEvents()
        try:
            with tempfile.TemporaryDirectory(prefix="msaa-apple-diagnostics-") as temporary:
                screen = QApplication.primaryScreen()
                capture = capture_watermarked_screenshot(
                    Path(temporary) / "watermarked_screen_capture.png",
                    case_id=case_id,
                    screen=screen,
                )
                context = collect_apple_diagnostic_context()
                context["screen_capture"] = capture
                context["operator_context"] = {
                    "case_id": case_id,
                    "apple_diagnostics_reference_code": self.reference_code.text().strip() or "not entered",
                    "symptoms_or_purpose": self.symptoms.text().strip() or "not entered",
                    "connected_peripherals": self.peripherals.text().strip() or "not entered",
                }
                package = export_apple_evidence_package(
                    export_profile="Hardware / Apple Diagnostics Evidence Checklist",
                    output_dir=Path(output),
                    redaction_level=str(self.redaction.currentData()),
                    app_version=self.app_version,
                    extra_context=context,
                    screenshot_path=Path(capture["path"]),
                    create_archive=True,
                )
            verification = verify_apple_evidence_package(package)
        except Exception as exc:
            self.status.setText("Apple Diagnostics evidence collection failed.")
            QMessageBox.critical(self, "Apple Diagnostics Evidence Failed", str(exc))
            return
        finally:
            self.capture_button.setEnabled(True)

        self.last_package = package
        self.verify_button.setEnabled(True)
        self.details.setPlainText(json.dumps({"package": package.to_dict(), "verification": verification}, indent=2, sort_keys=True))
        if verification.get("valid"):
            self.status.setText("VERIFIED — watermarked capture and diagnostic artifacts match the sealed SHA-256 receipts.")
            QMessageBox.information(
                self,
                "Apple Diagnostics Evidence Collected",
                f"The local evidence package was created and verified.\n\nArchive:\n{package.archive_path}\n\nSHA-256:\n{package.package_hash}\n\nRetain the receipt separately and review all content before sharing.",
            )
        else:
            self.status.setText("INTEGRITY FAILURE — one or more collected artifacts did not match immediately after packaging.")
            QMessageBox.critical(self, "Apple Diagnostics Evidence Integrity Failure", json.dumps(verification, indent=2, sort_keys=True))

    def verify_last_package(self) -> None:
        if self.last_package is None:
            return
        verification = verify_apple_evidence_package(self.last_package)
        self.details.setPlainText(json.dumps({"package": self.last_package.to_dict(), "verification": verification}, indent=2, sort_keys=True))
        if verification.get("valid"):
            self.status.setText("VERIFIED — all retained hashes still match.")
            QMessageBox.information(self, "Evidence Package Verified", "All retained Apple Diagnostics evidence hashes match.")
        else:
            self.status.setText("TAMPER DETECTED — at least one file or receipt no longer matches.")
            QMessageBox.critical(self, "Evidence Package Verification Failed", "At least one artifact, manifest, or archive hash does not match. Preserve the package and investigate the custody break.")


__all__ = ["AppleDiagnosticsPanel"]
