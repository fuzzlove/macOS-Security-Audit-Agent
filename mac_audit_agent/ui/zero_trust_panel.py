from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QComboBox, QDialog, QDialogButtonBox, QFormLayout, QGroupBox, QHBoxLayout,
    QLabel, QLineEdit, QPlainTextEdit, QPushButton, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget,
)

from mac_audit_agent.zero_trust import DeviceTrustPosture, ZeroTrustPostureEngine
from mac_audit_agent.zero_trust.routes import route_for_signal


class ZeroTrustPosturePanel(QWidget):
    review_requested = Signal(str)
    validation_requested = Signal(str)
    attestation_requested = Signal()
    investigation_requested = Signal()
    manual_evidence_changed = Signal(str, str)
    attestation_policy_changed = Signal(str, str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        description = QLabel(
            "MSAA automatically reuses current evidence from its read-only collectors and other security sections. "
            "Manual attestation is requested only when a control cannot be validated automatically. Unknown evidence is explicit and receives no trust credit."
        )
        description.setWordWrap(True)
        layout.addWidget(description)
        self.score = QLabel()
        self.score.setAccessibleName("MSAA Device Trust Score")
        layout.addWidget(self.score)
        self.identity = QLabel("Device identity attestation: not yet generated")
        self.identity.setAccessibleName("Zero Trust device identity state")
        self.identity.setWordWrap(True)
        layout.addWidget(self.identity)
        verify_device = QPushButton("Verify Device")
        verify_device.setAccessibleName("Verify device posture")
        verify_device.setToolTip("Run MSAA's read-only endpoint scan plus FileVault, Secure Boot, SIP, firewall, and Unsigned Software provenance collection, then recompute Zero Trust controls. Manual client scope approval is still required where indicated; this does not grant or deny access.")
        verify_device.clicked.connect(lambda: self.validation_requested.emit("zero_trust_device_identity"))
        layout.addWidget(verify_device)
        generate_attestation = QPushButton("Generate Attestation")
        generate_attestation.setAccessibleName("Generate Zero Trust posture attestation")
        generate_attestation.setToolTip("Create a local, integrity-hashed summary of the currently displayed posture and its evidence references. This is an MSAA evidence statement, not Apple hardware attestation or certification.")
        generate_attestation.clicked.connect(self.attestation_requested.emit)
        layout.addWidget(generate_attestation)
        start_investigation = QPushButton("Start Investigation")
        start_investigation.setAccessibleName("Start authorized Zero Trust investigation")
        start_investigation.setToolTip("Open Investigation Priority so an analyst can review concerns and unknown controls. No process is killed, setting changed, or access restriction applied automatically.")
        start_investigation.clicked.connect(self.investigation_requested.emit)
        layout.addWidget(start_investigation)
        policy_group = QGroupBox("Automatic Attestation Policy")
        policy_group.setAccessibleName("Zero Trust automatic attestation policy")
        policy_layout = QFormLayout(policy_group)
        self.approved_dns_policy = QLineEdit()
        self.approved_dns_policy.setPlaceholderText("Approved resolver IPs, comma separated")
        self.approved_dns_policy.setAccessibleName("Approved DNS resolver policy")
        self.connection_allowlist_policy = QPlainTextEdit()
        self.connection_allowlist_policy.setPlaceholderText(
            "One endpoint per line: 203.0.113.10, 203.0.113.0/24, 203.0.113.10:443\n"
            "Optional: process|tcp|203.0.113.10|443"
        )
        self.connection_allowlist_policy.setMaximumHeight(92)
        self.connection_allowlist_policy.setAccessibleName("Approved active connection allowlist")
        policy_layout.addRow("Approved DNS", self.approved_dns_policy)
        policy_layout.addRow("Approved connections", self.connection_allowlist_policy)
        policy_actions = QHBoxLayout()
        save_policy = QPushButton("Save & Validate Attestation Policy")
        save_policy.setAccessibleName("Save and validate Zero Trust attestation policy")
        save_policy.setToolTip(
            "Validate and save the organizational DNS and endpoint allowlists, record a policy fingerprint, "
            "then refresh the affected controls. Unlisted connections are marked Needs Validation, not malicious."
        )
        save_policy.clicked.connect(
            lambda: self.attestation_policy_changed.emit(
                self.approved_dns_policy.text(), self.connection_allowlist_policy.toPlainText()
            )
        )
        policy_actions.addWidget(save_policy)
        policy_actions.addStretch()
        policy_layout.addRow(policy_actions)
        self.policy_status = QLabel("No attestation policy loaded")
        self.policy_status.setWordWrap(True)
        policy_layout.addRow(self.policy_status)
        layout.addWidget(policy_group)
        self._manual_evidence_states: dict[str, str] = {}
        self.table = QTableWidget(0, 11)
        self.table.setHorizontalHeaderLabels(("Domain", "Control", "State", "Collection", "Current Evidence / Provenance", "NIST", "CIS", "MITRE ATT&CK", "Evidence View", "Automatic Test", "Manual Check"))
        self.table.setAccessibleName("Zero Trust endpoint posture evidence")
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.cellDoubleClicked.connect(lambda row, _column: self.show_control_validation(row))
        layout.addWidget(self.table)
        self.note = QLabel()
        self.note.setWordWrap(True)
        layout.addWidget(self.note)
        self.set_posture(ZeroTrustPostureEngine().calculate({}))

    def set_attestation_policy(self, approved_dns: str, connection_allowlist: str, *, fingerprint: str = "") -> None:
        self.approved_dns_policy.setText(approved_dns)
        self.connection_allowlist_policy.setPlainText(connection_allowlist)
        dns_count = len([item for item in approved_dns.split(",") if item.strip()])
        endpoint_count = len([
            item for item in connection_allowlist.splitlines()
            if item.strip() and not item.strip().startswith("#")
        ])
        suffix = f" · Policy SHA-256 {fingerprint[:16]}…" if fingerprint else ""
        self.policy_status.setText(
            f"Configured policy: {dns_count} approved resolver(s), {endpoint_count} approved endpoint rule(s){suffix}. "
            "MSAA validates fresh local evidence against this policy; this is not a malware verdict."
        )

    def _emit_for_row(self, row: int, *, validate: bool) -> None:
        item = self.table.item(row, 0)
        signal_id = str(item.data(Qt.UserRole) or "") if item is not None else ""
        if signal_id:
            (self.validation_requested if validate else self.review_requested).emit(signal_id)

    def set_posture(self, posture: DeviceTrustPosture) -> None:
        self._posture = posture
        self.score.setText(f"MSAA Device Trust Score: {posture.score}/100 — {posture.rating}\nEvidence coverage: {posture.evidence_coverage_percent}%")
        self.table.setRowCount(len(posture.signals))
        markers = {"validated": "✓ Validated", "concern": "⚠ Concern", "unknown": "? Not validated"}
        for row, signal in enumerate(posture.signals):
            route = route_for_signal(signal.signal_id)
            provenance = signal.evidence
            if signal.evidence_source:
                provenance += f"\nSource: {signal.evidence_source}"
            if signal.evidence_collected_at:
                provenance += f"\nCollected: {signal.evidence_collected_at} ({signal.evidence_freshness})"
            values = (signal.domain.title(), signal.label, markers[signal.state], "", provenance, ", ".join(signal.nist_controls), ", ".join(signal.cis_controls), ", ".join(signal.mitre_techniques))
            for column, value in enumerate(values):
                self.table.setItem(row, column, QTableWidgetItem(value))
            self.table.item(row, 0).setData(Qt.UserRole, signal.signal_id)
            control_tip = f"{route.explanation}\n\nAutomatic: {route.automatic_method}\n\nManual review: {' '.join(route.manual_steps)}"
            self.table.item(row, 1).setToolTip(control_tip)
            self.table.item(row, 2).setToolTip(control_tip if signal.state != "validated" else f"Validated from current evidence. {route.explanation}")
            evidence_state = QComboBox()
            evidence_state.setAccessibleName(f"Evidence collection state for {signal.label}")
            if signal.automatically_collected and signal.state != "unknown":
                evidence_state.addItem("automatically collected")
                evidence_state.setEnabled(False)
                evidence_state.setToolTip(
                    f"Collected automatically from {signal.evidence_source or 'an MSAA evidence service'}. "
                    "The consultant does not need to mark this evidence manually; use Revalidate to refresh it."
                )
            else:
                evidence_state.addItems(("not collected", "collected"))
                attempted = (
                    f" Automatic collection from {signal.evidence_source} returned no conclusive value, so manual evidence remains available."
                    if signal.automatically_collected and signal.evidence_source else ""
                )
                evidence_state.setToolTip("Records whether the assessor collected review evidence. This creates an audit event but does not by itself prove the control passed or change a Concern to Validated." + attempted)
                selected = self._manual_evidence_states.get(signal.signal_id, "not collected")
                evidence_state.setCurrentText(selected if selected in {"not collected", "collected"} else "not collected")
                evidence_state.currentTextChanged.connect(lambda value, signal_id=signal.signal_id: self._manual_evidence_selected(signal_id, value))
            review = QPushButton("View Findings")
            review.setAccessibleName(f"View findings for {signal.label}")
            review.setToolTip(f"Open {route.page}. {route.explanation}")
            review.clicked.connect(lambda _checked=False, signal_id=signal.signal_id: self.review_requested.emit(signal_id))
            validate = QPushButton("Revalidate" if signal.state == "validated" else "Validate Now")
            validate.setAccessibleName(f"Validate {signal.label}")
            validate.setToolTip(route.explanation)
            validate.clicked.connect(lambda _checked=False, signal_id=signal.signal_id: self.validation_requested.emit(signal_id))
            manual = QPushButton("How to Verify")
            manual.setAccessibleName(f"Show manual verification for {signal.label}")
            manual.setToolTip("Show the automatic method, current evidence, and analyst verification steps.")
            manual.clicked.connect(lambda _checked=False, row=row: self.show_control_validation(row))
            self.table.setCellWidget(row, 3, evidence_state)
            self.table.setCellWidget(row, 8, review)
            self.table.setCellWidget(row, 9, validate)
            self.table.setCellWidget(row, 10, manual)
        self.table.resizeColumnsToContents()
        self.note.setText(f"Method: {posture.methodology}\n{posture.assurance_note}")

    def _manual_evidence_selected(self, signal_id: str, value: str) -> None:
        normalized = value if value in {"not collected", "collected"} else "not collected"
        if self._manual_evidence_states.get(signal_id, "not collected") == normalized:
            return
        self._manual_evidence_states[signal_id] = normalized
        self.manual_evidence_changed.emit(signal_id, normalized)

    def set_manual_evidence_states(self, states: dict[str, str]) -> None:
        self._manual_evidence_states = {key: value for key, value in states.items() if value in {"not collected", "collected"}}
        if hasattr(self, "_posture"):
            self.set_posture(self._posture)

    def show_control_validation(self, row: int) -> None:
        if not hasattr(self, "_posture") or row < 0 or row >= len(self._posture.signals):
            return
        signal = self._posture.signals[row]
        route = route_for_signal(signal.signal_id)
        dialog = QDialog(self)
        dialog.setWindowTitle(f"Validate Control — {signal.label}")
        dialog.setMinimumWidth(620)
        layout = QVBoxLayout(dialog)
        state = {"validated": "Validated", "concern": "Concern", "unknown": "Not validated"}[signal.state]
        details = QLabel(
            f"Domain: {signal.domain.title()}\n"
            f"Control: {signal.label}\n"
            f"Current state: {state}\n"
            f"Current evidence: {signal.evidence}\n\n"
            f"Automatic validation\n{route.automatic_method}\n\n"
            "Manual analyst verification\n"
            + "\n".join(f"{index}. {step}" for index, step in enumerate(route.manual_steps, 1))
            + "\n\nEvidence to compare\n• " + "\n• ".join(route.evidence_fields)
            + f"\n\nAuthoritative MSAA view: {route.page}"
        )
        details.setWordWrap(True)
        details.setTextInteractionFlags(Qt.TextSelectableByMouse)
        details.setAccessibleName(f"Validation details for {signal.label}")
        layout.addWidget(details)
        open_view = QPushButton("Open Evidence View")
        open_view.setAccessibleName(f"Open authoritative evidence view for {signal.label}")
        open_view.clicked.connect(lambda: (dialog.accept(), self.review_requested.emit(signal.signal_id)))
        layout.addWidget(open_view)
        run_test = QPushButton("Run Automatic Test")
        run_test.setAccessibleName(f"Run automatic test for {signal.label}")
        run_test.clicked.connect(lambda: (dialog.accept(), self.validation_requested.emit(signal.signal_id)))
        layout.addWidget(run_test)
        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        dialog.exec()

    def set_device_identity(self, payload: dict) -> None:
        attestation = payload.get("attestation", payload) if isinstance(payload, dict) else {}
        state = str(attestation.get("trust_state", "not verified"))
        score = attestation.get("trust_score", "not collected")
        verified = str(attestation.get("timestamp", "not collected"))
        coverage = attestation.get("evidence_coverage_percent", "not collected")
        self.identity.setText(f"Device Trust State: {state}\nTrust score: {score}/100 · Evidence coverage: {coverage}% · Last verified: {verified}\nDecision support only; authorization remains external to MSAA.")
