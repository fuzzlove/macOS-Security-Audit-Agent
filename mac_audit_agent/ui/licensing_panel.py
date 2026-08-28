"""Product licensing status and signed activation controls."""

from __future__ import annotations

import os
from pathlib import Path

from PySide6.QtCore import QObject, QRunnable, QThreadPool, QUrl, Signal, Slot
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QFrame,
    QGridLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from mac_audit_agent.licensing.activation import ActivationError
from mac_audit_agent.licensing.manager import LicenseManager
from mac_audit_agent.licensing.policy import (
    DEFAULT_LICENSE_ACTIVATION_URL,
    DEFAULT_LICENSE_CHECKOUT_URL,
    OFFLINE_LICENSE_CONTACT,
    OFFLINE_LICENSE_PRICE_USD,
    OFFLINE_LICENSE_TERM,
)
from mac_audit_agent.licensing.verifier import LicenseVerificationError
from mac_audit_agent.ui.responsive_actions import ResponsiveActionRow


class _LicenseSignals(QObject):
    completed = Signal(object)
    failed = Signal(str, str)


class _LicenseWorker(QRunnable):
    def __init__(self, action: str, value: str = "") -> None:
        super().__init__()
        self.action = action
        self.value = value
        self.signals = _LicenseSignals()

    @Slot()
    def run(self) -> None:
        try:
            manager = LicenseManager()
            if self.action == "activate":
                status = manager.activate_online(self.value)
            elif self.action == "import":
                status = manager.import_offline(Path(self.value))
            elif self.action == "checkout":
                payload = manager.begin_stripe_checkout()
                payload["device_fingerprint"] = manager.device_fingerprint()
                self.signals.completed.emit(payload)
                return
            else:
                status = manager.status()
            payload = status.to_dict()
            payload["device_fingerprint"] = manager.device_fingerprint()
            payload["product_access"] = manager.product_access(status)
            payload["access_mode"] = payload["product_access"]["mode"]
            self.value = ""
            self.signals.completed.emit(payload)
        except (ActivationError, LicenseVerificationError, OSError, ValueError) as exc:
            self.value = ""
            self.signals.failed.emit(getattr(exc, "code", "LIC_OPERATION_FAILED"), str(exc))


class LicensingPanel(QFrame):
    license_changed = Signal(object)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("productLicensingPanel")
        self.setProperty("demoAllowed", True)
        self._worker: _LicenseWorker | None = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        title = QLabel("Product Licensing")
        title.setProperty("textRole", "cardTitle")
        layout.addWidget(title)
        explanation = QLabel(
            "Demo Preview keeps MSAA content visible but operational controls locked. Purchase through Stripe or import an Ed25519-signed offline license file to enable them. "
            f"Licenses are ${OFFLINE_LICENSE_PRICE_USD}/{OFFLINE_LICENSE_TERM}; contact {OFFLINE_LICENSE_CONTACT} if online checkout is unavailable. "
            "Private signing keys never belong in the application. Existing background safety and preserved evidence are not deleted or stopped by licensing."
        )
        explanation.setWordWrap(True)
        layout.addWidget(explanation)

        status_grid = QGridLayout()
        status_grid.setHorizontalSpacing(18)
        status_grid.setVerticalSpacing(6)
        self._values: dict[str, QLabel] = {}
        fields = (
            ("Product Access", "access_mode"),
            ("Status", "state"),
            ("Edition", "edition"),
            ("Licensed To", "licensed_to"),
            ("License ID", "license_id"),
            ("Expiration", "expires_at"),
            ("Activation", "activation_mode"),
            ("Device Bound", "device_bound"),
            ("Last Verified", "last_verified_at"),
        )
        for row, (label, key) in enumerate(fields):
            status_grid.addWidget(QLabel(label), row, 0)
            value = QLabel("Checking…")
            value.setWordWrap(True)
            self._values[key] = value
            status_grid.addWidget(value, row, 1)
        status_grid.setColumnStretch(1, 1)
        layout.addLayout(status_grid)

        self.message = QLabel("Checking signed license status…")
        self.message.setWordWrap(True)
        self.message.setObjectName("licenseStatusMessage")
        layout.addWidget(self.message)

        device_label = QLabel("Installation Device Code (not secret)")
        layout.addWidget(device_label)
        self.device_code = QLineEdit()
        self.device_code.setReadOnly(True)
        self.device_code.setPlaceholderText("Loading this installation's device code…")
        self.device_code.setAccessibleName("MSAA installation device code")
        layout.addWidget(self.device_code)

        self.activation_code = QLineEdit()
        self.activation_code.setEchoMode(QLineEdit.EchoMode.Password)
        self.activation_code.setMaxLength(512)
        self.activation_code.setClearButtonEnabled(True)
        self.activation_code.setPlaceholderText("Activation code (kept in memory only; input hidden)")
        self.activation_code.setVisible(False)
        layout.addWidget(self.activation_code)

        self.refresh_button = QPushButton("Refresh Status")
        self.copy_device_code_button = QPushButton("Copy Device Code")
        self.checkout_button = QPushButton(f"Buy with Stripe — ${OFFLINE_LICENSE_PRICE_USD}/{OFFLINE_LICENSE_TERM}")
        self.checkout_button.setAccessibleName("Purchase an MSAA license with Stripe")
        self.copy_activation_button = QPushButton("Copy Activation Code")
        self.import_button = QPushButton("Import Offline Key / License…")
        self.activate_button = QPushButton("Activate Online")
        checkout_configured = bool(
            os.environ.get("MSAA_LICENSE_CHECKOUT_URL", "").strip()
            or DEFAULT_LICENSE_CHECKOUT_URL
        )
        activation_configured = bool(
            os.environ.get("MSAA_LICENSE_ACTIVATION_URL", "").strip()
            or DEFAULT_LICENSE_ACTIVATION_URL
        )
        self.checkout_button.setVisible(checkout_configured and activation_configured)
        self.activation_code.setVisible(activation_configured)
        self.activate_button.setVisible(activation_configured)
        self.copy_activation_button.setVisible(activation_configured)
        actions = ResponsiveActionRow(spacing=8)
        actions.add_buttons(
            [
                self.refresh_button,
                self.copy_device_code_button,
                self.checkout_button,
                self.copy_activation_button,
                self.import_button,
                self.activate_button,
            ]
        )
        layout.addWidget(actions)

        self.refresh_button.clicked.connect(self.refresh)
        self.copy_device_code_button.clicked.connect(self._copy_device_code)
        self.checkout_button.clicked.connect(self.begin_checkout)
        self.copy_activation_button.clicked.connect(self._copy_activation_code)
        self.import_button.clicked.connect(self._select_offline_license)
        self.activate_button.clicked.connect(self._activate)
        self.activation_code.textChanged.connect(lambda: self.activate_button.setEnabled(self._worker is None and bool(self.activation_code.text().strip())))
        self.refresh()

    def _set_busy(self, busy: bool) -> None:
        self.refresh_button.setEnabled(not busy)
        self.copy_device_code_button.setEnabled(not busy and bool(self.device_code.text()))
        self.checkout_button.setEnabled(not busy)
        self.copy_activation_button.setEnabled(not busy and bool(self.activation_code.text().strip()))
        self.import_button.setEnabled(not busy)
        self.activate_button.setEnabled(not busy and bool(self.activation_code.text().strip()))

    def refresh(self) -> None:
        self._start(_LicenseWorker("status"))

    def _select_offline_license(self) -> None:
        path, _selected = QFileDialog.getOpenFileName(
            self,
            "Import Signed MSAA Offline Key / License",
            str(Path.home()),
            "MSAA Offline License (*.json);;JSON (*.json)",
        )
        if path:
            self._start(_LicenseWorker("import", path))

    def _activate(self) -> None:
        code = self.activation_code.text().strip()
        if not code:
            QMessageBox.information(self, "Activation Code Required", "Enter the activation code issued by Liquidsky Network Security.")
            return
        self.activation_code.clear()
        self._start(_LicenseWorker("activate", code))

    @Slot()
    def begin_checkout(self) -> None:
        self._start(_LicenseWorker("checkout"))

    def _copy_device_code(self) -> None:
        code = self.device_code.text().strip()
        if code:
            QApplication.clipboard().setText(code)
            self.message.setText("Installation device code copied. It identifies this MSAA installation and is not a private signing key.")

    def _copy_activation_code(self) -> None:
        code = self.activation_code.text().strip()
        if code:
            QApplication.clipboard().setText(code)
            self.message.setText("Activation code copied. Treat it as a bearer secret until activation completes.")

    def _start(self, worker: _LicenseWorker) -> None:
        if self._worker is not None:
            return
        self._worker = worker
        self._set_busy(True)
        self.message.setText("Verifying licensing state…")
        worker.signals.completed.connect(self._completed)
        worker.signals.failed.connect(self._failed)
        QThreadPool.globalInstance().start(worker)

    @Slot(object)
    def _completed(self, payload: object) -> None:
        self._worker = None
        data = payload if isinstance(payload, dict) else {}
        checkout_url = str(data.get("checkout_url", "")).strip()
        activation_code = str(data.get("activation_code", "")).strip()
        if checkout_url and activation_code:
            self.activation_code.setText(activation_code)
            self.activation_code.setVisible(True)
            self.activate_button.setVisible(True)
            self.copy_activation_button.setVisible(True)
            opened = QDesktopServices.openUrl(QUrl(checkout_url))
            self.message.setText(
                "Stripe Checkout opened in your browser. Complete payment, return here, and click Activate Online. "
                "The activation code is held in this field and is not written to the licensing audit log."
                if opened
                else "Checkout was created, but the browser could not be opened. Copy the activation code before retrying."
            )
            self._set_busy(False)
            return
        for key, label in self._values.items():
            value = data.get(key)
            if key == "license_id" and value:
                text = str(value)
                value = f"{text[:8]}…{text[-4:]}" if len(text) > 14 else text
            if key == "device_bound":
                value = "Yes" if value else "No"
            label.setText(str(value or "—"))
        state = str(data.get("state", "UNKNOWN"))
        self.setProperty("licenseState", state)
        self.style().unpolish(self)
        self.style().polish(self)
        warnings = " ".join(str(item) for item in data.get("warnings", []))
        self.device_code.setText(str(data.get("device_fingerprint", "")))
        access = data.get("product_access", {}) if isinstance(data.get("product_access"), dict) else {}
        access_message = str(access.get("reason", ""))
        self.message.setText(f"{access_message} {data.get('message', 'License status refreshed.')} {warnings}".strip())
        self._set_busy(False)
        self.license_changed.emit(data)

    @Slot(str, str)
    def _failed(self, code: str, message: str) -> None:
        self._worker = None
        self.message.setText(f"{code}: {message} Core protection and evidence preservation remain active.")
        self._set_busy(False)
        QMessageBox.warning(self, "License Operation Rejected", f"{message}\n\nError code: {code}")
