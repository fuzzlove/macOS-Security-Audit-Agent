from __future__ import annotations

import json
import shlex
import sys
from pathlib import Path

from PySide6.QtWidgets import QApplication, QComboBox, QFileDialog, QFormLayout, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPlainTextEdit, QPushButton, QVBoxLayout, QWidget

from mac_audit_agent.emergency_lockdown import open_lockdown_mode_switch
from mac_audit_agent.professional_report import PROFESSIONAL_REPORT_FILTER, selected_report_path, structured_payload_report
from mac_audit_agent.security.lockdown.lockdown_manager import LockdownManager
from mac_audit_agent.security.lockdown.lockdown_permissions import CONFIRMATION_PHRASE
from mac_audit_agent.security.lockdown.lockdown_policy import APPLE_DISCLAIMER, PRODUCT_NAME, load_profile, profile_impact_summary


class EmergencyProtectionPanel(QWidget):
    """Visible control surface; privileged activation remains an explicit Terminal workflow."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.manager = LockdownManager()
        layout = QVBoxLayout(self)
        title = QLabel(PRODUCT_NAME); title.setStyleSheet("font-size: 18px; font-weight: 800;"); layout.addWidget(title)
        notice = QLabel(APPLE_DISCLAIMER + "\n\nWARNING: This incident-response profile may interrupt applications, networking, and remote administration. All changes require explicit administrator authorization and retain rollback evidence."); notice.setWordWrap(True); layout.addWidget(notice)
        self.banner = QLabel(); self.banner.setWordWrap(True); self.banner.setStyleSheet("padding: 12px; border: 2px solid #b42318; font-weight: 700;"); layout.addWidget(self.banner)
        form = QFormLayout()
        self.profile = QComboBox()
        for profile_id, label in (("emergency", "Emergency Response"), ("critical_zero_day", "Critical Zero-Day Response"), ("ransomware_response", "Ransomware Response"), ("investigation_mode", "Investigation Mode")): self.profile.addItem(label, profile_id)
        self.profile.currentIndexChanged.connect(self.show_profile_description)
        self.operator = QLineEdit(); self.reason = QLineEdit(); self.ticket = QLineEdit()
        form.addRow("Profile", self.profile); form.addRow("Authorized operator", self.operator); form.addRow("Incident reason", self.reason); form.addRow("Ticket number", self.ticket); layout.addLayout(form)
        self.profile_help = QPlainTextEdit(); self.profile_help.setReadOnly(True); self.profile_help.setMinimumHeight(250); layout.addWidget(self.profile_help)
        apple_lockdown_actions = QHBoxLayout()
        self.open_apple_lockdown_button = QPushButton("Open Apple Lockdown Mode Switch")
        self.open_apple_lockdown_button.setObjectName("openAppleLockdownModeSwitchButton")
        self.open_apple_lockdown_button.setProperty("role", "urgent")
        self.open_apple_lockdown_button.setToolTip(
            "Open System Settings at Apple's Lockdown Mode control. You must flip the switch and approve Turn On & Restart."
        )
        self.open_apple_lockdown_button.clicked.connect(self.open_apple_lockdown_mode_switch)
        apple_lockdown_actions.addWidget(self.open_apple_lockdown_button)
        apple_lockdown_actions.addWidget(
            QLabel("Apple requires the signed-in user to flip the switch and confirm the restart; MSAA cannot enable it silently.")
        )
        apple_lockdown_actions.addStretch(1)
        layout.addLayout(apple_lockdown_actions)
        actions = QHBoxLayout()
        for label, callback in (("Run Preflight", self.preflight), ("Prepare Administrator Command", self.prepare_enable), ("Prepare Rollback Command", self.prepare_disable), ("Refresh Status", self.refresh_status), ("Export Audit Report", self.export_report)):
            button = QPushButton(label); button.clicked.connect(callback); actions.addWidget(button)
        layout.addLayout(actions)
        self.details = QPlainTextEdit(); self.details.setReadOnly(True); layout.addWidget(self.details)
        self.show_profile_description(); self.refresh_status()

    def show_profile_description(self) -> None:
        summary = profile_impact_summary(load_profile(str(self.profile.currentData())))
        sections = [
            f"{summary['name']}\n{summary['purpose']}",
            "SYSTEM CHANGES\n" + "\n".join(f"• {item}" for item in summary["system_changes"]),
            "POSSIBLE NEGATIVE EFFECTS\n" + "\n".join(f"• {item}" for item in summary["negative_impacts"]),
            "NETWORKING\n" + summary["network_effect"],
            "MONITORING\n" + summary["monitoring_effect"],
            "THIS PROFILE DOES NOT\n" + "\n".join(f"• {item}" for item in summary["not_performed"]),
            "ROLLBACK AND EVIDENCE\n" + summary["rollback"] + "\n\n" + summary["authorization"],
        ]
        self.profile_help.setPlainText("\n\n".join(sections))

    def refresh_status(self) -> None:
        status = self.manager.status()
        if status.get("active"):
            profile = status.get("profile", {})
            auth = status.get("authorization", {})
            self.banner.setText(f"MSAA EMERGENCY PROTECTION ACTIVE\nProfile: {profile.get('name', 'unknown')}\nStarted: {status.get('started_at', '')}\nAuthorized By: {auth.get('operator', '')}\nProtections Enabled: {status.get('protections_enabled', 0)} | Restrictions Applied: {status.get('restrictions_applied', 0)} | Exceptions: {len(status.get('exceptions', []))} | Rollback Available: {'YES' if status.get('rollback_available') else 'NO'}")
        else: self.banner.setText("MSAA Emergency Protection Mode is not active.")
        self.details.setPlainText(json.dumps(status, indent=2, sort_keys=True))

    def preflight(self) -> None:
        try: self.details.setPlainText(json.dumps(self.manager.preflight(str(self.profile.currentData())), indent=2, sort_keys=True))
        except Exception as exc: QMessageBox.warning(self, "Preflight Failed", str(exc))

    def _base_command(self, action: str) -> list[str]:
        command = ["sudo", sys.executable, "-m", "mac_audit_agent.cli", "lockdown", action, "--operator", self.operator.text().strip(), "--reason", self.reason.text().strip(), "--ticket", self.ticket.text().strip(), "--confirm", CONFIRMATION_PHRASE]
        if action == "enable": command.extend(["--profile", str(self.profile.currentData())])
        else: command.append("--restore")
        return command

    def _prepare(self, action: str) -> None:
        if not all((self.operator.text().strip(), self.reason.text().strip(), self.ticket.text().strip())):
            QMessageBox.warning(self, "Authorization Details Required", "Enter the authorized operator, incident reason, and ticket number."); return
        if action == "enable":
            summary = profile_impact_summary(load_profile(str(self.profile.currentData())))
            impacts = "\n".join(f"• {item}" for item in summary["negative_impacts"])
            warning = f"Selected profile: {summary['name']}\n\n{summary['network_effect']}\n\nPossible negative effects:\n{impacts}"
        else:
            warning = "This will attempt to restore the recorded pre-activation Remote Login and firewall configuration. Restoration is verified but is not guaranteed if state evidence or system conditions changed."
        if QMessageBox.question(self, PRODUCT_NAME, f"{warning}\n\nContinue and copy the administrator command?") != QMessageBox.Yes: return
        rendered = " ".join(shlex.quote(item) for item in self._base_command(action))
        QApplication.clipboard().setText(rendered)
        self.details.setPlainText("Administrator command copied for review in Terminal:\n\n" + rendered + "\n\nMSAA does not collect or store the administrator password.")

    def prepare_enable(self) -> None: self._prepare("enable")
    def prepare_disable(self) -> None: self._prepare("disable")

    def open_apple_lockdown_mode_switch(self) -> None:
        result = open_lockdown_mode_switch()
        if result.get("opened"):
            QMessageBox.information(
                self,
                "Apple Lockdown Mode",
                "System Settings is open at Apple Lockdown Mode. Flip the switch, then confirm Turn On & Restart. "
                "Opening this page does not itself enable Lockdown Mode.",
            )
            return
        QMessageBox.warning(
            self,
            "Unable to Open Apple Lockdown Mode",
            "Open System Settings > Privacy & Security > Lockdown Mode manually.\n\n"
            + str(result.get("stderr") or result.get("exception") or "System Settings rejected the shortcut."),
        )

    def export_report(self) -> None:
        try:
            default = Path.home() / "Desktop" / "msaa-emergency-protection-report.html"
            chosen, selected_filter = QFileDialog.getSaveFileName(
                self,
                "Export Emergency Protection Audit Report",
                str(default),
                PROFESSIONAL_REPORT_FILTER + ";;JSON Evidence (*.json)",
            )
            if not chosen:
                return
            if "JSON Evidence" in selected_filter:
                path = Path(chosen).with_suffix(".json")
                self.manager.export_report(path)
            else:
                path = selected_report_path(chosen, selected_filter)
                structured_payload_report(
                    path,
                    title="MSAA Emergency Protection Audit Report",
                    payload=self.manager.report_payload(),
                    qualification=(
                        "MSAA Emergency Protection profiles are separate from Apple Lockdown Mode. "
                        "Opening Apple's settings pane does not prove that Lockdown Mode was enabled."
                    ),
                )
            QMessageBox.information(self, "Audit Report Exported", str(path))
        except Exception as exc: QMessageBox.warning(self, "Export Failed", str(exc))
