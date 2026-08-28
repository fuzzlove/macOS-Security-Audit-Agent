from __future__ import annotations

import json
import os
import plistlib
import shlex
import subprocess
import sys
from pathlib import Path

from PySide6.QtCore import QSettings, QTimer, QUrl, Qt, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QApplication, QCheckBox, QComboBox, QFormLayout, QGroupBox, QHBoxLayout, QInputDialog, QLabel, QListWidget, QMessageBox, QPushButton, QSizePolicy, QSpinBox, QVBoxLayout, QWidget

from mac_audit_agent.clickfix.cli import _synthetic_envelope, default_db_path
from mac_audit_agent.clickfix.evidence import ClickFixEvidenceStore
from mac_audit_agent.clickfix.health import doctor
from mac_audit_agent.clickfix.models import GuardProfile
from mac_audit_agent.clickfix.native_journal import NativeJournalConsumer
from mac_audit_agent.clickfix.policy import ClickFixPolicy
from mac_audit_agent.clickfix.service import ClickFixService
from mac_audit_agent.clickfix.shell_status import shell_guard_status
from mac_audit_agent.ui.alerts import AlertStack


class ClickFixGuardPanel(QWidget):
    critical_count_changed = Signal(int)
    TEST_TOOLTIP = ("Runs an inert local test of Command + Space detection, clipboard classification, persistent MSAA alerting, native notification delivery, incident correlation, and optional clipboard quarantine. The test does not execute clipboard content or make security-setting changes.")

    def __init__(self, parent: QWidget | None = None, *, evidence_path: Path | None = None) -> None:
        super().__init__(parent); self.settings = QSettings("MSAA", "ClickFixGuard")
        self.store = ClickFixEvidenceStore(evidence_path or default_db_path()); self.alert_stack = AlertStack()
        self._alerts: dict[str, dict] = {}
        self.status_label = QLabel("Checking ClickFix Guard status…")
        self.status_label.setObjectName("clickFixGuardCurrentStatus")
        self.status_label.setAccessibleName("ClickFix Guard current status")
        self.status_label.setWordWrap(True)
        self.status_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.status_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
        self.status_label.setMinimumWidth(0)
        layout = QVBoxLayout(self)
        disclosure = QLabel("Interim ClickFix protection is provided by local zsh/Bash adapters and the optional shell-agnostic paste proxy. They inspect complete command buffers before submission and never persist command text. The separately compiled Command + Space sensor is optional defense-in-depth until an appropriately signed Apple deployment is available.")
        disclosure.setWordWrap(True); layout.addWidget(disclosure)
        self.status_group = QGroupBox("Current status")
        self.status_group.setObjectName("clickFixGuardStatusGroup")
        status_layout = QVBoxLayout(self.status_group)
        status_layout.addWidget(self.status_label)
        self.prevention_readiness = QLabel(
            "Prevention readiness is being evaluated. When properly installed, integrity-verified, and set to Warn or Block, "
            "ClickFix Guard is designed to interrupt most recognized paste-to-terminal ClickFix patterns; no control can guarantee prevention of every variant."
        )
        self.prevention_readiness.setObjectName("clickFixPreventionReadiness")
        self.prevention_readiness.setAccessibleName("ClickFix attack prevention readiness")
        self.prevention_readiness.setWordWrap(True)
        status_layout.addWidget(self.prevention_readiness)
        layout.addWidget(self.status_group)
        shell_controls=QGroupBox("Primary Interim Shell Guard")
        shell_form=QFormLayout(shell_controls)
        self.shell_status_label=QLabel(); self.shell_status_label.setWordWrap(True); self.shell_status_label.setTextInteractionFlags(Qt.TextSelectableByMouse); self.shell_status_label.setAccessibleName("ClickFix shell guard detailed status"); shell_form.addRow("Coverage",self.shell_status_label)
        self.shell_mode=QComboBox(); self.shell_mode.addItem("Audit — detect and log only","audit"); self.shell_mode.addItem("Warn — hold and require challenge","warn"); self.shell_mode.addItem("Block — discard high-confidence commands","block"); self.shell_mode.setAccessibleName("ClickFix shell enforcement mode"); shell_form.addRow("Enforcement",self.shell_mode)
        threshold_row=QHBoxLayout(); self.shell_warn_threshold=QSpinBox(); self.shell_warn_threshold.setRange(1,50); self.shell_warn_threshold.setValue(4); self.shell_warn_threshold.setAccessibleName("ClickFix warning threshold"); self.shell_block_threshold=QSpinBox(); self.shell_block_threshold.setRange(2,100); self.shell_block_threshold.setValue(7); self.shell_block_threshold.setAccessibleName("ClickFix block threshold"); threshold_row.addWidget(QLabel("Warn")); threshold_row.addWidget(self.shell_warn_threshold); threshold_row.addWidget(QLabel("Block")); threshold_row.addWidget(self.shell_block_threshold); shell_form.addRow("Score thresholds",threshold_row)
        self.shell_proxy_enabled=QCheckBox("Enable generic PTY proxy policy (explicit terminal opt-in still required)"); self.shell_proxy_enabled.setAccessibleName("ClickFix generic proxy policy"); shell_form.addRow("Other shells",self.shell_proxy_enabled)
        apply_shell=QPushButton("Apply Shell Guard Policy"); apply_shell.clicked.connect(self._apply_shell_policy); apply_shell.setToolTip("Writes user-level ClickFix policy atomically. A system-managed policy cannot be overridden here."); shell_form.addRow("Policy",apply_shell)
        shell_actions=QHBoxLayout(); install_shell=QPushButton("Install or Repair Shell Guard"); install_shell.setToolTip("Validates and installs the local scanner, zsh and Bash adapters, PTY fallback, hashes, and idempotent startup-file blocks. No sudo or Apple entitlement is required."); uninstall_shell=QPushButton("Uninstall Shell Guard"); uninstall_shell.setToolTip("Removes only MSAA-managed startup blocks and installed shell files. ClickFix event logs are preserved."); verify_shell=QPushButton("Verify Shell Guard"); verify_shell.setToolTip("Checks installed hashes, zsh/Bash startup integration, login-shell coverage, policy source, event freshness, and System Monitor bridge state.")
        install_shell.clicked.connect(self._install_shell_guard); uninstall_shell.clicked.connect(self._uninstall_shell_guard); verify_shell.clicked.connect(self.refresh)
        shell_actions.addWidget(install_shell); shell_actions.addWidget(uninstall_shell); shell_actions.addWidget(verify_shell); shell_form.addRow("Local scripts",shell_actions); layout.addWidget(shell_controls)
        controls = QGroupBox("ClickFix Guard Policy"); form = QFormLayout(controls)
        self.profile = QComboBox(); self.profile.addItems([item.value for item in GuardProfile]); self.profile.setCurrentText(str(self.settings.value("profile", "WARN")))
        self.profile.currentTextChanged.connect(self._profile_changed); form.addRow("Configuration profile", self.profile)
        permission_row = QHBoxLayout()
        input_button = QPushButton("Open Input Monitoring Settings"); input_button.setToolTip("Opens System Settings so you can permit the signed ClickFix Guard user-session agent to observe only Command + Space.")
        access_button = QPushButton("Open Accessibility Settings"); access_button.setToolTip("Opens System Settings for the permission required only by Protect Mode shortcut replay.")
        input_button.clicked.connect(lambda: self._open_privacy("Privacy_ListenEvent")); access_button.clicked.connect(lambda: self._open_privacy("Privacy_Accessibility"))
        permission_row.addWidget(input_button); permission_row.addWidget(access_button); form.addRow("macOS privacy permissions", permission_row)
        demo_row=QHBoxLayout(); install_demo=QPushButton("Copy Optional Native Demo Command"); install_demo.setToolTip("Optional defense-in-depth only: builds an ad-hoc signed Command + Space demo. Shell Guard does not require this component."); uninstall_demo=QPushButton("Copy Native Demo Uninstall"); install_demo.clicked.connect(self._copy_demo_install); uninstall_demo.clicked.connect(self._copy_demo_uninstall); demo_row.addWidget(install_demo); demo_row.addWidget(uninstall_demo); form.addRow("Optional native sensor",demo_row)
        test = QPushButton("Test ClickFix Guard"); test.setToolTip(self.TEST_TOOLTIP); test.clicked.connect(self._test); form.addRow("Self-test", test)
        refresh = QPushButton("Refresh ClickFix Guard Status"); refresh.clicked.connect(self.refresh); form.addRow("Sensor health", refresh)
        layout.addWidget(controls)
        self.alert_center = QListWidget(); self.alert_center.setAccessibleName("ClickFix Guard Alert Center"); layout.addWidget(QLabel("ClickFix Guard Alert Center")); layout.addWidget(self.alert_center)
        self.timer = QTimer(self); self.timer.setInterval(30_000); self.timer.timeout.connect(self.refresh)
        self._activated = False

    def showEvent(self, event) -> None:
        super().showEvent(event)
        if not self._activated:
            self._activated = True
            self.refresh()
        if not self.timer.isActive():
            self.timer.start()

    def hideEvent(self, event) -> None:
        self.timer.stop()
        super().hideEvent(event)

    def _profile_changed(self, value: str) -> None:
        self.settings.setValue("profile", value)
        mode = "block" if value in {"PROTECT", "HIGH_ASSURANCE"} else "warn" if value == "WARN" else "audit"
        index=self.shell_mode.findData(mode)
        if index>=0:self.shell_mode.setCurrentIndex(index)
        self._save_shell_policy(mode=mode)

    def _apply_shell_policy(self) -> None:
        self._save_shell_policy(mode=str(self.shell_mode.currentData() or "audit"),warn_threshold=self.shell_warn_threshold.value(),block_threshold=self.shell_block_threshold.value(),generic_proxy_enabled=self.shell_proxy_enabled.isChecked())

    def _save_shell_policy(self, *, mode: str, warn_threshold: int | None = None, block_threshold: int | None = None, generic_proxy_enabled: bool | None = None) -> None:
        managed = Path("/Library/Managed Preferences/com.msaa.clickfix.plist")
        if managed.is_file():
            self._set_status("The MSAA interface profile was saved. System-managed ClickFix policy remains authoritative; contact the administrator to change it.", "pending")
            return
        path = Path.home() / "Library/Preferences/com.msaa.clickfix.plist"
        try:
            payload = plistlib.loads(path.read_bytes()) if path.is_file() else {}
            if not isinstance(payload, dict):
                payload = {}
            payload["mode"] = mode
            if warn_threshold is not None: payload["warn_threshold"] = warn_threshold
            if block_threshold is not None: payload["block_threshold"] = block_threshold
            if generic_proxy_enabled is not None: payload["generic_proxy_enabled"] = generic_proxy_enabled
            if int(payload.get("warn_threshold",4)) >= int(payload.get("block_threshold",7)):
                self._set_status("ClickFix policy rejected: the warning threshold must be lower than the block threshold.", "degraded")
                return
            payload["configuration_version"] = "msaa-ui-1"
            path.parent.mkdir(parents=True, exist_ok=True)
            temporary = path.with_name(path.name + ".tmp")
            temporary.write_bytes(plistlib.dumps(payload, sort_keys=True))
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
            self._set_status(f"ClickFix shell policy saved as {mode}. New shell decisions use this setting immediately.", "pending")
        except (OSError, ValueError, TypeError, plistlib.InvalidFileException) as exc:
            self._set_status(f"ClickFix shell policy could not be saved ({type(exc).__name__}). Existing managed policy was not changed.", "degraded")

    def _set_status(self, text: str, state: str) -> None:
        colors = {
            "active": ("#123D2A", "#B9F6D2", "#36C275"),
            "pending": ("#3D3212", "#FFF1B8", "#D5A928"),
            "degraded": ("#451E24", "#FFD6DB", "#E05B69"),
        }
        background, foreground, border = colors.get(state, colors["pending"])
        self.status_label.setStyleSheet(
            f"QLabel {{ background-color: {background}; color: {foreground}; "
            f"border: 1px solid {border}; border-radius: 6px; padding: 10px; font-weight: 700; }}"
        )
        self.status_label.setText(text)

    @staticmethod
    def _open_privacy(anchor: str) -> None:
        QDesktopServices.openUrl(QUrl(f"x-apple.systempreferences:com.apple.preference.security?{anchor}"))

    def _service(self) -> ClickFixService:
        return ClickFixService(self.store, ClickFixPolicy.for_profile(GuardProfile(self.profile.currentText())))

    def _copy_demo_install(self) -> None:
        root=Path(__file__).resolve().parents[2]; build=root/"native/ClickFixGuard/build-development-demo.sh"; agent=root/"native/ClickFixGuard/.build/development-demo/MSAAClickFixGuardAgent.app"; installer=root/"scripts/install_clickfix_guard.py"
        command=f"{shlex.join(['/bin/sh',str(build)])} && {shlex.join([sys.executable,str(installer),'--agent-app',str(agent),'--profile',self.profile.currentText(),'--development-demo','--acknowledge-unsigned-demo'])}"
        QApplication.clipboard().setText(command); QMessageBox.information(self,"Development Demo Command Copied","A local-only, ad-hoc signed build/install command was copied. Run it in Terminal as your normal logged-in user—do not use sudo. After installation, use the permission buttons above to allow the agent.\n\nThis demo is not Developer ID signed, notarized, or suitable for distribution.")

    def _copy_demo_uninstall(self) -> None:
        installer=Path(__file__).resolve().parents[2]/"scripts/install_clickfix_guard.py"; command=shlex.join([sys.executable,str(installer),"--uninstall"]); QApplication.clipboard().setText(command); QMessageBox.information(self,"Demo Uninstall Command Copied","Run the copied command as your normal logged-in user. It removes the LaunchAgent and demo app while retaining evidence and logs.")

    def _install_shell_guard(self) -> None:
        if QMessageBox.question(self,"Install Interim ClickFix Shell Guard","MSAA will validate and install local scanner scripts, add clearly marked idempotent source blocks to .zshrc, .bashrc, and .bash_profile, and preserve timestamped backups. It will not use sudo, change the login shell, or alter terminal-app settings. Continue?") != QMessageBox.StandardButton.Yes: return
        script=Path(__file__).resolve().parents[2]/"scripts/install_clickfix_shell_guard.py"
        try: result=subprocess.run([sys.executable,str(script)],capture_output=True,text=True,timeout=30,check=False)
        except (OSError,subprocess.TimeoutExpired) as exc: QMessageBox.warning(self,"Shell Guard Installation Failed",f"The local installer could not run ({type(exc).__name__}). No administrator password was requested."); return
        if result.returncode: QMessageBox.warning(self,"Shell Guard Installation Failed",result.stderr.strip() or "The validated installer returned an error. Startup files may be reviewed using their timestamped backups.")
        else:
            self._profile_changed(self.profile.currentText())
            QMessageBox.information(self,"Shell Guard Installed",result.stdout.strip()+"\n\nOpen a new terminal session so its shell loads the adapter. Use Verify Shell Guard after opening the new session. WARN holds suspicious commands for a deliberate challenge; PROTECT blocks high-confidence chains.")
        self.refresh()

    def _uninstall_shell_guard(self) -> None:
        if QMessageBox.question(self,"Uninstall ClickFix Shell Guard","Remove only MSAA-managed shell startup blocks and installed shell-guard files? Privacy-safe event logs will be preserved.") != QMessageBox.StandardButton.Yes: return
        script=Path(__file__).resolve().parents[2]/"scripts/uninstall_clickfix_shell_guard.py"
        try: result=subprocess.run([sys.executable,str(script)],capture_output=True,text=True,timeout=30,check=False)
        except (OSError,subprocess.TimeoutExpired) as exc: QMessageBox.warning(self,"Shell Guard Uninstall Failed",type(exc).__name__); return
        QMessageBox.information(self if result.returncode==0 else self,"Shell Guard Uninstall" if result.returncode==0 else "Shell Guard Uninstall Failed",(result.stdout if result.returncode==0 else result.stderr).strip()); self.refresh()

    def _test(self) -> None:
        result = self._service().ingest_shortcut(_synthetic_envelope())
        self._set_status("SYNTHETIC CLICKFIX TEST — NO REAL INCIDENT DETECTED\n" + json.dumps(result, sort_keys=True), "pending")
        self.refresh()

    def refresh(self) -> None:
        native = Path.home() / "Library/Application Support/MacAuditAgent/ClickFixGuard/events.jsonl"
        try: NativeJournalConsumer(native, self._service()).consume()
        except Exception as exc: self.store.set_health({"native_journal_integrity_valid": False, "native_journal_error": str(exc)})
        status = doctor(self.store.health()); shell = shell_guard_status()
        mode_index=self.shell_mode.findData(shell["mode"])
        if mode_index>=0 and not self.shell_mode.hasFocus(): self.shell_mode.setCurrentIndex(mode_index)
        if shell["warn_threshold"] is not None and not self.shell_warn_threshold.hasFocus(): self.shell_warn_threshold.setValue(int(shell["warn_threshold"]))
        if shell["block_threshold"] is not None and not self.shell_block_threshold.hasFocus(): self.shell_block_threshold.setValue(int(shell["block_threshold"]))
        if not self.shell_proxy_enabled.hasFocus(): self.shell_proxy_enabled.setChecked(bool(shell["generic_proxy_enabled"]))
        window_db=getattr(self.window(),"db",None); bridge=window_db.get_background_monitor_state("clickfix_shell_daemon_bridge_status","not_observed") if window_db and hasattr(window_db,"get_background_monitor_state") else "not_observed"
        self.shell_status_label.setText(f"Installed: {shell['installed']}  •  Hash manifest: {shell['manifest_valid']}  •  Mode: {shell['mode']} ({shell['configuration_source']})\nLogin shell: {shell['login_shell']}  •  Coverage: {shell['coverage_level']}\nzsh: {shell['zsh_adapter_configured']}  •  bashrc: {shell['bashrc_adapter_configured']}  •  bash_profile: {shell['bash_profile_adapter_configured']}  •  PTY proxy available/enabled: {shell['generic_proxy_available']}/{shell['generic_proxy_enabled']}\nLast privacy-safe event: {shell['last_event_at'] or 'not observed'} ({shell['last_event_type'] or 'none'})  •  System Monitor bridge: {bridge}\nNo command text is stored. Missing events do not prove safety; noninteractive and GUI-launched execution remain coverage gaps.")
        if shell["operational"]:
            summary = "Interim shell protection active — " + str(shell["coverage_level"]) + ". Native sensor is optional: " + ("active" if status["fully_active"] else "not active")
            state = "active"
        elif status["fully_active"]:
            summary = "Native sensor active; interim shell guard is not fully configured: " + str(shell["coverage_level"])
            state = "pending"
        elif status["monitoring_active"]:
            summary = "Monitoring active; MSAA integration pending: " + ", ".join(status["error_codes"])
            state = "pending"
        elif status.get("proof_of_concept_ready") and status["error_codes"] == ["CFX003_INPUT_MONITORING_DENIED"]:
            summary = (
                "Proof-of-concept services are running; Input Monitoring approval is required. "
                "Enable MSAAClickFixGuardAgent in System Settings. The sensor will recover automatically."
            )
            state = "pending"
        else:
            summary = "Degraded: " + ", ".join(status["error_codes"])
            state = "degraded"
        self._set_status(summary, state)
        preventive_ready = bool(
            (shell["operational"] and shell["mode"] in {"warn", "block"})
            or (status["fully_active"] and status.get("protect_mode_active"))
        )
        if preventive_ready:
            self.prevention_readiness.setText(
                "PREVENTION READY — ClickFix protection is installed, integrity-verified, and enforcing. It is designed to "
                "interrupt most recognized ClickFix paste-to-terminal patterns. Novel lures, GUI-launched execution, unmonitored "
                "or noninteractive shells, and control bypasses remain possible; keep layered controls and user verification in place."
            )
            self.prevention_readiness.setProperty("preventionReady", True)
            self.prevention_readiness.setStyleSheet("background:#123D2A;color:#B9F6D2;border:1px solid #36C275;border-radius:6px;padding:9px;font-weight:700")
        else:
            self.prevention_readiness.setText(
                "DETECTION / SETUP ONLY — reliable prevention is not established. Install or repair the guard, verify integrity and "
                "coverage, and use Warn or Block mode. Audit mode records recognized patterns but does not prevent submission."
            )
            self.prevention_readiness.setProperty("preventionReady", False)
            self.prevention_readiness.setStyleSheet("background:#3D3212;color:#FFF1B8;border:1px solid #D5A928;border-radius:6px;padding:9px;font-weight:700")
        alerts = self.store.pending_alerts(); self.alert_center.clear()
        critical = 0
        for alert in alerts:
            self._alerts[str(alert.get("alert_id"))] = alert
            self.alert_center.addItem(f"{str(alert.get('severity')).upper()} — {alert.get('title')} — {alert.get('event_id')}")
            if alert.get("severity") == "critical": critical += 1
            if alert.get("severity") != "medium" or self.profile.currentText() != "AUDIT":
                card = self.alert_stack.add_alert(alert)
                if hasattr(card, "action_requested"):
                    try: card.action_requested.disconnect(self._handle_alert_action)
                    except RuntimeError: pass
                    card.action_requested.connect(self._handle_alert_action)
        self.critical_count_changed.emit(critical)
        route = Path.home() / "Library/Application Support/MacAuditAgent/ClickFixGuard/pending-incident-route.json"
        if route.exists():
            try:
                incident_id = str(json.loads(route.read_text(encoding="utf-8")).get("incident_id", ""))
                matches = self.alert_center.findItems(incident_id, Qt.MatchContains)
                if matches: self.alert_center.setCurrentItem(matches[0])
                route.unlink()
            except (OSError, ValueError, json.JSONDecodeError):
                pass

    def _handle_alert_action(self, action: str, alert_id: str) -> None:
        alert = self._alerts.get(alert_id, {})
        if action == "dismiss":
            actor = str(self.settings.value("acknowledgment_actor", "local-console-user"))
            reason = "Synthetic ClickFix test alert closed by user." if bool(alert.get("test_event")) or "SYNTHETIC CLICKFIX TEST" in str(alert.get("title", "")) else "ClickFix alert closed by user; evidence retained."
            self.store.acknowledge(alert_id, actor, reason)
            self.alert_stack.remove_acknowledged(alert_id)
            self._alerts.pop(alert_id, None)
            self.refresh()
            return
        if action == "open_settings":
            self.raise_(); self.setFocus(); return
        if action in {"view_shortcut", "open_incident"}:
            QMessageBox.information(self, "ClickFix Guard Evidence", json.dumps(alert, indent=2, sort_keys=True)); return
        if action == "copy_incident_id":
            QApplication.clipboard().setText(str(alert.get("incident_id") or alert.get("event_id") or "")); return
        if action == "contact_ir":
            QDesktopServices.openUrl(QUrl("mailto:?subject=Potential%20ClickFix%20Incident")); return
        if action == "quarantine_open":
            QMessageBox.warning(self, "Native Quarantine Required", "Clipboard quarantine is performed by the signed ClickFix Guard agent only. If the configured policy did not quarantine this incident, open the incident and preserve the clipboard without pasting it.")
            return
        if action == "restore_quarantined":
            QMessageBox.warning(self, "Authorized Native Restore Required", "Restoration requires the signed native agent, a same-Team authenticated XPC request, and an audited justification. Use the authorized incident workflow; restoring does not mark content safe.")
            return
        if action == "acknowledge":
            reason, ok = QInputDialog.getText(self, "Acknowledge Potential ClickFix Incident", "Acknowledgment reason:")
            if ok and reason.strip():
                actor = str(self.settings.value("acknowledgment_actor", "local-console-user"))
                self.store.acknowledge(alert_id, actor, reason.strip()); self.alert_stack.remove_acknowledged(alert_id); self.refresh()
