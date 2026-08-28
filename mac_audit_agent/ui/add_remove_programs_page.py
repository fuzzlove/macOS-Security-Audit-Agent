from __future__ import annotations

import json
import shlex
import subprocess
import sys
from threading import Event
from pathlib import Path

from PySide6.QtCore import QObject, QRunnable, QSortFilterProxyModel, Qt, QThreadPool, Signal, Slot
from PySide6.QtWidgets import QApplication, QAbstractItemView, QHBoxLayout, QInputDialog, QLabel, QLineEdit, QMessageBox, QPushButton, QTableView, QTextBrowser, QVBoxLayout, QWidget

from mac_audit_agent.application_removal import create_application_removal_plan, execute_application_removal
from mac_audit_agent.not_signed.inventory import SoftwareInventoryService
from mac_audit_agent.ui.not_signed.software_table_model import SoftwareTableModel
from mac_audit_agent.system_application_control import create_system_application_control_plan, execute_system_application_control


class _Signals(QObject):
    item = Signal(object); phase = Signal(str); completed = Signal(); failed = Signal(str); removed = Signal(object)


class _InventoryWorker(QRunnable):
    def __init__(self): super().__init__(); self.signals = _Signals(); self.cancel = Event()
    @Slot()
    def run(self):
        try: SoftwareInventoryService().scan(cancel=self.cancel, on_item=self.signals.item.emit, on_phase=self.signals.phase.emit)
        except Exception as exc: self.signals.failed.emit(str(exc)); return
        self.signals.completed.emit()


class _RemovalWorker(QRunnable):
    def __init__(self, plan, executor=execute_application_removal): super().__init__(); self.plan = plan; self.executor = executor; self.signals = _Signals()
    @Slot()
    def run(self):
        try: self.signals.removed.emit(self.executor(self.plan))
        except Exception as exc: self.signals.failed.emit(str(exc))


class _ApplicationsOnly(QSortFilterProxyModel):
    def __init__(self, parent=None): super().__init__(parent); self.query = ""; self.setDynamicSortFilter(True)
    def filterAcceptsRow(self, row, parent):
        item = self.sourceModel().items[row]
        return bool(item.bundle_path and (not self.query or self.query in f"{item.display_name} {item.bundle_identifier or ''} {item.bundle_path}".lower()))


class AddRemoveProgramsPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent); self.setObjectName("addRemoveProgramsPage"); self.pool = QThreadPool.globalInstance(); self.worker = None
        layout = QVBoxLayout(self)
        intro = QLabel("Inventory installed macOS applications and remove reviewed user-owned apps. Eligible system-installed applications can be reversibly disabled or moved to a protected quarantine after dependency review and administrator authorization. Apps on the sealed system volume, SIP-protected paths, critical macOS components, and MSAA itself remain protected.")
        intro.setWordWrap(True); layout.addWidget(intro)
        controls = QHBoxLayout(); self.refresh_button = QPushButton("Refresh Applications"); self.search = QLineEdit(); self.search.setPlaceholderText("Search applications, bundle identifiers, or paths"); controls.addWidget(self.refresh_button); controls.addWidget(self.search, 1); layout.addLayout(controls)
        self.status = QLabel("Select Refresh Applications to inventory this Mac."); self.status.setWordWrap(True); layout.addWidget(self.status)
        self.model = SoftwareTableModel(self); self.proxy = _ApplicationsOnly(self); self.proxy.setSourceModel(self.model)
        self.proxy.setSortRole(SoftwareTableModel.SORT_ROLE)
        self.table = QTableView(); self.table.setModel(self.proxy); self.table.setSortingEnabled(True); self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows); self.table.setAccessibleName("Installed applications"); self.table.setAccessibleDescription("Installed applications with color-coded severity and plain-language potential impact."); self.table.horizontalHeader().setStretchLastSection(True); self.table.horizontalHeader().resizeSection(0, 150); self.table.sortByColumn(0, Qt.DescendingOrder); layout.addWidget(self.table, 2)
        self.details = QTextBrowser(); self.details.setAccessibleName("Application removal preview"); layout.addWidget(self.details, 1)
        actions = QHBoxLayout(); self.preview_button = QPushButton("Preview Removal"); self.remove_button = QPushButton("Force Uninstall Selected"); self.disable_system_button = QPushButton("Force Disable to Quarantine"); self.quarantine_system_button = QPushButton("Force Uninstall to System Quarantine")
        self.remove_button.setObjectName("forceUninstallApplicationButton"); self.disable_system_button.setObjectName("forceDisableSystemApplicationButton"); self.quarantine_system_button.setObjectName("forceUninstallSystemApplicationButton")
        self.remove_button.setToolTip("Gracefully close, then force-stop only identity-matched processes that remain; move the app and exact eligible remnants into a reversible Trash folder.")
        for button in (self.remove_button, self.disable_system_button, self.quarantine_system_button): button.setEnabled(False)
        actions.addWidget(self.preview_button); actions.addWidget(self.remove_button); actions.addWidget(self.disable_system_button); actions.addWidget(self.quarantine_system_button); layout.addLayout(actions)
        self.refresh_button.clicked.connect(self.refresh); self.search.textChanged.connect(self._filter); self.table.selectionModel().selectionChanged.connect(self.preview); self.preview_button.clicked.connect(self.preview); self.remove_button.clicked.connect(self.remove); self.disable_system_button.clicked.connect(lambda: self.system_control("disable")); self.quarantine_system_button.clicked.connect(lambda: self.system_control("remove"))

    def _selected(self):
        rows = self.table.selectionModel().selectedRows(); return rows and self.proxy.data(rows[0], Qt.UserRole)
    def _filter(self, value): self.proxy.query = value.strip().lower(); self.proxy.invalidateFilter()
    def refresh(self):
        if self.worker: return
        self.model.clear(); self.worker = _InventoryWorker(); self.worker.signals.item.connect(self.model.add_item); self.worker.signals.phase.connect(self.status.setText); self.worker.signals.completed.connect(self._complete); self.worker.signals.failed.connect(self._failed); self.refresh_button.setEnabled(False); self.pool.start(self.worker)
    def _complete(self): self.worker = None; self.refresh_button.setEnabled(True); self.status.setText(f"Inventory complete — {self.proxy.rowCount()} installed applications")
    def _failed(self, error): self.worker = None; self.refresh_button.setEnabled(True); self.remove_button.setEnabled(False); self.disable_system_button.setEnabled(False); self.quarantine_system_button.setEnabled(False); self.status.setText("Operation failed"); QMessageBox.warning(self, "Applications", error)
    def preview(self):
        item = self._selected()
        if not item:
            self.remove_button.setEnabled(False); self.disable_system_button.setEnabled(False); self.quarantine_system_button.setEnabled(False); return
        plan = create_application_removal_plan(item)
        system_plan = create_system_application_control_plan(item)
        self.details.setPlainText(json.dumps({"standard_removal": plan.to_dict(), "system_application_control": system_plan.to_dict()}, indent=2, sort_keys=True, default=str))
        self.remove_button.setEnabled(plan.allowed); self.remove_button.setToolTip(plan.refusal_reason or "Force-stop only revalidated processes that resist graceful exit, then move the application to reversible Trash quarantine.")
        system_eligible = system_plan.platform_classification == "system_installed_application" and not system_plan.sealed_system_volume and not system_plan.critical_component
        self.disable_system_button.setEnabled(system_eligible); self.quarantine_system_button.setEnabled(system_eligible)
        tip = system_plan.refusal_reason or "Requires administrator authorization and dependency confirmation. The application is moved to reversible system quarantine."
        self.disable_system_button.setToolTip(tip); self.quarantine_system_button.setToolTip(tip)
    def remove(self):
        item = self._selected()
        if not item: return
        plan = create_application_removal_plan(item)
        if not plan.allowed: QMessageBox.warning(self, "Removal Unavailable", plan.refusal_reason); return
        preview = "\n".join((plan.application_path, *plan.persistence_files, *plan.remnants))
        warning = f"Force uninstall {plan.display_name}?\n\nMSAA will gracefully close {len(plan.processes)} associated process(es), force only identity-matched processes that do not exit, and move these items into a dedicated reversible Trash folder:\n\n{preview}\n\nExcluded user data will be retained. Nothing is permanently deleted. Continue?"
        if QMessageBox.warning(self, "Confirm Application Removal", warning, QMessageBox.Yes | QMessageBox.Cancel, QMessageBox.Cancel) != QMessageBox.Yes: return
        self.remove_button.setEnabled(False); self.refresh_button.setEnabled(False); self.status.setText(f"Removing {plan.display_name}…")
        self.worker = _RemovalWorker(plan); self.worker.signals.removed.connect(self._removed); self.worker.signals.failed.connect(self._failed); self.pool.start(self.worker)
    def system_control(self, action):
        item = self._selected()
        if not item: return
        preview_plan = create_system_application_control_plan(item, action=action, administrator_active=True)
        if preview_plan.sealed_system_volume or preview_plan.critical_component or preview_plan.platform_classification != "system_installed_application":
            QMessageBox.warning(self, "System Application Protected", preview_plan.refusal_reason or "This application is not eligible for system containment."); return
        dependencies = "\n".join(f"• [{impact.severity.upper()}] {impact.impact}\n  Validate: {impact.validation_required}" for impact in preview_plan.dependency_impacts)
        verb = "disable" if action == "disable" else "remove to reversible system quarantine"
        warning = f"Administrator authorization is required to {verb} {preview_plan.display_name}.\n\nDependency impact may be incomplete. Review every item:\n\n{dependencies}\n\nThe application will be closed and moved from /Applications. MSAA will not bypass SIP, authenticated-root, or sealed-system protections."
        if QMessageBox.warning(self, "Administrator Approval Required", warning, QMessageBox.Yes | QMessageBox.Cancel, QMessageBox.Cancel) != QMessageBox.Yes: return
        confirmation, accepted = QInputDialog.getText(self, "Confirm System Application Control", f"Type the application name exactly to authorize this action:\n{preview_plan.display_name}")
        if not accepted or confirmation.strip() != preview_plan.display_name:
            QMessageBox.warning(self, "Authorization Not Confirmed", "The application name did not match. No change was made."); return
        plan = create_system_application_control_plan(item, action=action)
        if not plan.allowed:
            if plan.requires_administrator and not plan.administrator_active and not plan.sealed_system_volume and not plan.critical_component:
                try:
                    self._open_administrator_system_control(preview_plan)
                except Exception as exc:
                    QMessageBox.warning(self, "Administrator Workflow Could Not Start", str(exc))
                    self.status.setText("Administrator workflow could not be started — no application changes were made")
                return
            QMessageBox.warning(self, "System Application Protected", plan.refusal_reason)
            return
        self.disable_system_button.setEnabled(False); self.quarantine_system_button.setEnabled(False); self.refresh_button.setEnabled(False); self.status.setText(f"Applying system containment to {plan.display_name}…")
        self.worker = _RemovalWorker(plan, execute_system_application_control); self.worker.signals.removed.connect(self._system_controlled); self.worker.signals.failed.connect(self._failed); self.pool.start(self.worker)

    def _open_administrator_system_control(self, plan):
        pending = Path.home() / "Library/Application Support/MacAuditAgent/pending-system-app-control"
        pending.mkdir(parents=True, exist_ok=True, mode=0o700); pending.chmod(0o700)
        plan_path = pending / f"{plan.plan_id}.json"
        plan_path.write_text(json.dumps({"schema_version": 1, "plan": plan.to_dict()}, indent=2, sort_keys=True, default=str), encoding="utf-8")
        plan_path.chmod(0o600)
        command = shlex.join(["sudo", "--", sys.executable, "-m", "mac_audit_agent.system_application_control_cli", "--plan", str(plan_path)])
        escaped = command.replace("\\", "\\\\").replace('"', '\\"')
        script = f'tell application "Terminal" to do script "{escaped}"\ntell application "Terminal" to activate'
        result = subprocess.run(["/usr/bin/osascript", "-e", script], capture_output=True, text=True, timeout=10, check=False)
        if result.returncode != 0:
            plan_path.unlink(missing_ok=True)
            raise RuntimeError("Terminal declined the request. No application changes were made.")
        QApplication.clipboard().setText(command)
        self.status.setText("Administrator removal opened in Terminal — review the command and approve sudo there")
        QMessageBox.information(self, "Administrator Removal Ready", "Terminal opened with the reviewed forced-uninstall command. Verify the command, then approve sudo in Terminal. MSAA never receives your password. The command was also copied to the clipboard.")
    def _removed(self, receipt):
        self.worker = None; self.refresh_button.setEnabled(True); self.details.setPlainText(json.dumps(receipt.to_dict(), indent=2, sort_keys=True));
        if receipt.status == "success": QMessageBox.information(self, "Application Removed", "The application and eligible remnants were removed successfully. A recovery receipt was saved in its dedicated Trash folder.")
        else: QMessageBox.warning(self, "Removal Partially Completed", "Some items were retained. Review the receipt before taking further action.")
        self.refresh()
    def _system_controlled(self, receipt):
        self.worker = None; self.refresh_button.setEnabled(True); self.details.setPlainText(json.dumps(receipt.to_dict(), indent=2, sort_keys=True))
        if receipt.status == "success": QMessageBox.information(self, "System Application Contained", "The application was closed and moved to reversible system quarantine. Review the receipt and validate dependent workflows.")
        else: QMessageBox.warning(self, "System Application Partially Contained", "Containment completed with retained processes or other errors. Review the receipt immediately.")
        self.refresh()
