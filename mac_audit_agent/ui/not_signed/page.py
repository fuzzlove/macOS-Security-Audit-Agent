from __future__ import annotations

import json
import hashlib
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from threading import Event

from PySide6.QtCore import QObject, QRunnable, QSortFilterProxyModel, Qt, QThreadPool, Signal, Slot, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (QAbstractItemView, QComboBox, QFileDialog, QGridLayout, QHBoxLayout, QLabel, QLineEdit, QMenu, QMessageBox, QPushButton, QSplitter, QTableView, QTextBrowser, QVBoxLayout, QWidget)

from mac_audit_agent.not_signed.actions import create_removal_plan, force_disable_software, force_uninstall_to_trash, move_application_to_trash, terminate_process
from mac_audit_agent.not_signed.inventory import SoftwareInventoryService
from mac_audit_agent.not_signed.models import SoftwareTrustClassification

from .software_table_model import SoftwareTableModel


class _Signals(QObject):
    item = Signal(object); phase = Signal(str); completed = Signal(); failed = Signal(str)


class _ScanWorker(QRunnable):
    def __init__(self): super().__init__(); self.signals = _Signals(); self.cancel = Event()
    @Slot()
    def run(self):
        try: SoftwareInventoryService().scan(cancel=self.cancel, on_item=self.signals.item.emit, on_phase=self.signals.phase.emit)
        except Exception as exc: self.signals.failed.emit(str(exc)); return
        self.signals.completed.emit()


class _FilterModel(QSortFilterProxyModel):
    def __init__(self, parent=None): super().__init__(parent); self.mode = "Recommended Review"; self.query = ""; self.setDynamicSortFilter(True)
    def filterAcceptsRow(self, row, parent):
        item = self.sourceModel().items[row]
        haystack = " ".join((item.display_name, str(item.bundle_identifier or ""), str(item.signing.team_identifier or ""), str(item.executable_path), " ".join(item.signing.authorities))).lower()
        if self.query and self.query not in haystack: return False
        c = item.signing.classification
        predicates = {
            "Recommended Review": c in {SoftwareTrustClassification.AD_HOC, SoftwareTrustClassification.UNSIGNED, SoftwareTrustClassification.INVALID, SoftwareTrustClassification.REVOKED, SoftwareTrustClassification.UNKNOWN},
            "Unsigned Only": c == SoftwareTrustClassification.UNSIGNED,
            "Invalid or Modified": c in {SoftwareTrustClassification.INVALID, SoftwareTrustClassification.REVOKED},
            "Running Processes": bool(item.running_processes), "Installed Applications": item.bundle_path is not None,
            "Persistent Items": bool(item.persistence_items), "Privileged Items": any(p.privileged for p in item.running_processes),
            "Not from App Store": c != SoftwareTrustClassification.MAC_APP_STORE,
            "Third-Party Signed": c in {SoftwareTrustClassification.DEVELOPER_ID_VALID, SoftwareTrustClassification.DEVELOPER_ID_NOTARIZED},
            "Apple Software": c == SoftwareTrustClassification.APPLE_PLATFORM, "Mac App Store": c == SoftwareTrustClassification.MAC_APP_STORE,
            "All Software": True,
        }
        return predicates.get(self.mode, True)


class NotSignedPage(QWidget):
    scan_completed = Signal(object)
    DESCRIPTION = "Lists installed applications and running processes that are unsigned, invalidly signed, signed by a third-party developer, or not installed through the official Mac App Store. Review software provenance, signature integrity, associated files, and system activity before terminating or removing an item."
    def __init__(self, parent=None):
        super().__init__(parent); self.setObjectName("notSignedPage"); self.pool = QThreadPool.globalInstance(); self.worker = None
        layout = QVBoxLayout(self); description = QLabel(self.DESCRIPTION); description.setWordWrap(True); description.setAccessibleName("Unsigned Software section description"); layout.addWidget(description)
        self.summary = QGridLayout(); self.cards = {}
        labels = ("Unsigned", "Invalid or Modified", "Ad Hoc Signed", "Notarization Unverified", "Non-App-Store", "Valid Developer ID", "Running Reviewed Processes", "Removal Candidates")
        for index, label in enumerate(labels):
            card = QLabel(f"{label}\n0"); card.setAccessibleName(label); card.setToolTip(f"Count of {label.lower()} items in the current inventory."); self.summary.addWidget(card, index//4, index%4); self.cards[label] = card
        layout.addLayout(self.summary)
        controls = QHBoxLayout(); self.scan_button = QPushButton("Scan Software Provenance"); self.cancel_button = QPushButton("Cancel"); self.cancel_button.setEnabled(False)
        self.filter = QComboBox(); self.filter.addItems(["Recommended Review", "Unsigned Only", "Invalid or Modified", "Running Processes", "Installed Applications", "Persistent Items", "Privileged Items", "Not from App Store", "Third-Party Signed", "Apple Software", "Mac App Store", "All Software"])
        self.search = QLineEdit(); self.search.setPlaceholderText("Search name, bundle ID, developer, Team ID, path, or authority")
        controls.addWidget(self.scan_button); controls.addWidget(self.cancel_button); controls.addWidget(self.filter); controls.addWidget(self.search); layout.addLayout(controls)
        self.phase = QLabel("Not scanned"); self.phase.setAccessibleName("Software provenance scan progress"); layout.addWidget(self.phase)
        splitter = QSplitter(Qt.Vertical); self.model = SoftwareTableModel(self); self.proxy = _FilterModel(self); self.proxy.setSourceModel(self.model)
        self.proxy.setSortRole(SoftwareTableModel.SORT_ROLE)
        self.table = QTableView(); self.table.setModel(self.proxy); self.table.setSortingEnabled(True); self.table.setAccessibleName("Unsigned Software inventory"); self.table.horizontalHeader().setStretchLastSection(True); splitter.addWidget(self.table)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.details = QTextBrowser(); self.details.setAccessibleName("Software provenance details"); splitter.addWidget(self.details); layout.addWidget(splitter)
        actions = QHBoxLayout(); self.reveal = QPushButton("Reveal in Finder"); self.copy = QPushButton("Copy Path"); self.export = QPushButton("Export Selected Evidence"); self.export_running = QPushButton("Export All Running Software"); self.terminate = QPushButton("Terminate"); self.force_disable = QPushButton("Force Disable Selected"); self.force_uninstall = QPushButton("Force Uninstall to Trash"); self.plan = QPushButton("Create Removal Plan"); self.rescan = QPushButton("Verify Signature Again")
        self.force_disable.setObjectName("notSignedForceDisableButton"); self.force_uninstall.setObjectName("notSignedForceUninstallButton")
        self.force_disable.setToolTip("Force-stop only identity-revalidated processes and reversibly quarantine exact user LaunchAgent persistence. The application remains installed and can still be launched manually.")
        self.force_uninstall.setToolTip("Force-disable exact active components, then move the eligible application to Trash. No permanent deletion is performed.")
        self.export_running.setToolTip("Export one local JSON report covering every currently inventoried running application/process and its available signature evidence.")
        for button in (self.reveal, self.copy, self.export, self.export_running, self.terminate, self.force_disable, self.force_uninstall, self.plan, self.rescan): actions.addWidget(button)
        layout.addLayout(actions)
        self.scan_button.clicked.connect(self.start_scan); self.cancel_button.clicked.connect(self.cancel_scan); self.search.textChanged.connect(self._filter); self.filter.currentTextChanged.connect(self._filter); self.table.selectionModel().selectionChanged.connect(self.show_details)
        self.reveal.clicked.connect(self._reveal); self.copy.clicked.connect(self._copy); self.export.clicked.connect(self._export); self.export_running.clicked.connect(self._export_all_running); self.terminate.clicked.connect(self._terminate); self.force_disable.clicked.connect(self._force_disable_selected); self.force_uninstall.clicked.connect(self._force_uninstall_selected); self.plan.clicked.connect(self._plan); self.rescan.clicked.connect(self.start_scan)
        self.table.customContextMenuRequested.connect(self._context_menu)

    def start_scan(self):
        if self.worker: return
        self.model.clear(); self.details.clear(); self.worker = _ScanWorker(); self.worker.signals.item.connect(self._item); self.worker.signals.phase.connect(self.phase.setText); self.worker.signals.completed.connect(self._done); self.worker.signals.failed.connect(self._failed); self.scan_button.setEnabled(False); self.cancel_button.setEnabled(True); self.pool.start(self.worker)
    def cancel_scan(self):
        if self.worker: self.worker.cancel.set(); self.phase.setText("Cancellation requested")
    def _item(self, item): self.model.add_item(item); self._summary()
    def _done(self):
        self.worker = None; self.scan_button.setEnabled(True); self.cancel_button.setEnabled(False); self.phase.setText(f"Complete — {len(self.model.items)} unique applications and executables"); self.scan_completed.emit(list(self.model.items))
    def _failed(self, error): self.worker = None; self.scan_button.setEnabled(True); self.cancel_button.setEnabled(False); self.phase.setText("Scan failed"); QMessageBox.warning(self, "Software Provenance Scan Failed", error)
    def _filter(self): self.proxy.mode = self.filter.currentText(); self.proxy.query = self.search.text().strip().lower(); self.proxy.invalidateFilter()
    def _selected(self):
        rows = self.table.selectionModel().selectedRows(); return rows and self.proxy.data(rows[0], Qt.UserRole)
    def show_details(self):
        item = self._selected()
        if not item: return
        payload = item.to_dict(); payload["classification_note"] = "Not signed, not signed by Apple, not from the Mac App Store, third-party signed, and invalidly signed are distinct assessments. User trust does not change cryptographic classification."
        payload["available_actions"] = ["inspect", "export", "rescan"] + ([] if item.protected else ["terminate eligible processes", "create reviewed removal plan"])
        payload["privileged_removal"] = "Unavailable until an approved allowlisted privileged-helper operation is integrated. The GUI never runs as root."
        self.details.setPlainText(json.dumps(payload, indent=2, sort_keys=True, default=str))
    def _summary(self):
        items = self.model.items; count = Counter(item.signing.classification for item in items)
        values = {"Unsigned": count[SoftwareTrustClassification.UNSIGNED], "Invalid or Modified": count[SoftwareTrustClassification.INVALID]+count[SoftwareTrustClassification.REVOKED], "Ad Hoc Signed": count[SoftwareTrustClassification.AD_HOC], "Notarization Unverified": count[SoftwareTrustClassification.DEVELOPER_ID_VALID]+count[SoftwareTrustClassification.UNKNOWN], "Non-App-Store": sum(i.signing.classification != SoftwareTrustClassification.MAC_APP_STORE for i in items), "Valid Developer ID": count[SoftwareTrustClassification.DEVELOPER_ID_VALID]+count[SoftwareTrustClassification.DEVELOPER_ID_NOTARIZED], "Running Reviewed Processes": sum(bool(i.running_processes) for i in items), "Removal Candidates": sum(i.severity in {"critical","high","medium"} and not i.protected for i in items)}
        for label, value in values.items(): self.cards[label].setText(f"{label}\n{value}")
    def _reveal(self):
        item=self._selected()
        if item: QDesktopServices.openUrl(QUrl.fromLocalFile(str((item.bundle_path or item.executable_path).parent)))
    def _copy(self):
        from PySide6.QtWidgets import QApplication
        item=self._selected()
        if item: QApplication.clipboard().setText(str(item.bundle_path or item.executable_path))
    def _export(self):
        item=self._selected()
        if not item: return
        path,_=QFileDialog.getSaveFileName(self,"Export Software Evidence",f"{item.display_name}-software-evidence.json","JSON (*.json)")
        if path: Path(path).write_text(json.dumps(item.to_dict(),indent=2,sort_keys=True,default=str)+"\n",encoding="utf-8")
    def _export_all_running(self):
        running = [item for item in self.model.items if item.running_processes]
        if not running:
            QMessageBox.information(self, "Export Running Software", "No running software evidence is available. Run Scan Software Provenance first."); return
        generated = datetime.now(timezone.utc).isoformat()
        records = [item.to_dict() for item in running]
        canonical = json.dumps(records, sort_keys=True, separators=(",", ":"), default=str)
        payload = {
            "schema_version": "1.0",
            "report_type": "MSAA_RUNNING_SOFTWARE_PROVENANCE",
            "generated_at": generated,
            "running_software_count": len(running),
            "running_process_count": sum(len(item.running_processes) for item in running),
            "records_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
            "qualification": "Point-in-time local inventory. Unknown or unsigned provenance is a review condition, not proof of maliciousness.",
            "software": records,
        }
        path, _ = QFileDialog.getSaveFileName(self, "Export All Running Software Evidence", "msaa-running-software-evidence.json", "JSON (*.json)")
        if path:
            Path(path).write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
            QMessageBox.information(self, "Running Software Exported", f"Exported {len(running)} software records containing {payload['running_process_count']} running processes.")
    def _terminate(self):
        item=self._selected()
        if not item or not item.running_processes: QMessageBox.information(self,"Terminate","No eligible running process is associated with this item."); return
        process=item.running_processes[0]
        if QMessageBox.warning(self,"Terminate Process",f"Terminate {process.name} (PID {process.pid})?\n\nExecutable: {process.executable_path}\n\nMSAA will revalidate start time and executable identity and request graceful termination.",QMessageBox.Yes|QMessageBox.Cancel,QMessageBox.Cancel)!=QMessageBox.Yes: return
        ok,message=terminate_process(process.pid,process.start_time,process.executable_path); QMessageBox.information(self,"Termination Result",message) if ok else QMessageBox.warning(self,"Termination Refused",message)
    def _plan(self):
        item=self._selected()
        if not item: return
        plan=create_removal_plan(item,privileged_helper_available=False); self.details.setPlainText(json.dumps(plan.to_dict(),indent=2,sort_keys=True,default=str)); QMessageBox.information(self,"Removal Plan Created","A non-destructive reviewed plan was created. Privileged execution remains unavailable; no files or services were changed.")

    def _confirm_forced_action(self, item, operation: str) -> bool:
        if item.protected:
            QMessageBox.warning(self, "Protected Software", item.protection_reason or "This software is protected and cannot be changed."); return False
        target = item.bundle_path or item.executable_path
        text = (
            f"{operation} {item.display_name}?\n\nTarget: {target}\nSignature: {item.signing.classification.value}\n"
            f"Team ID: {item.signing.team_identifier or 'unavailable'}\n\nOnly exact revalidated processes and user persistence are eligible. "
            "Apple, SIP, sealed-system, privileged, and MSAA targets are refused. The operation is reversible and does not permanently delete files."
        )
        return QMessageBox.warning(self, "Confirm Forced Software Control", text, QMessageBox.Yes | QMessageBox.Cancel, QMessageBox.Cancel) == QMessageBox.Yes

    def _force_disable_selected(self):
        item = self._selected()
        if not item or not self._confirm_forced_action(item, "Force disable"): return
        try: result = force_disable_software(item)
        except (OSError, PermissionError) as exc: QMessageBox.warning(self, "Force Disable Refused", str(exc)); return
        self.details.setPlainText(json.dumps(result, indent=2, sort_keys=True)); QMessageBox.information(self, "Force Disable Completed", "Exact active components were force-stopped or moved to reversible quarantine. Manual relaunch remains possible unless the application is uninstalled."); self.start_scan()

    def _force_uninstall_selected(self):
        item = self._selected()
        if not item or not self._confirm_forced_action(item, "Force uninstall to Trash"): return
        try: result = force_uninstall_to_trash(item)
        except (OSError, PermissionError) as exc: QMessageBox.warning(self, "Force Uninstall Refused", str(exc)); return
        self.details.setPlainText(json.dumps(result, indent=2, sort_keys=True)); QMessageBox.information(self, "Force Uninstall Completed", result["message"]) if result["application_moved_to_trash"] else QMessageBox.warning(self, "Force Uninstall Incomplete", result["message"]); self.start_scan()

    def _context_menu(self, position):
        index = self.table.indexAt(position)
        if index.isValid():
            self.table.selectRow(index.row())
        item = self._selected()
        if not item:
            return
        menu = QMenu(self)
        menu.addAction("View Details", self.show_details)
        menu.addAction("Reveal in Finder", self._reveal)
        menu.addAction("Export Evidence", self._export)
        menu.addSeparator()
        if item.running_processes and not item.protected:
            menu.addAction("Disable Now (Terminate Process)", self._terminate)
        if not item.protected:
            menu.addAction("Force Disable Selected", self._force_disable_selected)
            menu.addAction("Force Uninstall to Trash", self._force_uninstall_selected)
        remove = menu.addAction("Move Application to Trash", self._remove_selected)
        remove.setEnabled(not item.protected)
        menu.addAction("Create Reviewed Removal Plan", self._plan)
        menu.exec(self.table.viewport().mapToGlobal(position))

    def _remove_selected(self):
        item = self._selected()
        if not item:
            return
        apple = item.signing.classification in {SoftwareTrustClassification.APPLE_PLATFORM, SoftwareTrustClassification.MAC_APP_STORE}
        warning = (
            f"You are reviewing removal of:\n\n{item.display_name}\n{item.bundle_path or item.executable_path}\n\n"
            f"Signature classification: {item.signing.classification.value}\n"
            f"Team identifier: {item.signing.team_identifier or 'unavailable'}\n\n"
        )
        if apple:
            warning += (
                "CAUTION: This item is identified as Apple platform or Mac App Store software. "
                "Removing official or system-integrated software can damage macOS, break updates, "
                "or prevent login and recovery. Protected Apple items will be refused.\n\n"
            )
        else:
            warning += "Moving software may stop services, helpers, login items, or dependent applications.\n\n"
        warning += "The eligible primary application will be moved to Trash, not permanently deleted. Continue?"
        if QMessageBox.warning(self, "Potentially Harmful Software Removal", warning, QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel, QMessageBox.StandardButton.Cancel) != QMessageBox.StandardButton.Yes:
            return
        ok, message = move_application_to_trash(item)
        if ok:
            QMessageBox.information(self, "Application Moved to Trash", message)
            self.start_scan()
        else:
            QMessageBox.warning(self, "Removal Refused", message)
