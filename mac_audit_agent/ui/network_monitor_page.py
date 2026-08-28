from __future__ import annotations

import json
import re
from pathlib import Path

from PySide6.QtCore import QObject, QThread, QTimer, Qt, Signal, Slot
from PySide6.QtWidgets import (
    QCheckBox, QFileDialog, QHBoxLayout, QLabel, QLineEdit, QMessageBox,
    QPushButton, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

from mac_audit_agent.firewall.ip_anchor import create_candidate, parse_ip_list, validate_candidate
from mac_audit_agent.firewall.runtime import FirewallPrivilegeClient
from mac_audit_agent.network_activity_monitor import NetworkActivityMonitor
from mac_audit_agent.ui.rdap_lookup_widget import RDAPLookupWidget


class _Collector(QObject):
    completed = Signal(object)
    failed = Signal(str)

    @Slot()
    def run(self) -> None:
        try:
            self.completed.emit(NetworkActivityMonitor().collect())
        except Exception as exc:
            self.failed.emit(str(exc))


class NetworkMonitorPage(QWidget):
    """Live process-to-endpoint inventory with explicit PF policy handoff."""

    snapshot_changed = Signal(object)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("networkMonitorPage")
        self.client = FirewallPrivilegeClient()
        self.snapshot = None
        self.thread = None
        self._worker = None
        self._shutting_down = False
        layout = QVBoxLayout(self)
        description = QLabel(
            "Monitor active TCP/UDP connections and listening sockets grouped by the application or "
            "process that owns them. Selected remote IP addresses can be reviewed, converted into an "
            "isolated MSAA PF block or allow anchor, validated, and submitted to the authenticated Firewall helper."
        )
        description.setWordWrap(True)
        description.setAccessibleName("Network Monitor description")
        layout.addWidget(description)
        safety = QLabel(
            "Connection presence is evidence for review, not proof of malware. Blocking an address can "
            "break updates, authentication, cloud services, VPNs, DNS, or shared infrastructure."
        )
        safety.setWordWrap(True)
        safety.setStyleSheet("color:#b54708;font-weight:650;")
        layout.addWidget(safety)
        controls = QHBoxLayout()
        self.refresh_button = QPushButton("Refresh Connections")
        self.auto_refresh = QCheckBox("Auto refresh every 5 seconds")
        self.search = QLineEdit()
        self.search.setPlaceholderText("Filter by application, PID, user, path, address, port, or protocol")
        for widget in (self.refresh_button, self.auto_refresh, self.search):
            controls.addWidget(widget)
        layout.addLayout(controls)
        actions = QHBoxLayout()
        self.block_button = QPushButton("Add Selected Remote IP to PF Blocklist")
        self.allow_button = QPushButton("Add Selected Remote IP to PF Allowlist")
        self.allow_button.setAccessibleName("Add selected remote IP to PF allowlist")
        self.allow_button.setToolTip("Create and validate an outbound PF pass rule for the selected remote IP. Administrator-authorized helper activation is required; review this security exception carefully.")
        self.export_button = QPushButton("Export Snapshot")
        for widget in (self.block_button, self.allow_button, self.export_button):
            actions.addWidget(widget)
        actions.addStretch()
        layout.addLayout(actions)
        self.summary = QLabel("Not scanned")
        layout.addWidget(self.summary)
        self.tree = QTreeWidget()
        self.tree.setColumnCount(8)
        self.tree.setHeaderLabels(["Application / Connection", "PID", "User", "Protocol", "Local", "Remote", "State", "Risk"])
        self.tree.setAccessibleName("Application network activity")
        self.tree.setSelectionMode(QTreeWidget.SelectionMode.ExtendedSelection)
        self.tree.setSortingEnabled(True)
        layout.addWidget(self.tree)
        self.rdap = RDAPLookupWidget(self)
        layout.addWidget(self.rdap)
        self.timer = QTimer(self)
        self.timer.setInterval(5000)
        self.timer.timeout.connect(self.refresh)
        self.refresh_button.clicked.connect(self.refresh)
        self.auto_refresh.toggled.connect(lambda enabled: self.timer.start() if enabled else self.timer.stop())
        self.search.textChanged.connect(self._filter)
        self.block_button.clicked.connect(self.block_selected)
        self.allow_button.clicked.connect(self.allow_selected)
        self.export_button.clicked.connect(self.export_snapshot)
        self.tree.itemSelectionChanged.connect(self._rdap_from_selection)
        QTimer.singleShot(0, self.refresh)

    def refresh(self) -> None:
        if self._shutting_down:
            return
        if self.thread and self.thread.isRunning():
            return
        self.refresh_button.setEnabled(False)
        self.summary.setText("Collecting active application connections…")
        self.thread = QThread(self)
        worker = _Collector()
        worker.moveToThread(self.thread)
        self.thread.started.connect(worker.run)
        worker.completed.connect(self._loaded)
        worker.failed.connect(self._failed)
        worker.completed.connect(self.thread.quit)
        worker.failed.connect(self.thread.quit)
        self.thread.finished.connect(worker.deleteLater)
        self.thread.finished.connect(self._thread_finished)
        self._worker = worker
        self.thread.start()

    def _thread_finished(self) -> None:
        if self.thread:
            self.thread.deleteLater()
        self.thread = None
        self._worker = None
        self.refresh_button.setEnabled(True)

    def shutdown(self, timeout_ms: int = 3000) -> bool:
        """Stop owned asynchronous work before Qt destroys this widget."""
        self._shutting_down = True
        self.timer.stop()
        thread = self.thread
        if thread is None or not thread.isRunning():
            return True
        thread.requestInterruption()
        thread.quit()
        if thread.wait(timeout_ms):
            return True
        # The collector is a bounded, read-only OS inventory operation.  A
        # running QObject slot cannot process quit(), so final application
        # teardown must stop it rather than let QThread's destructor abort.
        thread.terminate()
        return thread.wait(500)

    def closeEvent(self, event) -> None:
        self.shutdown()
        super().closeEvent(event)

    def _loaded(self, snapshot) -> None:
        self.snapshot = snapshot
        self.tree.clear()
        for group in snapshot.groups:
            parent = QTreeWidgetItem([
                group.process_name or "Unknown process", str(group.pid or ""), group.user,
                "", group.process_path, "", f"{len(group.connections)} connections / {len(group.listeners)} listeners",
                group.risk_level.upper(),
            ])
            parent.setData(0, Qt.ItemDataRole.UserRole, {"kind": "process", "group": group})
            parent.setToolTip(0, "\n".join(group.risk_reasons) or "No elevated heuristic factors identified.")
            self.tree.addTopLevelItem(parent)
            for connection in group.connections:
                child = QTreeWidgetItem([
                    "Outbound connection", str(connection.pid or ""), connection.user, connection.protocol,
                    _endpoint(connection.local_address, connection.local_port),
                    _endpoint(connection.remote_address, connection.remote_port), connection.state, connection.risk_level.upper(),
                ])
                child.setData(0, Qt.ItemDataRole.UserRole, {"kind": "connection", "connection": connection, "group": group})
                parent.addChild(child)
            for listener in group.listeners:
                child = QTreeWidgetItem([
                    "Listening socket", str(listener.pid or ""), listener.user, listener.protocol,
                    _endpoint(listener.local_address, listener.port), "", listener.state, listener.risk_level.upper(),
                ])
                child.setData(0, Qt.ItemDataRole.UserRole, {"kind": "listener", "listener": listener, "group": group})
                parent.addChild(child)
        self.summary.setText(
            f"{len(snapshot.groups)} applications/processes | {snapshot.connection_count} active connections | "
            f"{snapshot.listener_count} listeners | {snapshot.remote_endpoint_count} unique remote endpoints | "
            f"Updated {snapshot.timestamp}"
        )
        self.snapshot_changed.emit(snapshot)
        self.tree.expandToDepth(0)
        self._filter(self.search.text())

    def _failed(self, message: str) -> None:
        self.summary.setText("Collection failed")
        QMessageBox.warning(self, "Network Monitor Collection Failed", message)

    def _filter(self, text: str) -> None:
        query = text.strip().lower()
        for index in range(self.tree.topLevelItemCount()):
            parent = self.tree.topLevelItem(index)
            parent_match = query in " ".join(parent.text(column) for column in range(parent.columnCount())).lower()
            child_match = False
            for child_index in range(parent.childCount()):
                child = parent.child(child_index)
                match = not query or query in " ".join(child.text(column) for column in range(child.columnCount())).lower()
                child.setHidden(not match)
                child_match = child_match or match
            parent.setHidden(bool(query) and not (parent_match or child_match))

    def _rdap_from_selection(self) -> None:
        for item in self.tree.selectedItems():
            payload = item.data(0, Qt.ItemDataRole.UserRole) or {}
            if payload.get("kind") == "connection":
                self.rdap.set_address(payload["connection"].remote_address)
                return

    def block_selected(self) -> None:
        self._apply_selected_pf_policy(action="block")

    def allow_selected(self) -> None:
        self._apply_selected_pf_policy(action="pass")

    def _apply_selected_pf_policy(self, *, action: str) -> None:
        if action not in {"block", "pass"}:
            raise ValueError("Unsupported Network Monitor PF action.")
        addresses: set[str] = set()
        selected_processes: set[str] = set()
        for item in self.tree.selectedItems():
            payload = item.data(0, Qt.ItemDataRole.UserRole) or {}
            if payload.get("kind") != "connection":
                continue
            connection = payload["connection"]
            address = str(connection.remote_address or "").split("%", 1)[0]
            if address not in {"", "*"}:
                addresses.add(address)
                selected_processes.add(str(payload["group"].process_name))
        if not addresses:
            QMessageBox.information(self, "Select Remote Connections", "Select one or more outbound connection rows with a remote IP address.")
            return
        preview = "\n".join(sorted(addresses))
        is_allow = action == "pass"
        verb = "Allow" if is_allow else "Block"
        list_name = "allowlist" if is_allow else "blocklist"
        impact = (
            "An allow rule is a security exception. PF rule and anchor ordering affects precedence, so verify the loaded runtime rules after activation. "
            "Allow only an address whose owner and business purpose have been validated."
            if is_allow else
            "Shared hosting, CDNs, authentication, updates, and unrelated applications may use the same addresses."
        )
        warning = (
            f"{verb} {len(addresses)} selected remote address(es) used by: {', '.join(sorted(selected_processes)) or 'unknown'}?\n\n"
            f"{preview}\n\n"
            f"MSAA will create a separate outbound PF {list_name} anchor. {impact} The candidate must pass PF syntax validation "
            "and privileged helper authorization before networking changes."
        )
        if QMessageBox.warning(self, f"Review PF {list_name.title()} Impact", warning, QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel, QMessageBox.StandardButton.Cancel) != QMessageBox.StandardButton.Yes:
            return
        policy_id = f"network-monitor-{'allow' if is_allow else 'block'}-" + re.sub(r"[^a-z0-9]+", "-", next(iter(sorted(selected_processes)), "selected").lower()).strip("-")[:24]
        try:
            imported = parse_ip_list(preview)
            candidate = validate_candidate(create_candidate(policy_id, imported, action=action, direction="out", log=True))
            payload = {
                "anchor": candidate.anchor_name, "candidate_path": str(candidate.path),
                "candidate_sha256": candidate.content_hash, "policy_id": candidate.policy_id,
                "expected_namespace": "com.liquidsky.msaa",
            }
            self.client.request("install_anchor", payload)
            self.client.request("reload_anchor", {"anchor": candidate.anchor_name, "candidate_sha256": candidate.content_hash})
        except PermissionError as exc:
            QMessageBox.warning(self, "PF Helper Authorization Required", f"{exc}\n\nThe candidate was validated but active networking was not changed.")
            return
        except Exception as exc:
            QMessageBox.warning(self, f"{list_name.title()} Not Applied", f"{exc}\n\nActive networking was not changed.")
            return
        QMessageBox.information(self, f"PF {list_name.title()} Loaded", f"Loaded isolated anchor {candidate.anchor_name} with {len(addresses)} remote address(es). Open Firewall > Active Policies to verify the runtime rule and anchor ordering.")

    def export_snapshot(self) -> None:
        if not self.snapshot:
            QMessageBox.information(self, "No Snapshot", "Refresh Network Monitor before exporting.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export Network Monitor Snapshot", "network-monitor-snapshot.json", "JSON (*.json)")
        if path:
            Path(path).write_text(json.dumps(self.snapshot.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _endpoint(address: str, port: str) -> str:
    if ":" in address and address not in {"", "*"}:
        return f"[{address}]:{port}" if port else address
    return f"{address}:{port}" if port else address


__all__ = ["NetworkMonitorPage"]
