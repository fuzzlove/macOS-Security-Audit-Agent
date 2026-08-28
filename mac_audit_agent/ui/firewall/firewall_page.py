from __future__ import annotations
import json
from pathlib import Path
from PySide6.QtCore import QTimer,QUrl,Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QApplication,QCheckBox,QComboBox,QFileDialog,QFormLayout,QGridLayout,QHBoxLayout,QLabel,QLineEdit,QMessageBox,QPlainTextEdit,QPushButton,QSpinBox,QTabWidget,QTableWidget,QTableWidgetItem,QVBoxLayout,QWidget
from mac_audit_agent.firewall.audit import FirewallAuditLog
from mac_audit_agent.firewall.models import AddressSelector,FirewallPolicy,FirewallRule
from mac_audit_agent.firewall.renderer import render_policy
from mac_audit_agent.firewall.runtime import FirewallPrivilegeClient,inspect_status
from mac_audit_agent.firewall.validator import parse_ports,validate_policy
from mac_audit_agent.firewall.ip_anchor import create_candidate,create_content_candidate,parse_ip_list,sudo_install_command,validate_candidate
from mac_audit_agent.firewall.application_firewall import SETTINGS_URL,inspect_application_firewall,sudo_application_firewall_command
from mac_audit_agent.firewall.policy_inventory import inventory_policies
from mac_audit_agent.ui.responsive_actions import ResponsiveActionRow

class FirewallPage(QWidget):
    status_changed=Signal(dict)
    def __init__(self,parent=None):
        super().__init__(parent); self.setObjectName("firewallPage"); self.client=FirewallPrivilegeClient(); self.policies=[]; self.ip_candidate=None; self.rule_candidate=None; self.last_status={}; self.audit=FirewallAuditLog(Path.home()/"Library/Application Support/MSAA/Firewall/audit/events.jsonl")
        layout=QVBoxLayout(self); note=QLabel("Manage deterministic PF policies through isolated com.liquidsky.msaa anchors. The GUI validates candidates but never runs as root or collects a password. Activation copies an explicit sudo command for the user to review and run in Terminal."); note.setWordWrap(True); note.setAccessibleName("Firewall safety architecture"); layout.addWidget(note)
        self.tabs=QTabWidget(); self.tabs.setAccessibleName("Firewall management sections"); layout.addWidget(self.tabs)
        self.tabs.addTab(self._dashboard(),"Dashboard"); self.tabs.addTab(self._builder(),"Rule Builder"); self.tabs.addTab(self._lists(),"Lists"); self.tabs.addTab(self._policies(),"Policies"); self.tabs.addTab(self._anchors(),"Anchors"); self.tabs.addTab(self._diagnostics(),"Diagnostics"); self.tabs.addTab(self._audit(),"Audit Log"); self._activated=False
    def showEvent(self,event):
        super().showEvent(event)
        if not self._activated:self._activated=True;self.refresh_status()
    def _dashboard(self):
        page=QWidget(); layout=QVBoxLayout(page); grid=QGridLayout(); self.cards={}
        for i,label in enumerate(("PF Runtime","MSAA Anchor","Active Policies","Allow Rules","Block Rules","IPv4 Entries","IPv6 Entries","Domains","Last Reload","Validation","Drift","Rollback Watchdog")):
            card=QLabel(f"{label}\nUnknown"); card.setAccessibleName(label); grid.addWidget(card,i//4,i%4); self.cards[label]=card
        layout.addLayout(grid); buttons=ResponsiveActionRow()
        for label,callback in (("Refresh Status",self.refresh_status),("Validate Configuration",self.validate_current),("Enable PF",lambda:self._privileged("enable_pf")),("Reload MSAA Firewall",lambda:self._privileged("reload_anchor")),("Disable MSAA Policies",lambda:self._privileged("disable_msaa_policy")),("Emergency Rollback",lambda:self._privileged("restore_pf_conf_backup"))):
            button=QPushButton(label); button.setAccessibleName(label); button.clicked.connect(callback); buttons.add_button(button)
        layout.addWidget(buttons); self.app_firewall_state=QLabel("macOS Application Firewall: Unknown"); self.app_firewall_state.setAccessibleName("macOS Application Firewall state"); layout.addWidget(self.app_firewall_state); app_buttons=ResponsiveActionRow()
        for label,callback in (("Open macOS Firewall Settings",self.open_application_firewall_settings),("Turn Application Firewall On",lambda:self.copy_application_firewall_command(True)),("Turn Application Firewall Off",lambda:self.copy_application_firewall_command(False))):
            button=QPushButton(label); button.setAccessibleName(label); button.clicked.connect(callback); app_buttons.add_button(button)
        layout.addWidget(app_buttons); self.status_raw=QPlainTextEdit(); self.status_raw.setReadOnly(True); self.status_raw.setAccessibleName("Raw PF and Application Firewall status"); layout.addWidget(self.status_raw); return page
    def _builder(self):
        page=QWidget(); layout=QVBoxLayout(page); form=QFormLayout(); self.rule_name=QLineEdit("Review rule"); self.action=QComboBox(); self.action.addItems(["Block","Allow"]); self.direction=QComboBox(); self.direction.addItems(["Outbound","Inbound","Both"]); self.family=QComboBox(); self.family.addItems(["Any","IPv4","IPv6"]); self.source=QLineEdit("any"); self.destination=QLineEdit("any"); self.ports=QLineEdit(); self.ports.setPlaceholderText("22,53,80,443 or 8000:8100")
        self.protocols={}; protocol_row=QHBoxLayout()
        for name in ("TCP","UDP","ICMP","ICMPv6","GRE","ESP","AH"):
            box=QCheckBox(name); box.setAccessibleName(f"Protocol {name}"); protocol_row.addWidget(box); self.protocols[name]=box
        self.quick=QCheckBox("Quick"); self.quick.setChecked(True); self.log=QCheckBox("Log"); self.stateful=QCheckBox("Keep state"); self.action.currentTextChanged.connect(self._sync_stateful_option); self._sync_stateful_option(self.action.currentText())
        for label,widget in (("Rule name",self.rule_name),("Action",self.action),("Direction",self.direction),("Address family",self.family),("Source",self.source),("Destination",self.destination),("Destination ports",self.ports)): form.addRow(label,widget)
        form.addRow("Protocols",protocol_row); options=QHBoxLayout(); options.addWidget(self.quick); options.addWidget(self.log); options.addWidget(self.stateful); form.addRow("Options",options); layout.addLayout(form)
        warning=QLabel("Broad TCP, UDP, ICMP/ICMPv6, IPv6, or outbound blocking can disrupt DNS, DHCP, Neighbor Discovery, VPN, updates, and remote administration. Generated rules remain visible below and are never activated without validation and explicit authorization."); warning.setWordWrap(True); layout.addWidget(warning)
        actions=QHBoxLayout(); generate=QPushButton("Generate and Validate Preview"); generate.clicked.connect(self.preview); activate=QPushButton("Validate and Load Protocol Anchor"); activate.clicked.connect(self.load_rule_anchor); actions.addWidget(generate); actions.addWidget(activate); layout.addLayout(actions); self.preview_text=QPlainTextEdit(); self.preview_text.setAccessibleName("Generated PF syntax preview"); layout.addWidget(self.preview_text); return page
    def _lists(self):
        page=QWidget(); layout=QVBoxLayout(page); info=QLabel("Import IPv4 and IPv6 addresses or CIDR subnets. MSAA separates address families, deduplicates entries, collapses adjacent subnets, renders inspectable PF tables, and validates the isolated anchor before requesting helper activation. Domain lists use the separate managed-resolution workflow."); info.setWordWrap(True); layout.addWidget(info)
        controls=QHBoxLayout(); self.ip_policy_id=QLineEdit("imported-blocklist"); self.ip_policy_id.setAccessibleName("Imported IP policy identifier"); self.ip_action=QComboBox(); self.ip_action.addItems(["Block","Allow"]); self.ip_direction=QComboBox(); self.ip_direction.addItems(["Outbound","Inbound"]); self.ip_log=QCheckBox("Log matches")
        import_button=QPushButton("Import IPv4/IPv6 List"); import_button.clicked.connect(self.import_ip_list); load_button=QPushButton("Validate and Load Anchor"); load_button.clicked.connect(self.load_ip_anchor)
        for widget in (QLabel("Policy ID"),self.ip_policy_id,self.ip_action,self.ip_direction,self.ip_log,import_button,load_button): controls.addWidget(widget)
        layout.addLayout(controls); self.ip_import_summary=QLabel("No IP list imported"); self.ip_import_summary.setWordWrap(True); self.ip_import_summary.setAccessibleName("IP list import summary"); layout.addWidget(self.ip_import_summary); self.ip_anchor_preview=QPlainTextEdit(); self.ip_anchor_preview.setAccessibleName("Imported IP PF anchor preview"); layout.addWidget(self.ip_anchor_preview)
        self.list_table=QTableWidget(0,7); self.list_table.setHorizontalHeaderLabels(["Name","Type","Entries","Valid","Invalid","Last Refreshed","Referenced By"]); layout.addWidget(self.list_table); return page
    def _policies(self):
        page=QWidget(); layout=QVBoxLayout(page); controls=QHBoxLayout(); refresh=QPushButton("Refresh Policies"); refresh.clicked.connect(self.refresh_policies); controls.addWidget(refresh); controls.addStretch(); layout.addLayout(controls); self.policy_table=QTableWidget(0,8); self.policy_table.setHorizontalHeaderLabels(["Policy","Version","State","Rules","Anchor","Validation","Hash","Drift"]); self.policy_table.setAccessibleName("Generated and installed PF policies"); layout.addWidget(self.policy_table); return page
    def _anchors(self):
        page=QWidget(); layout=QVBoxLayout(page); text=QLabel("MSAA anchors are manageable only inside com.liquidsky.msaa/*. Third-party anchors are displayed read-only and are never flushed, modified, or removed."); text.setWordWrap(True); layout.addWidget(text); self.anchor_table=QTableWidget(0,7); self.anchor_table.setHorizontalHeaderLabels(["Anchor","Ownership","Installed","Loaded","Rules","File Hash","Drift"]); layout.addWidget(self.anchor_table); return page
    def _diagnostics(self): page=QWidget(); layout=QVBoxLayout(page); self.diagnostics=QPlainTextEdit(); self.diagnostics.setReadOnly(True); layout.addWidget(self.diagnostics); return page
    def _audit(self): page=QWidget(); layout=QVBoxLayout(page); self.audit_view=QPlainTextEdit(); self.audit_view.setReadOnly(True); layout.addWidget(self.audit_view); return page
    def refresh_status(self):
        status=inspect_status(); appfw=inspect_application_firewall(); self.cards["PF Runtime"].setText(f"PF Runtime\n{'Enabled' if status.enabled else 'Disabled' if status.enabled is False else 'Unknown'}"); self.cards["MSAA Anchor"].setText(f"MSAA Anchor\n{'Loaded' if status.anchor_loaded else 'Not loaded'}"); self.app_firewall_state.setText(f"macOS Application Firewall: {'On' if appfw.enabled else 'Off' if appfw.enabled is False else 'Unknown'}"); raw={"packet_filter":status.to_dict(),"application_firewall":appfw.to_dict()}; self.last_status={"state":"ENABLED" if appfw.enabled or status.enabled else "DISABLED" if appfw.enabled is False and status.enabled is False else "UNKNOWN","summary":f"macOS Application Firewall: {'on' if appfw.enabled else 'off' if appfw.enabled is False else 'unknown'}; PF: {'enabled' if status.enabled else 'disabled' if status.enabled is False else 'unknown'}","evidence":raw}; self.status_raw.setPlainText(json.dumps(raw,indent=2)); self.diagnostics.setPlainText(self.status_raw.toPlainText()); self.refresh_policies(); self.status_changed.emit(dict(self.last_status))

    def refresh_policies(self):
        policies=inventory_policies(); self.policies=list(policies); self.policy_table.setRowCount(len(policies))
        for row,policy in enumerate(policies):
            values=(policy.policy_id,str(policy.version),policy.state,str(policy.rules),policy.anchor,policy.validation,policy.content_hash[:16],policy.drift)
            for column,value in enumerate(values):
                item=QTableWidgetItem(value); item.setToolTip(policy.installed_path or policy.candidate_path or value); self.policy_table.setItem(row,column,item)
        self.cards["Active Policies"].setText(f"Active Policies\n{sum(policy.state=='Installed' for policy in policies)}"); self.cards["Allow Rules"].setText(f"Allow Rules\n{sum(policy.allow_rules for policy in policies)}"); self.cards["Block Rules"].setText(f"Block Rules\n{sum(policy.block_rules for policy in policies)}")

    def open_application_firewall_settings(self):
        if not QDesktopServices.openUrl(QUrl(SETTINGS_URL)):
            QMessageBox.warning(self,"Could Not Open Settings","Open System Settings → Network → Firewall manually.")

    def copy_application_firewall_command(self,enabled):
        command=sudo_application_firewall_command(enabled); QApplication.clipboard().setText(command); self.audit.append("set_application_firewall","sudo_command_copied",enabled=enabled,networking_changed=False); QMessageBox.information(self,"Application Firewall Command Copied",f"Copied for review:\n\n{command}\n\nRun it in Terminal and then refresh status. The application did not change the firewall itself.")
    def _rule(self):
        protocols=tuple({"ICMPv6":"icmp6"}.get(name,name.lower()) for name,box in self.protocols.items() if box.isChecked()); family={"Any":"any","IPv4":"inet","IPv6":"inet6"}[self.family.currentText()]; direction={"Outbound":"out","Inbound":"in","Both":"both"}[self.direction.currentText()]
        def selector(value): return AddressSelector() if value.strip().lower()=="any" else AddressSelector("network",(value.strip(),))
        action=self.action.currentText().lower().replace("allow","pass")
        return FirewallRule("rule-1",self.rule_name.text().strip() or "Rule",action,direction,address_family=family,protocols=protocols,source=selector(self.source.text()),destination=selector(self.destination.text()),destination_ports=parse_ports(self.ports.text()),quick=self.quick.isChecked(),log=self.log.isChecked(),state_mode="keep" if action=="pass" and self.stateful.isChecked() else "none")

    def _sync_stateful_option(self,action):
        passing=action=="Allow"; self.stateful.setEnabled(passing); self.stateful.setChecked(passing); self.stateful.setToolTip("PF state tracking is available only for allow/pass rules." if not passing else "Track connections admitted by this pass rule.")
    def preview(self):
        try:
            policy=FirewallPolicy("protocol-preview", "Protocol rule",rules=(self._rule(),)); warnings=validate_policy(policy); rendered=render_policy(policy); self.rule_candidate=create_content_candidate(policy.policy_id,rendered); self.preview_text.setPlainText(("\n".join(f"WARNING: {w}" for w in warnings)+"\n" if warnings else "")+rendered); self.cards["Validation"].setText("Validation\nModel valid"); self.audit.append("validate","success",policy_id=policy.policy_id,warnings=warnings)
        except Exception as exc: self.rule_candidate=None; self.preview_text.setPlainText(str(exc)); self.cards["Validation"].setText("Validation\nFailed")
    def validate_current(self): self.preview(); self.tabs.setCurrentIndex(1)
    def _privileged(self,operation):
        commands={"enable_pf":"sudo /sbin/pfctl -E","disable_msaa_policy":"sudo /sbin/pfctl -a com.liquidsky.msaa.firewall -F rules","reload_anchor":"sudo /sbin/pfctl -n -f /etc/pf.conf && sudo /sbin/pfctl -f /etc/pf.conf"}
        command=commands.get(operation)
        if command:
            QApplication.clipboard().setText(command); self.audit.append(operation,"sudo_command_copied",command=command,networking_changed=False); QMessageBox.information(self,"Sudo pfctl Command Copied","A fixed pfctl command was copied for review in Terminal. sudo will request administrator authorization.\n\nNetworking has not changed yet."); return
        QMessageBox.warning(self,"Rollback Selection Required","Choose a specific timestamped MSAA backup before restoring it. No broad or guessed restore command will be generated.\n\nNetworking was not changed.")

    def load_rule_anchor(self):
        self.preview()
        if not self.rule_candidate: return
        try:
            validated=validate_candidate(self.rule_candidate); self.rule_candidate=validated; command=sudo_install_command(validated); QApplication.clipboard().setText(command); self.audit.append("install_protocol_anchor","sudo_command_copied",anchor=validated.anchor_name,candidate_sha256=validated.content_hash,networking_changed=False); QMessageBox.information(self,"Protocol Anchor Command Copied","The generated protocol rule was syntax-checked with pfctl. Its hash-bound sudo installation command was copied for review in Terminal.\n\nNetworking has not changed yet.")
        except Exception as exc: QMessageBox.warning(self,"Protocol Anchor Not Loaded",str(exc)+"\n\nNetworking was not changed.")
    def import_ip_list(self):
        path,_=QFileDialog.getOpenFileName(self,"Import IPv4 and IPv6 List","","Text and List Files (*.txt *.list *.csv);;All Files (*)")
        if not path: return
        try:
            source=Path(path)
            if source.is_symlink() or source.stat().st_size>10_000_000: raise ValueError("Import must be a regular non-symlink file no larger than 10 MB.")
            imported=parse_ip_list(source.read_text(encoding="utf-8",errors="strict")); candidate=create_candidate(self.ip_policy_id.text().strip(),imported,action="pass" if self.ip_action.currentText()=="Allow" else "block",direction="in" if self.ip_direction.currentText()=="Inbound" else "out",log=self.ip_log.isChecked()); self.ip_candidate=candidate
            self.ip_anchor_preview.setPlainText(candidate.content); self.ip_import_summary.setText(f"Lines: {imported.total_lines} | IPv4 networks: {len(imported.ipv4)} | IPv6 networks: {len(imported.ipv6)} | Duplicates: {imported.duplicates} | Invalid: {len(imported.invalid)}\nInvalid entries: {', '.join(imported.invalid[:20]) or 'none'}")
            self.cards["IPv4 Entries"].setText(f"IPv4 Entries\n{len(imported.ipv4)}"); self.cards["IPv6 Entries"].setText(f"IPv6 Entries\n{len(imported.ipv6)}"); self.audit.append("ip_list_import","success",policy_id=candidate.policy_id,source_hash=imported.source_hash,ipv4=len(imported.ipv4),ipv6=len(imported.ipv6),invalid=len(imported.invalid),activated=False)
        except Exception as exc: self.ip_candidate=None; QMessageBox.warning(self,"IP List Import Failed",str(exc)+"\n\nNo PF rules were changed.")
    def load_ip_anchor(self):
        if not self.ip_candidate: QMessageBox.information(self,"No Candidate","Import and review an IPv4/IPv6 list first."); return
        try:
            validated=validate_candidate(self.ip_candidate); self.ip_candidate=validated; self.cards["Validation"].setText("Validation\nPF syntax valid")
            payload={"anchor":validated.anchor_name,"candidate_path":str(validated.path),"candidate_sha256":validated.content_hash,"policy_id":validated.policy_id,"expected_namespace":"com.liquidsky.msaa"}
            command=sudo_install_command(validated); QApplication.clipboard().setText(command); self.audit.append("install_ip_anchor","sudo_command_copied",**payload,networking_changed=False); QMessageBox.information(self,"Sudo Command Copied","The validated activation command was copied to the clipboard. Review and run it in Terminal; sudo will request your password.\n\nActive networking has not changed yet.")
        except Exception as exc: self.audit.append("install_ip_anchor","blocked_or_failed",error=str(exc),networking_changed=False); QMessageBox.warning(self,"Anchor Not Loaded",str(exc)+"\n\nThe candidate remains available for review. Active networking was not changed.")
