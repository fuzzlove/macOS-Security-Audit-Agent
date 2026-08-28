from __future__ import annotations

import base64
import hashlib
from pathlib import Path

from PySide6.QtCore import QObject,QRunnable,QThreadPool,Signal,Qt
from PySide6.QtWidgets import QCheckBox,QComboBox,QFileDialog,QFormLayout,QGroupBox,QHBoxLayout,QLabel,QLineEdit,QMessageBox,QPushButton,QSizePolicy,QSpinBox,QTabWidget,QTableWidget,QTableWidgetItem,QVBoxLayout,QWidget

from mac_audit_agent.network_segmentation import APPROVED_PROVIDERS,EgressEvidenceStore,EgressProbe,EgressTestEngine,provider_by_id
from mac_audit_agent.network_segmentation.reporting import export_report
from mac_audit_agent.network_segmentation.backends.nmap import NmapBackend
from mac_audit_agent.network_segmentation.nmap_profiles import PROFILES,profile_by_id
from mac_audit_agent.network_segmentation.ingress_reporting import export_ingress


class _Signals(QObject):
    completed=Signal(object)
    failed=Signal(str)


class _Runner(QRunnable):
    def __init__(self,kwargs):super().__init__();self.kwargs=kwargs;self.signals=_Signals()
    def run(self):
        try:self.signals.completed.emit(EgressTestEngine().run(**self.kwargs))
        except Exception as exc:self.signals.failed.emit(f"{type(exc).__name__}: {exc}")


class _NmapRunner(QRunnable):
    def __init__(self,args,profile_id,authorization):super().__init__();self.args=args;self.profile_id=profile_id;self.authorization=authorization;self.signals=_Signals()
    def run(self):
        try:
            backend=NmapBackend();code,xml,stderr=backend.run(self.args,3600);rows=backend.summarize_xml(xml) if xml else []
            sanitized_args=["<nmap>",*self.args[1:]]
            self.signals.completed.emit({"schema":"msaa.ingress.nmap.v1","profile_id":self.profile_id,"authorization_reference":self.authorization,"arguments":sanitized_args,"exit_code":code,"stderr":stderr.decode("utf-8","replace"),"xml_sha256":hashlib.sha256(xml).hexdigest(),"raw_xml_base64":base64.b64encode(xml).decode("ascii"),"results":rows,"limitations":["Nmap-only results are inferred or indeterminate without healthy destination-observer evidence.","A closed port proves network reachability and is not proof of segmentation.","This run covers only the configured source vantage and target scope."]})
        except Exception as exc:self.signals.failed.emit(f"{type(exc).__name__}: {exc}")


class NetworkSegmentationPanel(QWidget):
    def __init__(self,database=None,parent=None):
        super().__init__(parent);self.database=database;self.run_record=None;self.pool=QThreadPool.globalInstance();self._build()

    def _build(self):
        root=QVBoxLayout(self);self.segmentation_tabs=QTabWidget();root.addWidget(self.segmentation_tabs)
        ingress_page=QWidget();egress_page=QWidget();self.segmentation_tabs.addTab(egress_page,"Egress Tests");self.segmentation_tabs.addTab(ingress_page,"Ingress Tests")
        ingress_page_layout=QVBoxLayout(ingress_page);layout=QVBoxLayout(egress_page)
        ingress=QGroupBox("Ingress > Network Segmentation")
        ingress_layout=QVBoxLayout(ingress)
        ingress_notice=QLabel("Two-ended ingress validation controller foundation. Active ingress traffic requires a recorded engagement, signed scope, and a healthy destination observer. MSAA does not treat a closed service or a timeout alone as proof of segmentation.")
        ingress_notice.setWordWrap(True);ingress_layout.addWidget(ingress_notice)
        limited=QLabel("LIMITED VANTAGE COVERAGE — A test from one jump-box source does not validate other corporate, wireless, VPN, cloud, third-party, IPv6, or internal paths.")
        limited.setWordWrap(True);limited.setStyleSheet("background:#7F1D1D;color:white;padding:8px;font-weight:700;");ingress_layout.addWidget(limited)
        ingress_actions=QHBoxLayout()
        self.new_engagement_button=QPushButton("New Engagement")
        self.create_plan_button=QPushButton("Create Test Plan")
        self.probe_package_button=QPushButton("Generate Probe Package")
        self.emergency_stop_button=QPushButton("Emergency Stop All Probes")
        for button in (self.new_engagement_button,self.create_plan_button,self.probe_package_button,self.emergency_stop_button):ingress_actions.addWidget(button)
        ingress_actions.addStretch();ingress_layout.addLayout(ingress_actions)
        unavailable="Requires the signed probe-management and passive-capture deployment component; this build will not simulate success."
        for button in (self.create_plan_button,self.probe_package_button,self.emergency_stop_button):button.setEnabled(False);button.setToolTip(unavailable)
        self.new_engagement_button.setToolTip("The scope-enforcement and migration-backed engagement model is installed; the guided editor remains unavailable in this build.")
        self.new_engagement_button.clicked.connect(lambda:QMessageBox.information(self,"Ingress Engagement Editor","The safety-critical engagement, scope, classification, audit-chain, and offline-bundle foundations are installed. The guided engagement editor and enrolled probe service are not yet available; no ingress packets were sent."))
        ingress_page_layout.addWidget(ingress)
        ingress_form=QFormLayout();self.ingress_target=QLineEdit();self.ingress_target.setPlaceholderText("Exact target IP or CIDR")
        self.ingress_authorized_cidr=QLineEdit();self.ingress_authorized_cidr.setPlaceholderText("Authorized destination CIDR containing the target")
        self.ingress_authorization=QLineEdit();self.ingress_authorization.setPlaceholderText("SOW, ROE, ticket, or written authorization reference")
        self.ingress_profile=QComboBox()
        for profile in PROFILES:self.ingress_profile.addItem(profile.name,profile.profile_id)
        self.ingress_approval=QCheckBox("I confirm this source, target, profile, and test window are explicitly authorized")
        ingress_form.addRow("Target",self.ingress_target);ingress_form.addRow("Authorized CIDR",self.ingress_authorized_cidr);ingress_form.addRow("Authorization",self.ingress_authorization);ingress_form.addRow("Fixed Nmap profile",self.ingress_profile);ingress_form.addRow("Scope acknowledgement",self.ingress_approval);ingress_page_layout.addLayout(ingress_form)
        backend=NmapBackend();identity=backend.identity();self.nmap_status=QLabel("Nmap ready: "+identity.get("path","") if identity.get("available") else "Nmap unavailable — install Nmap in /opt/homebrew/bin or /usr/local/bin. No ingress scan will be simulated.");self.nmap_status.setWordWrap(True);ingress_page_layout.addWidget(self.nmap_status)
        self.ingress_run_button=QPushButton("Run Scoped Nmap Ingress Test");self.ingress_export_button=QPushButton("Export Ingress Evidence");self.ingress_export_button.setEnabled(False)
        self.ingress_run_button.setEnabled(bool(identity.get("available")));ingress_buttons=QHBoxLayout();ingress_buttons.addWidget(self.ingress_run_button);ingress_buttons.addWidget(self.ingress_export_button);ingress_buttons.addStretch();ingress_page_layout.addLayout(ingress_buttons)
        self.ingress_results=QTableWidget(0,6);self.ingress_results.setHorizontalHeaderLabels(["Target","Protocol","Port","Nmap state","Reason","Segmentation interpretation"]);self.ingress_results.horizontalHeader().setStretchLastSection(True);ingress_page_layout.addWidget(self.ingress_results)
        self.ingress_run_button.clicked.connect(self._run_ingress_validation);self.ingress_export_button.clicked.connect(self._export_ingress)
        notice=QLabel("Authorized egress validation actively opens outbound TCP connections to the selected public test service. Obtain written scope approval first. MSAA sends no application payload. A reachable port is a review finding, not proof of compromise.");notice.setWordWrap(True);notice.setStyleSheet("background:#78350F;color:#FFF7ED;padding:10px;font-weight:700;");layout.addWidget(notice)
        form=QFormLayout();self.provider=QComboBox()
        for item in APPROVED_PROVIDERS:self.provider.addItem(item.name,item.provider_id)
        self.provider_info=QLabel()
        self.provider_info.setObjectName("egressProviderStatus")
        self.provider_info.setAccessibleName("Selected egress provider qualification status")
        self.provider_info.setWordWrap(True)
        self.provider_info.setTextFormat(Qt.TextFormat.PlainText)
        self.provider_info.setAlignment(Qt.AlignmentFlag.AlignLeft|Qt.AlignmentFlag.AlignTop)
        self.provider_info.setSizePolicy(QSizePolicy.Policy.Expanding,QSizePolicy.Policy.Minimum)
        self.provider_info.setMinimumWidth(0)
        self.provider_info.setMargin(8)
        self.provider_info.setStyleSheet("QLabel#egressProviderStatus { background: palette(alternate-base); border: 1px solid palette(mid); border-radius: 5px; }")
        self.ports=QLineEdit("53,80,443");self.ports.setPlaceholderText("Comma-separated TCP ports, maximum 1024")
        self.full_range=QCheckBox("Full TCP range (ports 1–65535)")
        self.full_range.setToolTip("Available only for broad-port providers. Requires a separate high-traffic confirmation before each run.")
        self.scope=QLineEdit();self.scope.setPlaceholderText("Client, segment, device, or engagement scope")
        self.authorization=QLineEdit();self.authorization.setPlaceholderText("Ticket, statement of work, or approval reference")
        self.timeout=QSpinBox();self.timeout.setRange(1,10);self.timeout.setValue(2);self.confirm=QCheckBox("I confirm this test is authorized for the stated scope and provider")
        form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapLongRows)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        form.addRow("Provider",self.provider)
        # A full-width row gives the wrapped status text a reliable height-for-width
        # calculation. In the field column QFormLayout could retain a one-line row
        # height and crop the second line on narrow windows.
        form.addRow(self.provider_info)
        form.addRow("TCP ports",self.ports);form.addRow("Test range",self.full_range);form.addRow("Target scope",self.scope);form.addRow("Authorization reference",self.authorization);form.addRow("Timeout per port (seconds)",self.timeout);form.addRow("Required approval",self.confirm);layout.addLayout(form)
        actions=QHBoxLayout();self.run_button=QPushButton("Run Authorized Egress Test");self.export_button=QPushButton("Export Evidence Report");self.export_button.setEnabled(False);actions.addWidget(self.run_button);actions.addWidget(self.export_button);actions.addStretch();layout.addLayout(actions)
        self.status=QLabel("No egress test has been run.");self.status.setWordWrap(True);layout.addWidget(self.status)
        self.table=QTableWidget(0,6);self.table.setHorizontalHeaderLabels(["Port","Protocol","Status","Latency ms","Error","Evidence SHA-256"]);self.table.horizontalHeader().setStretchLastSection(True);layout.addWidget(self.table)
        self.run_button.clicked.connect(self._run);self.export_button.clicked.connect(self._export);self.provider.currentIndexChanged.connect(self._provider_changed);self.full_range.toggled.connect(self._full_range_changed);self._provider_changed()

    def _run_ingress_validation(self):
        try:
            profile=profile_by_id(str(self.ingress_profile.currentData()))
            if not self.ingress_authorization.text().strip():raise ValueError("authorization reference is required")
            if not self.ingress_approval.isChecked():raise PermissionError("scope acknowledgement is required")
            high=profile.profile_id=="full_tcp"
            if high and QMessageBox.warning(self,"Confirm Full TCP Ingress Test","This fixed profile scans TCP ports 1–65535 and may create substantial traffic. Confirm the target and approved change window before continuing.",QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.Cancel,QMessageBox.StandardButton.Cancel)!=QMessageBox.StandardButton.Yes:return
            backend=NmapBackend();args=backend.build_profile_arguments(self.ingress_target.text().strip(),self.ingress_authorized_cidr.text().strip(),profile,explicit_high_traffic=high)
        except Exception as exc:QMessageBox.warning(self,"Ingress Scope Rejected",str(exc));return
        self.ingress_run_button.setEnabled(False);self.nmap_status.setText("Nmap ingress profile running asynchronously…")
        runner=_NmapRunner(args,profile.profile_id,self.ingress_authorization.text().strip());runner.signals.completed.connect(self._ingress_completed);runner.signals.failed.connect(self._ingress_failed);self._ingress_runner=runner;self.pool.start(runner)

    def _ingress_completed(self,record):
        self.ingress_record=record;self.ingress_results.setRowCount(0)
        for item in record["results"]:
            row=self.ingress_results.rowCount();self.ingress_results.insertRow(row)
            for column,value in enumerate([item["target"],item["protocol"],item["port"],item["scanner_state"],item["reason"],item["segmentation_result"]]):self.ingress_results.setItem(row,column,QTableWidgetItem(str(value)))
        self.nmap_status.setText(f"Completed with exit code {record['exit_code']}. Scanner-only results are inferred/indeterminate until corroborated by a healthy destination observer. XML SHA-256: {record['xml_sha256']}");self.ingress_run_button.setEnabled(True);self.ingress_export_button.setEnabled(True)
    def _ingress_failed(self,error):self.nmap_status.setText("Ingress test failed: "+error);self.ingress_run_button.setEnabled(True)
    def _export_ingress(self):
        if not hasattr(self,"ingress_record"):return
        path,_=QFileDialog.getSaveFileName(self,"Export Ingress Evidence","MSAA-ingress-evidence.html","Reports (*.html *.docx *.xlsx);;Evidence (*.json *.csv)")
        if path:
            try:export_ingress(self.ingress_record,Path(path));QMessageBox.information(self,"Ingress Evidence Exported",path)
            except Exception as exc:QMessageBox.warning(self,"Ingress Export Failed",str(exc))

    def _provider_changed(self):
        item=provider_by_id(str(self.provider.currentData()))
        state=item.initial_state.value
        qualification="Qualification required before active use. " if item.qualification_required else "Runtime health is not assumed. "
        services=", ".join(sorted(item.protocols))
        self.provider_info.setText(f"{state} · {services.upper()} · {qualification}DNS addresses, ASN, and RIR are resolved and recorded at test time.")
        # QFormLayout can under-allocate a wrapped QLabel by one line on macOS.
        # Reserve the measured hint so status and qualification warnings remain
        # readable at narrow widths and under larger accessibility fonts.
        minimum_text_height=max(self.provider_info.sizeHint().height(),self.provider_info.fontMetrics().lineSpacing()*3+self.provider_info.margin()*2)
        self.provider_info.setMinimumHeight(minimum_text_height)
        self.provider_info.setToolTip(self.provider_info.text())
        broad="broad_ports" in item.capabilities
        self.full_range.setEnabled(broad and not item.qualification_required)
        if not broad:self.full_range.setChecked(False)
        self.run_button.setEnabled(not item.qualification_required)

    def _full_range_changed(self,enabled):
        self.ports.setEnabled(not enabled)
        if enabled:self.ports.setPlaceholderText("Full range selected: ports 1–65535")
        else:self.ports.setPlaceholderText("Comma-separated ports or ranges (for example 53,80,443,8000-8010)")

    def _parsed_ports(self):
        if self.full_range.isChecked():return list(range(1,65536))
        values=[]
        for token in self.ports.text().split(","):
            token=token.strip()
            if not token:continue
            if "-" in token:
                start_text,end_text=token.split("-",1);start=int(start_text);end=int(end_text)
                if start>end:raise ValueError("port range start must not exceed its end")
                if end-start+1>1024:raise ValueError("custom ranges are limited to 1024 ports; use Full TCP Range for ports 1–65535")
                candidates=range(start,end+1)
            else:candidates=(int(token),)
            for port in candidates:
                if not 1<=port<=65535:raise ValueError("ports must be between 1 and 65535")
                if port not in values:values.append(port)
                if len(values)>1024:raise ValueError("custom tests are limited to 1024 unique ports")
        return values

    def _run(self):
        try:probes=[EgressProbe(port) for port in self._parsed_ports()];[probe.validate() for probe in probes]
        except (TypeError,ValueError) as exc:QMessageBox.warning(self,"Invalid Egress Test",str(exc));return
        if not self.confirm.isChecked():QMessageBox.warning(self,"Authorization Required","Confirm written authorization before MSAA opens outbound test connections.");return
        if self.full_range.isChecked():
            warning=("Full TCP Range will attempt 65,535 outbound connections. It may generate significant traffic, take considerable time, and cause the public provider to rate-limit or block this client. Use it only with explicit authorization; a randomized sample is safer for routine checks.\n\nContinue with this full-range test?")
            if QMessageBox.warning(self,"Confirm Full TCP Range",warning,QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.Cancel,QMessageBox.StandardButton.Cancel)!=QMessageBox.StandardButton.Yes:return
        kwargs={"provider":provider_by_id(str(self.provider.currentData())),"probes":probes,"authorization_reference":self.authorization.text(),"target_scope":self.scope.text(),"timeout_seconds":float(self.timeout.value()),"workers":4,"authorized":True,"full_range_authorized":self.full_range.isChecked()}
        runner=_Runner(kwargs);runner.signals.completed.connect(self._completed);runner.signals.failed.connect(self._failed);self.run_button.setEnabled(False);self.status.setText("Egress validation running…");self.pool.start(runner)

    def _completed(self,run):
        self.run_record=run;store=EgressEvidenceStore(Path.home()/"Library/Application Support/MSAA/network-segmentation.sqlite3")
        try:digest=store.save(run)
        finally:store.close()
        self.table.setRowCount(0)
        for item in run.results:
            row=self.table.rowCount();self.table.insertRow(row)
            for col,value in enumerate([item.port,item.protocol,item.status,item.latency_ms if item.latency_ms is not None else "",item.error_code,item.evidence_sha256]):self.table.setItem(row,col,QTableWidgetItem(str(value)))
        reachable=sum(item.status=="reachable" for item in run.results);self.status.setText(f"Completed {len(run.results)} probes; {reachable} reachable. Evidence record SHA-256: {digest}");self.run_button.setEnabled(True);self.export_button.setEnabled(True)

    def _failed(self,error):self.status.setText("Test failed: "+error);self.run_button.setEnabled(True);QMessageBox.warning(self,"Egress Test Failed",error)

    def _export(self):
        if self.run_record is None:return
        path,_=QFileDialog.getSaveFileName(self,"Export Egress Evidence","MSAA-egress-report.html","Reports (*.html *.json *.csv *.txt *.xlsx *.docx *.pdf)")
        if not path:return
        try:export_report(self.run_record,Path(path));QMessageBox.information(self,"Report Exported",path)
        except Exception as exc:QMessageBox.warning(self,"Export Failed",str(exc))
