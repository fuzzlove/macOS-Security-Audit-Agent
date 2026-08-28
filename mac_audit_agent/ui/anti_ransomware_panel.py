from __future__ import annotations

import html
import json
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from PySide6.QtCore import QSize, Qt, QUrl, Signal
from PySide6.QtGui import QDesktopServices, QPixmap
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from mac_audit_agent.anti_ransomware import rules as ransomware_rules
from mac_audit_agent.anti_ransomware.adaptive_action_suite import (
    run_adaptive_action_suite,
)
from mac_audit_agent.anti_ransomware.adaptive_detector import (
    run_adaptive_detector_demo,
)
from mac_audit_agent.anti_ransomware.advisory_sources import advisory_source_status
from mac_audit_agent.anti_ransomware.evidence import create_evidence_bundle
from mac_audit_agent.anti_ransomware.guidance_engine import (
    GuidanceAuditLog,
    GuidanceEngine,
)
from mac_audit_agent.anti_ransomware.health import (
    EXPECTED_SENSOR_PATH,
    ESClientResult,
    source_health,
)
from mac_audit_agent.anti_ransomware.install_guidance import (
    DEVELOPMENT_INSTALL_COMMAND,
    development_sensor_install_guide,
)
from mac_audit_agent.anti_ransomware.legal_safety import AUTHORIZED_USE_STATEMENT
from mac_audit_agent.anti_ransomware.recovery import analyze_recovery_readiness
from mac_audit_agent.anti_ransomware.repair import repair_plan
from mac_audit_agent.anti_ransomware.simulation_suite import (
    catalog_metadata,
    export_simulation_report,
    run_simulation_suite,
)
from mac_audit_agent.anti_ransomware.standards_mapping import map_readiness
from mac_audit_agent.anti_ransomware.terminal_install import (
    DevelopmentSensorLaunchError,
    endpoint_security_sensor_repair_command,
    open_development_sensor_install_in_terminal,
    open_development_sensor_repair_in_terminal,
    open_endpoint_security_sensor_repair_in_terminal,
    repository_install_command,
    repository_repair_command,
)
from mac_audit_agent.anti_ransomware.yara_validation_suite import (
    run_yara_validation_suite,
)
from mac_audit_agent.assets import get_asset_path
from mac_audit_agent.protection.components import active_protection_components
from mac_audit_agent.protection.status import resolve_active_protection_status
from mac_audit_agent.ui.responsive_actions import ResponsiveActionRow

CONSULTING_BANNER_TEXT = (
    "Professional ransomware-readiness, incident-response, and security consulting "
    "from Liquidsky Security Network. Call 469-921-3983 for more information."
)
CONSULTING_URL = "https://liquidskysecurity.com"
IC3_RANSOMWARE_REFERENCE_ID = "fbi-ic3-ransomware"


def incident_reporting_references(references) -> list[dict[str, object]]:
    """Return the primary IC3 channel first, followed by supplemental FBI references."""
    reporting = [
        dict(reference)
        for reference in references
        if "Reporting" in str(reference.get("category", ""))
        or reference.get("organization") in {"FBI", "FBI Internet Crime Complaint Center"}
    ]
    return sorted(
        reporting,
        key=lambda reference: (reference.get("reference_id") != IC3_RANSOMWARE_REFERENCE_ID,),
    )


def open_government_url_in_new_window(url: str) -> bool:
    """Open one trusted HTTPS government URL in a separate browser window on macOS."""
    parsed=urlparse(url); hostname=(parsed.hostname or "").lower()
    if parsed.scheme!="https" or not hostname.endswith(".gov"):
        return False
    try:
        subprocess.Popen(["/usr/bin/open","-n",url],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
        return True
    except OSError:
        return False


class ConsultingBannerImage(QLabel):
    clicked = Signal()

    def __init__(self, image_path: Path, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._source = QPixmap(str(image_path))
        self.setObjectName("antiRansomwareConsultingImage")
        self.setAccessibleName(
            "Ransomware awareness and Liquidsky Security Network consulting advertisement. "
            "Open liquidskysecurity.com."
        )
        self.setToolTip(f"Open Liquidsky Security Network: {CONSULTING_URL}")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setMinimumHeight(220)
        self.setMaximumHeight(480)
        self._update_pixmap()

    def sizeHint(self) -> QSize:
        if self._source.isNull():
            return QSize(900, 320)
        return QSize(900, 480)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._update_pixmap()

    def mouseReleaseEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mouseReleaseEvent(event)

    def keyPressEvent(self, event) -> None:
        if event.key() in {Qt.Key.Key_Return, Qt.Key.Key_Enter, Qt.Key.Key_Space}:
            self.clicked.emit()
            event.accept()
            return
        super().keyPressEvent(event)

    def _update_pixmap(self) -> None:
        if self._source.isNull():
            self.setText("Ransomware Awareness — Liquidsky Security Network")
            return
        target = self.size()
        if target.width() <= 0 or target.height() <= 0:
            target = self.sizeHint()
        self.setPixmap(self._source.scaled(target, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation))


class AntiRansomwarePanel(QWidget):
    """Integrated ransomware protection, evidence, repair, and awareness surface."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setAccessibleName("Anti-Ransomware Protection")
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(0, 0, 0, 0)
        self.tabs = QTabWidget()
        self.tabs.setAccessibleName("Anti-Ransomware sections")
        root_layout.addWidget(self.tabs)
        overview = QWidget()
        layout = QVBoxLayout(overview)
        layout.setContentsMargins(22, 16, 22, 18)
        layout.setSpacing(10)

        title = QLabel("Ransomware Awareness & Professional Consulting")
        title.setAccessibleName("Ransomware Awareness and Professional Consulting heading")
        title.setStyleSheet("font-size: 24px; font-weight: 750;")

        intro = QLabel(
            "Prepare your organization before an attack. Liquidsky Security Network provides "
            "professional ransomware-readiness, security consulting, simulation, and incident-response guidance."
        )
        intro.setWordWrap(True)
        intro.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByKeyboard | Qt.TextInteractionFlag.TextSelectableByMouse)
        intro.setStyleSheet("font-size: 15px;")

        image_path = get_asset_path("antiransom.png")
        if not image_path.exists():
            image_path = Path(__file__).resolve().parents[2] / "antiransom.png"
        self.consulting_image = ConsultingBannerImage(image_path)
        self.consulting_image.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.consulting_image.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(CONSULTING_URL)))

        self.consulting_banner = QFrame()
        self.consulting_banner.setObjectName("antiRansomwareConsultingBanner")
        self.consulting_banner.setAccessibleName(CONSULTING_BANNER_TEXT)
        self.consulting_banner.setStyleSheet(
            "QFrame#antiRansomwareConsultingBanner {"
            "background-color: #0b1f33; border: 1px solid #2677a8; border-radius: 10px;"
            "}"
            "QLabel { color: #f4f8fb; background: transparent; }"
        )
        banner_layout = QVBoxLayout(self.consulting_banner)
        banner_layout.setContentsMargins(18, 16, 18, 16)
        banner_layout.setSpacing(8)
        banner_heading = QLabel("LIQUIDSKY SECURITY NETWORK")
        banner_heading.setStyleSheet("font-size: 14px; font-weight: 800; letter-spacing: 1px; color: #60c7ff;")
        self.consulting_message = QLabel(CONSULTING_BANNER_TEXT)
        self.consulting_message.setObjectName("antiRansomwareConsultingNotice")
        self.consulting_message.setAccessibleName(CONSULTING_BANNER_TEXT)
        self.consulting_message.setWordWrap(True)
        self.consulting_message.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByKeyboard | Qt.TextInteractionFlag.TextSelectableByMouse)
        self.consulting_message.setStyleSheet("font-size: 16px; font-weight: 650;")
        website = QLabel(f'<a style="color:#60c7ff;" href="{CONSULTING_URL}">Visit liquidskysecurity.com</a>')
        website.setOpenExternalLinks(True)
        website.setAccessibleName("Visit Liquidsky Security Network website")
        phone = QLabel('<a style="color:#ffffff;" href="tel:+14699213983">Call 469-921-3983</a>')
        phone.setOpenExternalLinks(True)
        phone.setAccessibleName("Call Liquidsky Security Network at 469-921-3983")
        phone.setStyleSheet("font-size: 18px; font-weight: 800;")
        banner_layout.addWidget(banner_heading)
        banner_layout.addWidget(self.consulting_message)
        banner_layout.addWidget(phone)
        banner_layout.addWidget(website)

        disclaimer = QLabel(
            "Awareness and consulting information only. If an attack is active, isolate affected systems, "
            "preserve evidence, and contact qualified incident-response personnel."
        )
        disclaimer.setWordWrap(True)
        disclaimer.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByKeyboard | Qt.TextInteractionFlag.TextSelectableByMouse)
        disclaimer.setProperty("textRole", "muted")
        disclaimer.setStyleSheet("font-size: 12px;")

        self.action_buttons: list[QPushButton] = []
        layout.addWidget(title)
        layout.addWidget(intro)
        layout.addWidget(self.consulting_banner)
        layout.addWidget(self.consulting_image)
        layout.addWidget(disclaimer)
        layout.addStretch(1)
        self.tabs.addTab(overview, "Awareness & Consulting")
        self._build_guidance_tabs()
        if hasattr(self, "protection_status_tab"):
            self.tabs.setCurrentWidget(self.protection_status_tab)

    def _build_guidance_tabs(self) -> None:
        self.guidance_engine = GuidanceEngine()
        self.guidance_audit = GuidanceAuditLog()
        bundle = self.guidance_engine.bundle

        events = QWidget(); events_layout = QVBoxLayout(events)
        events_note = QLabel("Detection events are enriched locally with why-it-matters context, ATT&CK techniques, official guidance, and immediate response actions. No agency is contacted.")
        events_note.setWordWrap(True); events_layout.addWidget(events_note)
        sample = self.guidance_engine.resolve({"detection_type": "encryption_burst", "severity": "critical", "confidence": "high"})
        self.detection_guidance = QTextBrowser()
        self.detection_guidance.setPlainText(json.dumps(sample.to_dict(), indent=2, default=str))
        events_layout.addWidget(self.detection_guidance)
        self.tabs.addTab(events, "Detection Events")

        threats = QWidget(); threats_layout = QVBoxLayout(threats)
        threats_note = QLabel("Current protection readiness and active-mode evidence. A degraded observation state must not be interpreted as full ransomware prevention.")
        threats_note.setWordWrap(True); threats_layout.addWidget(threats_note)
        threats_status = QTextBrowser(); threats_status.setPlainText(json.dumps(source_health().to_dict(), indent=2, default=str)); threats_layout.addWidget(threats_status)
        self.tabs.addTab(threats, "Active Threats")

        install = QWidget(); install_layout = QVBoxLayout(install)
        self.protection_status_tab = install
        install_title = QLabel("Anti-Ransomware Sensor & Repair"); install_title.setStyleSheet("font-size: 20px; font-weight: 700;"); install_layout.addWidget(install_title)
        install_note = QLabel("MSAA verifies the installed sensor, signature, Endpoint Security entitlement, Full Disk Access, LaunchDaemon, heartbeat, and live events. Repair follows the live blocker and never labels fallback observation as full protection.")
        install_note.setWordWrap(True); install_layout.addWidget(install_note)
        self.badge = QLabel(); self.badge.setAccessibleName("Anti-Ransomware sensor installation state"); self.badge.setWordWrap(True); install_layout.addWidget(self.badge)
        status_header = ResponsiveActionRow()
        self.repair_sensor_button = QPushButton("Repair Anti-Ransomware")
        self.repair_sensor_button.setObjectName("repairAntiRansomwareButton")
        self.repair_sensor_button.setAccessibleName("Repair Anti-Ransomware protection")
        self.repair_sensor_button.setToolTip("Diagnose the live sensor state and perform the supported repair or open the exact macOS approval needed.")
        self.repair_sensor_button.setStyleSheet("padding: 7px 14px; font-weight: 700;")
        self.repair_sensor_button.clicked.connect(self.repair_anti_ransomware)
        status_header.add_button(self.repair_sensor_button)
        self.simulation_button = QPushButton("Run Harmless Detection Test")
        self.simulation_button.setObjectName("runHarmlessRansomwareSimulationButton")
        self.simulation_button.setAccessibleName("Run harmless ransomware detection simulation")
        self.simulation_button.setToolTip(
            "Create only disposable marked fixture files, verify monitored activity, and confirm the behavioral engine catches the expected signals."
        )
        self.simulation_button.clicked.connect(self.run_safe_validation)
        status_header.add_button(self.simulation_button)
        install_layout.addWidget(status_header)
        self.status = QTextBrowser(); self.status.setAccessibleName("Anti-Ransomware installation instructions and status"); install_layout.addWidget(self.status, 1)
        install_actions = ResponsiveActionRow()
        plan_button = QPushButton("1. Review Install Plan"); plan_button.setToolTip("Show components, privileges, limitations, and the reviewed command without changing the Mac."); plan_button.clicked.connect(self.view_install_plan); install_actions.add_button(plan_button)
        self.install_protection_button = QPushButton("2. Open Terminal for Administrator Install"); self.install_protection_button.setToolTip("Open Terminal with one fixed, visible sudo command. macOS asks for the password; MSAA never sees or stores it."); self.install_protection_button.clicked.connect(self.install_protection); install_actions.add_button(self.install_protection_button)
        verify_button = QPushButton("3. Verify Sensor Installation"); verify_button.setToolTip("Read the LaunchDaemon, heartbeat, observer, YARA, and production Endpoint Security states without changing settings."); verify_button.clicked.connect(self.verify_development_sensor); install_actions.add_button(verify_button)
        copy_button = QPushButton("Copy Exact Install Command"); copy_button.setToolTip("Copy the same fixed command for manual use if Terminal automation is unavailable. No password or secret is copied."); copy_button.clicked.connect(self.copy_development_install_command); install_actions.add_button(copy_button)
        fda_button = QPushButton("Open Full Disk Access"); fda_button.setToolTip("Open macOS settings. MSAA cannot grant TCC permissions automatically."); fda_button.clicked.connect(self.open_full_disk_access_settings); install_actions.add_button(fda_button)
        install_layout.addWidget(install_actions)
        limitations = QLabel("Production sensor: requires a signed artifact, Apple Endpoint Security entitlement, privacy approval, and a verified live ES connection. Installing the development observer does not satisfy those gates.")
        limitations.setWordWrap(True); install_layout.addWidget(limitations)
        self.tabs.addTab(install, "Protection Status & Repair")
        self._refresh()
        self._build_simulation_lab_tab()

        recovery = QWidget(); recovery_layout = QVBoxLayout(recovery)
        recovery_guidance = self.guidance_engine.resolve({"detection_type": "recovery_tamper", "severity": "critical"})
        recovery_text = QTextBrowser()
        recovery_text.setPlainText(json.dumps({
            "why_it_matters": recovery_guidance.why_it_matters,
            "recommended_actions": recovery_guidance.recommended_actions,
            "recovery_readiness": analyze_recovery_readiness(),
            "government_guidance": recovery_guidance.government_guidance,
        }, indent=2, default=str))
        recovery_layout.addWidget(recovery_text)
        self.tabs.addTab(recovery, "Recovery Guidance")

        resources = QWidget(); resources_layout = QVBoxLayout(resources)
        resource_note = QLabel(f"Offline trusted resource cache version {bundle.versions.get('government_references.json', 'unknown')}. Integrity-verified with SHA-256. Links open only after user action.")
        resource_note.setWordWrap(True); resources_layout.addWidget(resource_note)
        resource_table = QTableWidget(len(bundle.references), 5)
        resource_table.setHorizontalHeaderLabels(["Organization", "Resource", "Purpose", "Frameworks", "Open Resource"])
        for row, reference in enumerate(bundle.references):
            resource_table.setItem(row, 0, QTableWidgetItem(str(reference.get("organization", ""))))
            safe_url=html.escape(str(reference.get("url", "")),quote=True); safe_name=html.escape(str(reference.get("source_name", ""))); resource_link=QLabel(f'<a href="{safe_url}">{safe_name}</a>'); resource_link.setTextFormat(Qt.TextFormat.RichText); resource_link.setTextInteractionFlags(Qt.TextInteractionFlag.LinksAccessibleByMouse|Qt.TextInteractionFlag.LinksAccessibleByKeyboard); resource_link.setOpenExternalLinks(False); resource_link.setAccessibleName(f"Open {reference.get('source_name', '')} in a new browser window"); resource_link.linkActivated.connect(lambda _url,ref=dict(reference): self._open_government_resource(ref)); resource_table.setCellWidget(row,1,resource_link)
            resource_table.setItem(row, 2, QTableWidgetItem(str(reference.get("description", ""))))
            resource_table.setItem(row, 3, QTableWidgetItem(", ".join(reference.get("frameworks", ()))))
            button = QPushButton("Open Official Resource")
            button.setAccessibleName(f"Open {reference.get('source_name', '')} from {reference.get('organization', '')}")
            button.clicked.connect(lambda _checked=False, ref=dict(reference): self._open_government_resource(ref))
            resource_table.setCellWidget(row, 4, button)
        resource_table.resizeColumnsToContents()
        resources_layout.addWidget(resource_table)
        self.tabs.addTab(resources, "Government Resources")

        update_policy = QWidget(); update_layout = QVBoxLayout(update_policy)
        update_title = QLabel("Ransomware Advisory and Detection Update Policy")
        update_title.setStyleSheet("font-size: 20px; font-weight: 700;")
        update_note = QLabel("MSAA separates advisories, vulnerability intelligence, and executable detections. Only explicitly identified rules from an allowlisted source may enter the test channel; compilation and named human approval are required before activation. The privileged sensor makes no unrestricted feed requests.")
        update_note.setWordWrap(True)
        update_status = QTextBrowser(); update_status.setPlainText(json.dumps(advisory_source_status(), indent=2))
        update_layout.addWidget(update_title); update_layout.addWidget(update_note); update_layout.addWidget(update_status, 1)
        self.tabs.addTab(update_policy, "Advisory Update Policy")

        mitre = QWidget(); mitre_layout = QVBoxLayout(mitre)
        rows = [(behavior, item) for behavior, mappings in bundle.mitre_mappings.items() for item in mappings]
        mitre_table = QTableWidget(len(rows), 5)
        mitre_table.setHorizontalHeaderLabels(["Detection Behavior", "Technique ID", "Technique", "Tactic", "Official Reference"])
        for row, (behavior, mapping) in enumerate(rows):
            for column, value in enumerate((behavior, mapping.get("technique_id", ""), mapping.get("technique", ""), mapping.get("tactic", ""), mapping.get("url", ""))):
                mitre_table.setItem(row, column, QTableWidgetItem(str(value)))
        mitre_table.resizeColumnsToContents(); mitre_layout.addWidget(mitre_table)
        self.tabs.addTab(mitre, "MITRE ATT&CK Mapping")

        reporting = QWidget(); reporting_layout = QVBoxLayout(reporting)
        reporting_layout.setSpacing(12)
        reporting_note = QLabel("MSAA does not transmit or submit incident information. Preserve evidence, follow organizational notification procedures, and obtain required authorization before submitting information through an official federal channel.")
        reporting_note.setWordWrap(True); reporting_layout.addWidget(reporting_note)
        reporting_references = incident_reporting_references(bundle.references)
        primary = next((reference for reference in reporting_references if reference.get("reference_id") == IC3_RANSOMWARE_REFERENCE_ID), None)
        if primary:
            emergency = QFrame()
            emergency.setObjectName("ic3EmergencyReportingFrame")
            emergency.setAccessibleName("Primary federal reporting channel for an active ransomware incident")
            emergency.setStyleSheet(
                "QFrame#ic3EmergencyReportingFrame { background-color: #fff1f1; border: 2px solid #b42318; border-radius: 8px; }"
                "QLabel { background: transparent; color: #5f1712; }"
            )
            emergency_layout = QVBoxLayout(emergency)
            emergency_heading = QLabel("ACTIVE RANSOMWARE INCIDENT — PRIMARY FEDERAL REPORTING CHANNEL")
            emergency_heading.setStyleSheet("font-size: 16px; font-weight: 800;")
            emergency_detail = QLabel(
                "FBI Internet Crime Complaint Center (IC3) — Official Ransomware Reporting\n"
                "Use this prioritized federal resource when ransomware activity is currently affecting systems. "
                "Preserve available evidence and comply with your organization's incident-notification and approval requirements."
            )
            emergency_detail.setWordWrap(True)
            emergency_button = QPushButton("Open FBI IC3 Active-Incident Reporting")
            emergency_button.setObjectName("ic3EmergencyReportingButton")
            emergency_button.setAccessibleName("Open the FBI IC3 ransomware reporting resource for an active incident")
            emergency_button.setToolTip("Open the official FBI IC3 ransomware reporting resource in a new browser window.")
            emergency_button.setStyleSheet(
                "QPushButton#ic3EmergencyReportingButton { background-color: #b42318; color: white; border: 1px solid #8f1c13; "
                "border-radius: 6px; padding: 10px 16px; font-weight: 800; }"
                "QPushButton#ic3EmergencyReportingButton:hover { background-color: #912018; }"
                "QPushButton#ic3EmergencyReportingButton:pressed { background-color: #70170f; }"
            )
            emergency_button.clicked.connect(lambda _checked=False, ref=dict(primary): self._open_government_resource(ref))
            emergency_layout.addWidget(emergency_heading)
            emergency_layout.addWidget(emergency_detail)
            emergency_layout.addWidget(emergency_button)
            reporting_layout.addWidget(emergency)

        supplemental_heading = QLabel("SUPPLEMENTAL FEDERAL REFERENCE RESOURCES")
        supplemental_heading.setProperty("textRole", "sectionTitle")
        supplemental_note = QLabel("Retain these FBI resources for supporting guidance and law-enforcement coordination. They are secondary references and do not replace the prioritized IC3 reporting channel above during an active ransomware incident.")
        supplemental_note.setWordWrap(True)
        reporting_layout.addWidget(supplemental_heading)
        reporting_layout.addWidget(supplemental_note)
        for reference in reporting_references:
            if reference.get("reference_id") == IC3_RANSOMWARE_REFERENCE_ID:
                continue
            row = QHBoxLayout(); label = QLabel(f"Secondary Reference — {reference.get('organization')}: {reference.get('source_name')}\n{reference.get('description')}"); label.setWordWrap(True)
            button = QPushButton("Open Supplemental FBI Resource"); button.clicked.connect(lambda _checked=False, ref=dict(reference): self._open_government_resource(ref))
            row.addWidget(label, 1); row.addWidget(button); reporting_layout.addLayout(row)
        reporting_layout.addStretch(1)
        self.tabs.addTab(reporting, "Incident Reporting")

    def _build_simulation_lab_tab(self) -> None:
        lab = QWidget()
        layout = QVBoxLayout(lab)
        layout.setContentsMargins(16, 14, 16, 16)
        layout.setSpacing(10)
        heading = QLabel("Safe Ransomware Definition Simulations")
        heading.setStyleSheet("font-size: 20px; font-weight: 700;")
        explanation = QLabel(
            "Twenty-four attack-shaped scenarios and four benign negative controls exercise MSAA's built-in behavioral definitions in memory. "
            "They do not encrypt, rename, delete, or open user files; execute commands; contact the network; "
            "change backups; alter security controls; or invoke containment. A pass proves rule evaluation only, not live sensor delivery."
        )
        explanation.setWordWrap(True)
        layout.addWidget(heading)
        layout.addWidget(explanation)

        catalog = catalog_metadata()
        self.simulation_catalog_table = QTableWidget(len(catalog), 7)
        self.simulation_catalog_table.setObjectName("ransomwareSimulationCatalog")
        self.simulation_catalog_table.setAccessibleName("Safe ransomware definition simulation catalog")
        self.simulation_catalog_table.setHorizontalHeaderLabels(
            ["ID", "Category", "Simulation", "Behavior", "Definition Signals", "Expected Outcome", "Last Result"]
        )
        self.simulation_catalog_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.simulation_catalog_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.simulation_catalog_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.simulation_catalog_table.setAlternatingRowColors(True)
        self.simulation_catalog_table.verticalHeader().setVisible(False)
        for row, item in enumerate(catalog):
            values = (
                item["simulation_id"], str(item["category"]).replace("_", " ").title(),
                item["title"], item["behavior"],
                ", ".join(item["required_signal_ids"]),
                (
                    f"<= {item['expected_maximum_score']} · no escalation"
                    if item["expected_outcome"] == "NOT_ESCALATED"
                    else f">= {item['expected_minimum_score']} · caught"
                ),
                "Not run",
            )
            for column, value in enumerate(values):
                cell = QTableWidgetItem(str(value))
                if column == 0:
                    cell.setData(Qt.ItemDataRole.UserRole, item["simulation_id"])
                self.simulation_catalog_table.setItem(row, column, cell)
        header = self.simulation_catalog_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.simulation_catalog_table.setMinimumHeight(310)
        layout.addWidget(self.simulation_catalog_table, 1)

        actions = ResponsiveActionRow()
        self.run_selected_simulation_button = QPushButton("Run Selected Safe Simulation")
        self.run_selected_simulation_button.setObjectName("runSelectedRansomwareSimulationButton")
        self.run_selected_simulation_button.setToolTip("Evaluate the selected scenario against its built-in rule definitions without touching the host.")
        self.run_all_simulations_button = QPushButton(f"Run All {len(catalog)} Safe Simulations")
        self.run_all_simulations_button.setObjectName("runRansomwareSimulationSuiteButton")
        self.run_all_simulations_button.setAccessibleName("Run all safe ransomware definition simulations")
        self.run_all_simulations_button.setToolTip("Evaluate all scenarios in memory and show exact rule signals, scores, and results.")
        self.export_simulations_button = QPushButton("Export Simulation Evidence")
        self.export_simulations_button.setObjectName("exportRansomwareSimulationReportButton")
        self.export_simulations_button.setToolTip("Export the latest non-sensitive JSON rule-validation report.")
        self.export_simulations_button.setEnabled(False)
        self.run_yara_validation_button = QPushButton("Run 20 Safe YARA Tests")
        self.run_yara_validation_button.setObjectName("runRansomwareYaraValidationSuiteButton")
        self.run_yara_validation_button.setToolTip(
            "Compile harmless test rules and exercise expected matches, negative controls, namespaces, and rejection gates entirely in memory."
        )
        self.run_adaptive_detector_button = QPushButton("Run Adaptive Unsigned Demo")
        self.run_adaptive_detector_button.setObjectName("runAdaptiveUnsignedRansomwareDemoButton")
        self.run_adaptive_detector_button.setToolTip(
            "Exercise MSAA's process-tree, baseline, trust-context, coverage, and multi-file correlation without touching files."
        )
        self.run_adaptive_action_suite_button = QPushButton("Run 20 Adaptive Action Tests")
        self.run_adaptive_action_suite_button.setObjectName("runAdaptiveRansomwareActionSuiteButton")
        self.run_adaptive_action_suite_button.setToolTip(
            "Run 20 metadata-only ransomware action tests covering entropy, rename, deletion, spread, trust, baseline, replay, and degraded coverage."
        )
        for button in (
            self.run_selected_simulation_button,
            self.run_all_simulations_button,
            self.run_adaptive_detector_button,
            self.run_adaptive_action_suite_button,
            self.run_yara_validation_button,
            self.export_simulations_button,
        ):
            actions.add_button(button)
        layout.addWidget(actions)
        self.simulation_suite_status = QTextBrowser()
        self.simulation_suite_status.setAccessibleName("Ransomware simulation suite results")
        self.simulation_suite_status.setPlainText("No definition simulation has been run.")
        self.simulation_suite_status.setMinimumHeight(150)
        layout.addWidget(self.simulation_suite_status)
        self.run_selected_simulation_button.clicked.connect(self._run_selected_simulation)
        self.run_all_simulations_button.clicked.connect(self._run_all_simulations)
        self.run_yara_validation_button.clicked.connect(self._run_yara_validations)
        self.run_adaptive_detector_button.clicked.connect(self._run_adaptive_detector_demo)
        self.run_adaptive_action_suite_button.clicked.connect(self._run_adaptive_action_suite)
        self.export_simulations_button.clicked.connect(self._export_simulation_suite)
        self._simulation_suite_report: dict | None = None
        self.tabs.addTab(lab, "Simulation Lab")

    def _simulation_confirmation(self, count: int) -> bool:
        message = (
            f"MSAA will evaluate {count} deterministic ransomware scenario{'s' if count != 1 else ''} entirely in memory. "
            "No ransomware sample, destructive command, user file, backup, network connection, security setting, or containment action is used.\n\n"
            "Continue with safe rule validation?"
        )
        return QMessageBox.question(
            self, "Run Safe Ransomware Simulations", message,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        ) == QMessageBox.StandardButton.Yes

    def _run_selected_simulation(self) -> None:
        row = self.simulation_catalog_table.currentRow()
        if row < 0 or self.simulation_catalog_table.item(row, 0) is None:
            QMessageBox.information(self, "Select a Simulation", "Select one simulation row first.")
            return
        simulation_id = str(self.simulation_catalog_table.item(row, 0).data(Qt.ItemDataRole.UserRole))
        if self._simulation_confirmation(1):
            self._run_simulations({simulation_id})

    def _run_all_simulations(self) -> None:
        if self._simulation_confirmation(len(catalog_metadata())):
            self._run_simulations(None)

    def _run_yara_validations(self) -> None:
        message = (
            "MSAA will run 20 harmless YARA tests entirely in memory: expected matches, negative controls, malformed-rule rejection, "
            "namespace collision isolation, include rejection, and unsupported-module rejection. No user file or malware sample is used. Continue?"
        )
        if QMessageBox.question(
            self, "Run Safe YARA Validation", message,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        ) != QMessageBox.StandardButton.Yes:
            return
        report = run_yara_validation_suite()
        self.simulation_suite_status.setPlainText(json.dumps(report, indent=2))
        self._simulation_suite_report = report
        self.export_simulations_button.setEnabled(True)
        if report["all_passed"]:
            QMessageBox.information(
                self, "YARA Validation Passed",
                f"{report['passed_count']} of {report['case_count']} safe YARA tests passed. "
                "Use Malware Definitions → Verify Active Release for the installed external rules.",
            )
        else:
            QMessageBox.warning(
                self, "YARA Validation Gap",
                f"{report['failed_count']} of {report['case_count']} safe YARA tests failed. Review the displayed case evidence.",
            )

    def _run_adaptive_detector_demo(self) -> None:
        message = (
            "MSAA will evaluate six deterministic metadata-only cases for its adaptive, signature-independent detector. "
            "The cases include unsigned-only, entropy-wave, correlated attack, signed-process, degraded-sensor, and baseline-deviation behavior. "
            "No file, process, command, network connection, or containment action is used. Continue?"
        )
        if QMessageBox.question(
            self, "Run Adaptive Ransomware Demo", message,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        ) != QMessageBox.StandardButton.Yes:
            return
        report = run_adaptive_detector_demo()
        self.simulation_suite_status.setPlainText(json.dumps(report, indent=2))
        self._simulation_suite_report = report
        self.export_simulations_button.setEnabled(True)
        if report["all_passed"]:
            QMessageBox.information(
                self, "Adaptive Ransomware Demo Passed",
                f"{report['passed_count']} of {report['scenario_count']} adaptive cases passed. "
                "Run the harmless live observer test separately to prove sensor delivery.",
            )
        else:
            QMessageBox.warning(
                self, "Adaptive Ransomware Demo Gap",
                f"{report['failed_count']} adaptive case(s) failed. Review the displayed reason codes and coverage state.",
            )

    def _run_adaptive_action_suite(self) -> None:
        message = (
            "MSAA will run 20 deterministic metadata-only ransomware action tests. No files are created, encrypted, renamed, "
            "or deleted; no commands or processes run; and containment is never performed. Continue?"
        )
        if QMessageBox.question(
            self, "Run 20 Adaptive Action Tests", message,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        ) != QMessageBox.StandardButton.Yes:
            return
        report = run_adaptive_action_suite()
        self.simulation_suite_status.setPlainText(json.dumps(report, indent=2))
        self._simulation_suite_report = report
        self.export_simulations_button.setEnabled(True)
        if report["all_passed"]:
            QMessageBox.information(
                self, "Adaptive Action Tests Passed",
                f"{report['passed_count']} of {report['case_count']} ransomware action tests passed. "
                "Use Run Harmless Detection Test separately to validate live sensor observation.",
            )
        else:
            QMessageBox.warning(
                self, "Adaptive Action Test Gap",
                f"{report['failed_count']} of {report['case_count']} action tests failed. Review the displayed reason codes.",
            )

    def _run_simulations(self, selected_ids: set[str] | None) -> None:
        try:
            report = run_simulation_suite(selected_ids)
        except ValueError as exc:
            QMessageBox.warning(self, "Simulation Definition Error", str(exc))
            return
        self._simulation_suite_report = report
        by_id = {str(item["simulation_id"]): item for item in report["results"]}
        for row in range(self.simulation_catalog_table.rowCount()):
            simulation_id = str(self.simulation_catalog_table.item(row, 0).data(Qt.ItemDataRole.UserRole))
            result = by_id.get(simulation_id)
            if result:
                self.simulation_catalog_table.setItem(
                    row, 6, QTableWidgetItem(
                        f"{result['result']} · {result['actual_score']}/100 · {str(result['threat_state']).replace('_', ' ')}"
                    ),
                )
        summary = {
            "operation": report["operation"],
            "ruleset_version": report["ruleset_version"],
            "scenario_count": report["scenario_count"],
            "attack_scenarios": report["attack_scenario_count"],
            "negative_controls": report["negative_control_count"],
            "caught": report["caught_count"],
            "missed": report["missed_count"],
            "controls_passed": report["control_passed_count"],
            "unexpected_escalations": report["unexpected_escalation_count"],
            "all_passed": report["all_passed"],
            "safety": report["safety"],
            "qualification": report["qualification"],
            "results": [
                {
                    "id": item["simulation_id"], "title": item["title"], "result": item["result"],
                    "score": item["actual_score"], "risk_state": item["risk_state"],
                    "signals": [signal["signal_id"] for signal in item["observed_signals"]],
                }
                for item in report["results"]
            ],
        }
        self.simulation_suite_status.setPlainText(json.dumps(summary, indent=2))
        self.export_simulations_button.setEnabled(True)
        title = "Ransomware Definition Simulations Passed" if report["all_passed"] else "Ransomware Definition Simulation Gap"
        message = (
            f"{report['caught_count']} of {report['attack_scenario_count']} attack scenarios were caught and "
            f"{report['control_passed_count']} of {report['negative_control_count']} benign controls avoided escalation. "
            "This validates in-memory rule evaluation only; review Sensor Health separately for live coverage."
        )
        if report["all_passed"]:
            QMessageBox.information(self, title, message)
        else:
            QMessageBox.warning(self, title, message)

    def _export_simulation_suite(self) -> None:
        if self._simulation_suite_report is None:
            return
        destination, _ = QFileDialog.getSaveFileName(
            self, "Export Ransomware Simulation Evidence", "MSAA-ransomware-simulation-suite.json", "JSON (*.json)"
        )
        if not destination:
            return
        try:
            path = export_simulation_report(self._simulation_suite_report, Path(destination))
            QMessageBox.information(self, "Simulation Evidence Exported", str(path))
        except (OSError, ValueError) as exc:
            QMessageBox.warning(self, "Simulation Export Failed", str(exc))

    def _open_government_resource(self, reference: dict[str, object]) -> None:
        url = str(reference.get("url") or "")
        self.guidance_audit.record_view(
            finding_id="", resource_viewed=str(reference.get("reference_id") or url),
            severity=str(reference.get("priority") or "informational"),
            response_actions_displayed=[],
        )
        if not open_government_url_in_new_window(url):
            QMessageBox.warning(self,"Government Resource Could Not Be Opened","The resource must be a trusted HTTPS .gov address and macOS must provide /usr/bin/open. No page was opened.")

    def _refresh(self) -> None:
        health=source_health()
        protection = resolve_active_protection_status()
        self.badge.setText(health.status_badge)
        self.badge.setStyleSheet(
            "padding: 7px 10px; border-radius: 6px; font-weight: 750; color: #067647; background: #ecfdf3; border: 1px solid #abefc6;"
            if health.endpoint_security_observe_ready
            else "padding: 7px 10px; border-radius: 6px; font-weight: 750; color: #93370d; background: #fffaeb; border: 1px solid #fedf89;"
        )
        self.status.setPlainText(json.dumps({"anti_ransomware": health.to_dict(), "persistent_active_protection": protection.to_dict()}, indent=2, default=str))
        self.install_protection_button.setVisible(not health.endpoint_security_observe_ready)
        observer = health.sensor_details.get("development_observer", {})
        self.install_protection_button.setText("Open Terminal for Administrator Install" if not observer.get("running") else "Open Terminal to Repair Sensor")

    def _show_repair_plan(self) -> None:
        self.status.setPlainText(json.dumps(repair_plan(), indent=2, default=str))

    def repair_anti_ransomware(self) -> None:
        """Repair the live Endpoint Security layer without masking unsupported gates."""
        health = source_health()
        if health.endpoint_security_observe_ready:
            self._refresh()
            self._refresh_parent_health()
            QMessageBox.information(
                self,
                "Anti-Ransomware Ready",
                "The signed Endpoint Security sensor is running, Full Disk Access is present, and a live event was verified. "
                "No sensor repair is required. Production containment remains a separately reported capability.",
            )
            return

        if health.sensor_installed and (
            health.endpoint_security_client_result is ESClientResult.NOT_PERMITTED
            or not health.full_disk_access_present
        ):
            try:
                subprocess.Popen(
                    ["/usr/bin/open", "-R", str(EXPECTED_SENSOR_PATH.parents[2])],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
            except OSError:
                pass
            self.open_full_disk_access_settings()
            QMessageBox.information(
                self,
                "Full Disk Access Required",
                "macOS opened the exact installed sensor and the Full Disk Access pane. Add or enable "
                "MSAAEndpointSecuritySensor.app, then select Repair Anti-Ransomware again. MSAA cannot grant TCC permission itself.",
            )
            return

        explanation = (
            "MSAA will open Terminal with one fixed repair command. The command verifies the signed bundle, Team ID, "
            "bundle ID, provisioning profile, and Endpoint Security entitlement before backing up and reinstalling the sensor.\n\n"
            "macOS sudo requests administrator approval in Terminal; MSAA never receives or stores the password. Continue?"
        )
        if QMessageBox.question(self, "Repair Anti-Ransomware", explanation) != QMessageBox.StandardButton.Yes:
            self._show_repair_plan()
            return
        try:
            launch = open_endpoint_security_sensor_repair_in_terminal()
        except DevelopmentSensorLaunchError as exc:
            try:
                QApplication.clipboard().setText(endpoint_security_sensor_repair_command())
                copied = True
            except DevelopmentSensorLaunchError:
                copied = False
            self.status.setPlainText(json.dumps({
                "operation": "endpoint_security_sensor_repair",
                "status": "terminal_unavailable",
                "command_copied": copied,
                "error": str(exc),
                "repair_plan": repair_plan(health),
            }, indent=2, default=str))
            QMessageBox.warning(
                self,
                "Sensor Repair Could Not Start",
                f"{exc}\n\n" + ("The exact repair command was copied." if copied else "Review the displayed repair plan."),
            )
            return
        self.status.setPlainText(json.dumps({
            "operation": "endpoint_security_sensor_repair",
            "terminal_opened": launch.launched,
            "event_id": launch.event_id,
            "password_collected_by_msaa": False,
            "next_steps": [
                "Review the fixed command in Terminal.",
                "Approve sudo only in Terminal.",
                "Wait for signature and launch verification to finish.",
                "Select Repair Anti-Ransomware again to recheck live evidence.",
            ],
        }, indent=2))
        QMessageBox.information(self, "Repair Started", launch.message)

    def refresh_protection_status(self) -> None:
        self._refresh()

    def install_protection(self) -> None:
        """Confirm and invoke the canonical headless Active Protection installer."""
        current = resolve_active_protection_status()
        if current.status == "installed_running":
            self.status.setPlainText(json.dumps({"message": "Active Protection is already installed and running.", "actions_available": ["Verify Active Protection", "Repair Active Protection"], "status": current.to_dict()}, indent=2, default=str))
            return
        if current.status != "not_installed":
            self.repair_protection()
            return
        explanation = ("This opens Terminal with a fixed command that installs the entitlement-free ransomware observer inside the existing System Monitor LaunchDaemon, plus its local notifier, database, manifests, and boot-persistent service.\n\nELEVATED-PERMISSION WARNING\nThe command uses sudo to write root-owned files under /Library, register a LaunchDaemon, and start it at boot. A compromised or unreviewed privileged installer could control the Mac. Review the visible command and continue only on a Mac you are authorized to administer.\n\nMSAA itself does not run the Qt interface as root, does not collect the password, and cannot grant Full Disk Access or an Apple Endpoint Security entitlement.\n\nOpen Terminal now?")
        if QMessageBox.question(self, "Install Active Protection", explanation) != QMessageBox.StandardButton.Yes:
            return
        try:
            launch = open_development_sensor_install_in_terminal()
        except DevelopmentSensorLaunchError as exc:
            self.copy_development_install_command()
            QMessageBox.warning(self, "Terminal Installation Unavailable", f"{exc}\n\nThe exact command was copied. Paste it into Terminal, review it, and enter the password only at the macOS sudo prompt.")
            return
        self.status.setPlainText(json.dumps({"operation": "development_sensor_install", "terminal_opened": launch.launched, "event_id": launch.event_id, "password_collected_by_msaa": False, "next_steps": ["Review the command in Terminal.", "Enter the administrator password only in the sudo prompt.", "Wait for the installer verification result.", "Return to MSAA and select Verify Sensor Installation."], "production_endpoint_security_installed": False}, indent=2))
        QMessageBox.information(self, "Terminal Opened", launch.message + "\n\nReturn here and select Verify Sensor Installation after the command finishes.")

    def copy_development_install_command(self) -> None:
        try:
            command = repository_install_command()
        except DevelopmentSensorLaunchError:
            command = DEVELOPMENT_INSTALL_COMMAND
        QApplication.clipboard().setText(command)
        self.status.setPlainText(json.dumps(development_sensor_install_guide(resolve_active_protection_status().to_dict()), indent=2, default=str))

    def verify_development_sensor(self) -> None:
        protection = resolve_active_protection_status(); health = source_health(); observer = health.sensor_details.get("development_observer", {})
        self.status.setPlainText(json.dumps({"verification": "development_ransomware_sensor", "system_monitor": protection.system_daemon, "development_observer": observer, "development_sensor_installed_and_running": bool(protection.system_daemon.get("running")) and bool(observer.get("running")), "production_endpoint_security": {"installed": health.sensor_installed, "connected": health.endpoint_security_connected, "full_active_protection": health.full_active_protection}, "truthful_result": "Endpoint Security observe-ready" if health.endpoint_security_observe_ready else "development observer active" if observer.get("running") else "development observer not verified", "limitations": list(health.limitations)}, indent=2, default=str))
        self._refresh_parent_health()

    def view_install_plan(self) -> None:
        """Render the canonical, non-mutating installation inventory."""
        current = resolve_active_protection_status()
        self.status.setPlainText(json.dumps({
            "operation": "active_protection_install_plan",
            "changes_applied": False,
            "administrator_approval_required": True,
            "local_first": True,
            "components": [item.to_dict() for item in active_protection_components()],
            "development_sensor_guide": development_sensor_install_guide(current.to_dict()),
            "current_status": current.to_dict(),
            "message": "Review only. The development observer is installed inside the existing System Monitor by the headless bootstrap after explicit administrator authorization.",
        }, indent=2, default=str))

    def repair_protection(self) -> None:
        """Open the canonical root service repair without elevating the GUI."""
        explanation = (
            "MSAA will open Terminal with one fixed repair command. The administrator-approved repair backs up and "
            "repairs daemon/notifier registrations, refreshes the installed runtime, preserves security events, and "
            "verifies service health.\n\nThe graphical application remains unprivileged and never receives your password. Continue?"
        )
        if QMessageBox.question(self, "Repair Active Protection", explanation) != QMessageBox.StandardButton.Yes:
            return
        try:
            launch = open_development_sensor_repair_in_terminal()
        except DevelopmentSensorLaunchError as exc:
            copied = False
            try:
                QApplication.clipboard().setText(repository_repair_command())
                copied = True
            except DevelopmentSensorLaunchError:
                pass
            self.status.setPlainText(json.dumps({
                "operation": "active_protection_repair",
                "status": "terminal_unavailable",
                "command_copied": copied,
                "error": str(exc),
                "events_preserved": True,
            }, indent=2))
            QMessageBox.warning(
                self,
                "Repair Could Not Start",
                f"{exc}\n\n" + ("The exact repair command was copied." if copied else "Repair the source environment first."),
            )
            return
        self.status.setPlainText(json.dumps({
            "operation": "active_protection_repair",
            "terminal_opened": launch.launched,
            "event_id": launch.event_id,
            "password_collected_by_msaa": False,
            "events_preserved": True,
            "next_steps": [
                "Review the fixed repair command in Terminal.",
                "Approve sudo only in Terminal.",
                "Wait for runtime alignment and service verification.",
                "Return to MSAA and select Verify Active Protection, then rerun the live fixture suite.",
            ],
        }, indent=2))
        QMessageBox.information(self, "Repair Started", launch.message)

    def verify_protection(self) -> None:
        """Run the read-only canonical protection doctor and refresh the panel."""
        status = resolve_active_protection_status()
        self.status.setPlainText(json.dumps({"operation": "verify", "status": status.to_dict()}, indent=2, default=str))
        self._refresh_parent_health()

    def open_protection_diagnostics(self) -> None:
        """Render sanitized protection diagnostics without importing backend UI code."""
        self.verify_protection()

    def run_readiness_check(self) -> None:
        self.status.setPlainText(json.dumps({"protection": source_health().to_dict(), "recovery": analyze_recovery_readiness()}, indent=2, default=str))

    def start_observation_mode(self) -> None:
        protection = resolve_active_protection_status()
        health = source_health()
        prototype = health.sensor_details.get("development_observer", {})
        self.status.setPlainText(json.dumps({
            "mode": "DEVELOPMENT_OBSERVATION_ONLY",
            "system_daemon_installed": bool(protection.system_daemon.get("installed")),
            "system_daemon_running": bool(protection.system_daemon.get("running")),
            "development_observer": prototype,
            "clickfix_daemon_bridge_status": prototype.get("clickfix_daemon_bridge_status", "unavailable"),
            "active": bool(prototype.get("running")),
            "destructive_actions": False,
            "production_endpoint_security_active": health.endpoint_security_observe_ready,
            "message": (
                "The root-owned system daemon is running delayed metadata-only ransomware observation. "
                "ClickFix remains a logged-in-user LaunchAgent and its verified journal is bridged into daemon events."
                if prototype.get("running") else
                "Install or repair Active Protection to start the root-owned development observer. "
                "Then install the ClickFix development demo in the logged-in user session and grant Input Monitoring."
            ),
            "limitations": list(health.limitations),
        }, indent=2, default=str))

    def configure_protection_policy(self) -> None:
        self.status.setPlainText(json.dumps({"authorized_use": AUTHORIZED_USE_STATEMENT, "default_mode": "confirm_before_containment",
                                             "automatic_file_deletion": False, "stronger_modes_require_confirmation": True}, indent=2))

    def view_detection_rules(self) -> None:
        public = [name for name in dir(ransomware_rules) if name.isupper()]
        self.status.setPlainText(json.dumps({"module": "mac_audit_agent.anti_ransomware.rules", "loaded": True,
                                             "public_rule_sets": public, "method": "multi-signal behavioral correlation"}, indent=2))

    def export_evidence(self) -> None:
        destination = Path.home() / "Library" / "Application Support" / "MacAuditAgent" / "evidence" / "latest_anti_ransomware.json"
        try:
            result = create_evidence_bundle(destination, detection=source_health().to_dict(), redact=True)
            self.status.setPlainText(json.dumps(result, indent=2))
        except OSError as exc:
            self.status.setPlainText(json.dumps({"status": "failed", "reason": str(exc), "content_collected": False}, indent=2))

    def open_incident_timeline(self) -> None:
        self.status.setPlainText(json.dumps({"timeline": [], "message": "No incident records were selected.",
                                             "file_contents_included": False}, indent=2))

    def view_standards_mapping(self) -> None:
        findings = map_readiness(audit_logging=True, recovery_ready=False, containment_policy=False)
        self.status.setPlainText(json.dumps({"findings": [item.to_dict() for item in findings],
                                             "certification_claim": False}, indent=2))

    def open_full_disk_access_settings(self) -> None:
        opened=QDesktopServices.openUrl(QUrl("x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"))
        self.status.setPlainText(json.dumps({"operation":"open_full_disk_access_settings","opened":opened,"permission_changed":False,"message":"Grant access only to the exact signed MSAA component, then refresh status. MSAA did not modify TCC."},indent=2))

    def run_safe_validation(self) -> None:
        explanation = (
            "MSAA will create a dedicated, marked temporary directory under Documents when that folder is monitored, "
            "write and rewrite up to 20 random fixture files, and remove the directory automatically. No existing or "
            "personal file is opened, encrypted, renamed, or deleted. The test does not exercise containment. Continue?"
        )
        if QMessageBox.question(self, "Run Harmless Ransomware Detection Test", explanation) != QMessageBox.StandardButton.Yes:
            return
        from mac_audit_agent.anti_ransomware.simulator import (
            run_safe_detection_validation,
        )
        self.status.setPlainText("Running a bounded harmless detection fixture…")
        QApplication.processEvents()
        try:
            result = run_safe_detection_validation()
            self.status.setPlainText(json.dumps(result, indent=2, default=str))
            if result["status"] == "PASS":
                QMessageBox.information(
                    self,
                    "Ransomware Detection Test Passed",
                    "The development observer captured new fixture activity and the behavioral engine classified the synthetic signals at the expected catch threshold. No user files were touched.",
                )
            else:
                reason = str((result.get("repair_guidance") or {}).get("reason") or "live_fixture_not_observed")
                missing_count = len(result.get("missing_live_stages", []))
                QMessageBox.warning(
                    self,
                    "Ransomware Detection Test Inconclusive",
                    "The behavioral tests completed, but installed protection did not return complete challenge-bound live evidence. "
                    f"Reason: {reason}. Missing live stages: {missing_count}. Review the displayed result, select Repair Anti-Ransomware, then retest.",
                )
        except (OSError, ValueError, PermissionError) as exc:
            self.status.setPlainText(json.dumps({"status": "failed", "error": str(exc)}, indent=2))
            QMessageBox.warning(self, "Ransomware Detection Test Failed", str(exc))

    def deploy_canary_files(self) -> None:
        directory=QFileDialog.getExistingDirectory(self,"Select Approved Canary Directory")
        if not directory:return
        if QMessageBox.question(self,"Deploy Canary Files","MSAA will create two harmless hidden canary files and a local manifest in the selected directory. No personal data is created. Remove them using MSAA. Continue?")!=QMessageBox.StandardButton.Yes:return
        from mac_audit_agent.anti_ransomware.canary import deploy_canaries
        try:self.status.setPlainText(json.dumps({"deployed":deploy_canaries(Path(directory),authorized=True)},indent=2))
        except (OSError,ValueError,PermissionError) as exc:self.status.setPlainText(json.dumps({"status":"failed","error":str(exc)},indent=2))

    def remove_canary_files(self) -> None:
        directory=QFileDialog.getExistingDirectory(self,"Select Canary Directory")
        if not directory:return
        if QMessageBox.question(self,"Remove Canary Files","MSAA will remove only unchanged files recorded in its local canary manifest. Modified canaries remain for investigation. Continue?")!=QMessageBox.StandardButton.Yes:return
        from mac_audit_agent.anti_ransomware.canary import remove_canaries
        try:self.status.setPlainText(json.dumps({"removed":remove_canaries(Path(directory),authorized=True)},indent=2))
        except (OSError,ValueError,PermissionError) as exc:self.status.setPlainText(json.dumps({"status":"failed","error":str(exc)},indent=2))

    def verify_detection_rule_signatures(self) -> None:
        from mac_audit_agent.anti_ransomware.yara_backend import YaraBackend
        health=source_health(); self.status.setPlainText(json.dumps({"exact_sha256_backend":"AVAILABLE","yara":YaraBackend().capability.__dict__,"production_rule_package_valid":health.full_active_protection,"message":"No unsigned rule package is loaded as trusted."},indent=2))

    def view_no_ransom_plan(self) -> None:
        self.status.setPlainText(json.dumps({"policy":"RANSOM_PAYMENT_PROHIBITED","steps":["Confirm and scope the incident","Isolate affected systems under approved policy","Preserve volatile and durable evidence","Protect unaffected systems and backups","Disable compromised sessions and rotate affected credentials","Identify and eradicate persistence","Validate clean recovery sources","Rebuild and restore in a controlled sequence","Monitor for reinfection","Prepare authorized internal, legal, insurance, CISA, and law-enforcement reporting packages","Record executive decisions and conduct post-incident review"],"prohibited":["payment guidance","cryptocurrency acquisition","attacker negotiation","automatic threat-actor contact"]},indent=2))

    def _show_operation_result(self, operation: str, result: dict) -> None:
        current = resolve_active_protection_status()
        self.status.setPlainText(json.dumps({"operation": operation, "operation_result": result, "persistent_active_protection": current.to_dict(), "anti_ransomware": source_health().to_dict()}, indent=2, default=str))
        self._refresh_parent_health()
        title = "Active Protection " + operation.title()
        message = str(result.get("message", "Operation completed."))
        if result.get("first_failure_stage"):
            message += f"\n\nFirst failure stage: {result['first_failure_stage']}"
        if result.get("recommended_action"):
            message += f"\n\nNext action: {result['recommended_action']}"
        if result.get("status") == "installed_running":
            QMessageBox.information(self, title, message)
        else:
            QMessageBox.warning(self, title, message)

    def _refresh_parent_health(self) -> None:
        window = self.window()
        refresh = getattr(window, "refresh_operational_health", None)
        if callable(refresh):
            refresh()
