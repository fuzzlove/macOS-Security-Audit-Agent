from __future__ import annotations

import os
import subprocess
import sys

from mac_audit_agent.ui.anti_ransomware_panel import incident_reporting_references


def test_ic3_is_prioritized_above_supplemental_incident_resources() -> None:
    references = [
        {"reference_id": "fbi-ransomware", "organization": "FBI", "category": "Incident Reporting"},
        {"reference_id": "fbi-cyber", "organization": "FBI", "category": "Investigation"},
        {"reference_id": "fbi-ic3-ransomware", "organization": "FBI Internet Crime Complaint Center", "category": "Incident Reporting"},
    ]

    ordered = incident_reporting_references(references)

    assert [item["reference_id"] for item in ordered] == ["fbi-ic3-ransomware", "fbi-ransomware", "fbi-cyber"]


def test_panel_is_awareness_and_consulting_surface() -> None:
    environment = os.environ.copy()
    environment["QT_QPA_PLATFORM"] = "offscreen"
    environment["MSAA_ALLOW_EXPERIMENTAL_PY314_GUI"] = "1"
    code = (
        "from PySide6.QtWidgets import QApplication, QPushButton; "
        "from mac_audit_agent.ui.anti_ransomware_panel import AntiRansomwarePanel, CONSULTING_BANNER_TEXT, CONSULTING_URL; "
        "app=QApplication.instance() or QApplication([]); panel=AntiRansomwarePanel(); "
        "banner=panel.findChild(type(panel.consulting_banner), 'antiRansomwareConsultingBanner'); "
        "notice=panel.findChild(type(panel.consulting_message), 'antiRansomwareConsultingNotice'); "
        "image=panel.consulting_image; emergency=panel.findChild(QPushButton, 'ic3EmergencyReportingButton'); "
        "repair=panel.findChild(QPushButton, 'repairAntiRansomwareButton'); "
        "simulation=panel.findChild(QPushButton, 'runHarmlessRansomwareSimulationButton'); "
        "suite=panel.findChild(QPushButton, 'runRansomwareSimulationSuiteButton'); "
        "yara_suite=panel.findChild(QPushButton, 'runRansomwareYaraValidationSuiteButton'); "
        "assert notice.text() == CONSULTING_BANNER_TEXT; "
        "assert '469-921-3983' in notice.text(); "
        "assert banner.accessibleName() == CONSULTING_BANNER_TEXT; "
        "assert not image.pixmap().isNull(); "
        "assert CONSULTING_URL in image.toolTip(); assert emergency is not None; "
        "assert repair is not None; assert repair.text() == 'Repair Anti-Ransomware'; "
        "assert repair.accessibleName() == 'Repair Anti-Ransomware protection'; "
        "assert simulation is not None; assert simulation.text() == 'Run Harmless Detection Test'; "
        "assert simulation.accessibleName() == 'Run harmless ransomware detection simulation'; "
        "assert suite is not None; assert suite.text() == 'Run All 16 Safe Simulations'; "
        "assert yara_suite is not None; assert yara_suite.text() == 'Run 20 Safe YARA Tests'; "
        "assert panel.simulation_catalog_table.rowCount() == 16; "
        "assert panel.action_buttons == []; panel.close()"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True,
        env=environment, timeout=30, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
