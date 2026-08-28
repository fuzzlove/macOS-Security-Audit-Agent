from __future__ import annotations

import os
import subprocess
import sys


def test_panel_exposes_safe_unhook_and_quarantine_action() -> None:
    environment = os.environ.copy()
    environment["QT_QPA_PLATFORM"] = "offscreen"
    environment["MSAA_ALLOW_EXPERIMENTAL_PY314_GUI"] = "1"
    code = (
        "from PySide6.QtWidgets import QApplication, QLabel, QPushButton; "
        "from mac_audit_agent.ui.button_layout_auditor import audit_buttons; "
        "from mac_audit_agent.ui.keylogger_detection_panel import KeyloggerDetectionPanel; "
        "app=QApplication.instance() or QApplication([]); panel=KeyloggerDetectionPanel(); panel.resize(820,760); panel.show(); app.processEvents(); "
        "button=panel.findChild(QPushButton, 'unhookKeyloggerButton'); "
        "assert button is not None; assert button.text() == 'Unhook & Quarantine'; "
        "assert button.accessibleName() == 'Unhook and quarantine selected keylogger indicator'; "
        "assert 'reversible quarantine' in button.toolTip(); "
        "headers=[panel.table.horizontalHeaderItem(i).text() for i in range(panel.table.columnCount())]; "
        "assert 'Confidence' in headers and 'False-positive risk' in headers; "
        "labels={item.text() for item in panel.findChildren(QLabel)}; "
        "assert {'Intervention','Removal (evidence first; reversible quarantine)','Remediation and verification'} <= labels; "
        "assert not [issue for record in audit_buttons(panel) for issue in record['issues'] if 'overlap' in issue['issue']]; panel.close()"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True,
        env=environment, timeout=30, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
