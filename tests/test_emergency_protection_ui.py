from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QPushButton

from mac_audit_agent.ui.emergency_protection_panel import EmergencyProtectionPanel


def test_emergency_protection_exposes_apple_lockdown_mode_shortcut() -> None:
    app = QApplication.instance() or QApplication([])
    panel = EmergencyProtectionPanel()

    button = panel.findChild(QPushButton, "openAppleLockdownModeSwitchButton")

    assert button is not None
    assert button.text() == "Open Apple Lockdown Mode Switch"
    assert button.property("role") == "urgent"
    assert "flip the switch" in button.toolTip().lower()
    assert "restart" in button.toolTip().lower()
    panel.close()
    app.processEvents()
