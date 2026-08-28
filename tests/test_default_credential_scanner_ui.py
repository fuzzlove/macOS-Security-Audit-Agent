from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from mac_audit_agent.help.help_registry import get_help_topic
from mac_audit_agent.ui.main_window import MainWindow


def test_default_credential_scanner_is_first_class_network_page(tmp_path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")
    navigation = {item.id: item.title for item in window.navigation_items}

    assert navigation["default_credential_scanner"] == "Default Credential Scanner"
    assert hasattr(window, "default_credential_scanner_panel")
    assert window.default_credential_scanner_panel.scan_button.text() == "Scan Authorized Targets"
    assert not window.default_credential_scanner_panel.scan_button.isEnabled()
    assert get_help_topic("default_credential_scanner") is not None

    window.default_credential_scanner_panel.repository.close()
    window.close()
    app.processEvents()
