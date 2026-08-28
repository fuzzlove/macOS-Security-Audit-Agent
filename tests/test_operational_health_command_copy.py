from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from mac_audit_agent.ui.operational_health_panel import OperationalHealthPanel


def test_what_can_you_do_now_copies_paste_ready_command() -> None:
    app = QApplication.instance() or QApplication([])
    panel = OperationalHealthPanel()
    command = "python3.12 -m mac_audit_agent.protection doctor --json"

    panel._set_suggested_fix(f"```sh\n$ {command}\n```")

    assert panel.action_heading_label.text() == "What can you do now?"
    assert panel.action_label.text() == command
    assert panel.action_label.textFormat() == Qt.PlainText
    assert panel.action_label.textInteractionFlags() & Qt.TextSelectableByMouse
    assert panel.copy_action_button.text() == "Copy Command"

    panel.copy_action_button.click()

    assert QApplication.clipboard().text() == command
    assert panel.copy_action_button.text() == "Copied"
    panel.close()
    app.processEvents()


def test_what_can_you_do_now_keeps_human_guidance_distinct() -> None:
    app = QApplication.instance() or QApplication([])
    panel = OperationalHealthPanel()

    panel._set_suggested_fix("Repair Notifier")

    assert panel.action_label.text() == "Repair Notifier"
    assert panel.copy_action_button.text() == "Copy Guidance"
    panel.copy_action_button.click()
    assert QApplication.clipboard().text() == "Repair Notifier"
    assert panel.copy_action_button.text() == "Copied"
    panel.close()
    app.processEvents()
