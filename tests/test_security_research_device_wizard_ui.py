from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from mac_audit_agent.ui.security_research_device_panel import SecurityResearchDevicePanel


class _FakeDatabase:
    def __init__(self) -> None:
        self.states: dict[str, str] = {}
        self.events = []

    def get_background_monitor_state(self, key: str, default: str = "") -> str:
        return self.states.get(key, default)

    def set_background_monitor_state(self, key: str, value: str) -> None:
        self.states[key] = value

    def record_background_monitor_event(self, event, **_kwargs) -> None:
        self.events.append(event)


def test_security_research_device_is_an_authorization_gated_wizard() -> None:
    app = QApplication.instance() or QApplication([])
    database = _FakeDatabase()
    panel = SecurityResearchDevicePanel(database)

    assert panel.wizard_pages.count() == 3
    assert panel.wizard_pages.currentIndex() == 0
    assert panel.step_indicator.text() == "Step 1 of 3 — Select Scope"
    assert not panel.start_wizard_button.isEnabled()

    panel.authorization_checkbox.setChecked(True)
    assert panel.start_wizard_button.isEnabled()
    panel.start_wizard_button.click()

    assert panel.wizard_pages.currentIndex() == 1
    assert panel.step_indicator.text().startswith("Step 2 of 3 — Review Controls")
    assert panel.progress.format().startswith("Task 1 of ")
    assert panel.previous.text() == "Back to Scope"
    assert any(event.event_type == "security_research_wizard_started" for event in database.events)

    panel.previous.click()
    assert panel.wizard_pages.currentIndex() == 0
    assert panel.step_indicator.text() == "Step 1 of 3 — Select Scope"

    panel.close()
    app.processEvents()


def test_security_research_wizard_finishes_with_evidence_summary() -> None:
    app = QApplication.instance() or QApplication([])
    database = _FakeDatabase()
    panel = SecurityResearchDevicePanel(database)
    panel.authorization_checkbox.setChecked(True)
    panel.start_wizard_button.click()
    panel._states.update({
        "filevault": {"status": "pass"},
        "secure_boot": {"status": "unknown", "manual_evidence_collected_at": "2026-08-25T00:00:00Z"},
        "sip": {"status": "fail"},
    })
    panel._index = len(panel._tasks()) - 1
    panel._render()

    assert panel.next.text() == "Review Summary"
    panel.next.click()

    summary = panel.summary.toPlainText()
    assert panel.wizard_pages.currentIndex() == 2
    assert panel.step_indicator.text() == "Step 3 of 3 — Review & Export"
    assert "1 pass · 1 fail · 1 unknown/manual review" in summary
    assert "EVIDENCE RECORDED" in summary
    assert "not certification" in summary

    panel.restart_wizard_button.click()
    assert panel.wizard_pages.currentIndex() == 0
    assert not panel.authorization_checkbox.isChecked()
    panel.close()
    app.processEvents()
