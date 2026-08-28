from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from mac_audit_agent.ui.clickfix_awareness_panel import ClickFixAwarenessPanel
from mac_audit_agent.clickfix.awareness import CLICKFIX_PRESENTATIONS


def test_awareness_fixtures_are_non_executable_and_report_a_result() -> None:
    app = QApplication.instance() or QApplication([])
    panel = ClickFixAwarenessPanel()
    for _ in range(12):
        panel.generate_fixture()
    text = panel.fixture.toPlainText()
    assert "EXECUTABLE_CONTENT=[OMITTED_BY_DESIGN]" in text
    assert "FINAL_INTENT=[OPEN_CALCULATOR_DEMONSTRATION_ONLY]" in text
    assert "WHAT A CLICKFIX PROMPT MAY LOOK LIKE" in text
    assert "# DO NOT PASTE — INERT MSAA TRAINING FACSIMILE" in text
    assert ".example.invalid" in text
    facsimile = text.split("# DO NOT PASTE — INERT MSAA TRAINING FACSIMILE", 1)[1].split("\n\nRESULT", 1)[0]
    assert all(not line.strip() or line.lstrip().startswith("#") for line in facsimile.splitlines())
    assert panel.last_report is not None
    assert panel.last_report["non_executable"] is True
    assert panel.last_report["executable_content_stored"] is False
    assert panel.last_report["complexity"] == 5
    assert panel.last_report["guard_result"] in {"caught", "needs_definition_review"}
    panel.close(); app.processEvents()


def test_twenty_benign_awareness_presentations_cover_common_lures() -> None:
    app = QApplication.instance() or QApplication([])
    panel = ClickFixAwarenessPanel()

    assert len(CLICKFIX_PRESENTATIONS) == 20
    assert panel.presentation_combo.count() == 20
    assert panel.start_presentation_button.text() == "Start Presentation"
    titles = {item.title for item in CLICKFIX_PRESENTATIONS}
    assert {"Fake CAPTCHA Verification", "Urgent Browser Update", "Fake IT Support"}.issubset(titles)
    for index in range(20):
        panel.presentation_combo.setCurrentIndex(index)
        rendered = panel.presentation.toPlainText()
        assert f"CLICKFIX AWARENESS {index + 1} OF 20" in rendered
        assert "EDUCATIONAL SIMULATION" in rendered
        assert all(token not in rendered.lower() for token in ("curl ", "/bin/", "base64 ", "osascript ", "chmod "))

    panel.presentation_combo.setCurrentIndex(0)
    panel._mark_presentation_complete()
    assert "1/20" in panel.presentation_progress.text()
    assert "not a security finding" in panel.presentation_progress.text()
    panel.close()
    app.processEvents()


def test_start_presentation_opens_focused_viewer_and_advances_slides() -> None:
    app = QApplication.instance() or QApplication([])
    panel = ClickFixAwarenessPanel()

    panel.start_presentation_button.click()
    viewer = panel._presentation_viewer
    assert viewer is not None
    assert viewer.isVisible()
    assert "Fake CAPTCHA Verification" in viewer.slide.toPlainText()
    assert viewer.counter_label.text() == "Presentation 1 of 20"

    viewer.next_button.click()
    assert panel.presentation_combo.currentIndex() == 1
    assert "Urgent Browser Update" in viewer.slide.toPlainText()
    viewer.complete_button.click()
    assert CLICKFIX_PRESENTATIONS[1].presentation_id in panel.completed_presentations
    assert viewer.complete_button.text() == "Completed"

    viewer.close()
    panel.close()
    app.processEvents()
