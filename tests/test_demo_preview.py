from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QLabel,
    QLineEdit,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from mac_audit_agent.licensing.models import LicenseState, LicenseStatus
from mac_audit_agent.ui.clickfix_awareness_panel import ClickFixAwarenessPanel
from mac_audit_agent.ui.demo_preview import (
    DemoPreviewController,
    preview_control_allowed,
)


def test_preview_control_classifier_keeps_content_navigation_and_blocks_operations() -> None:
    assert preview_control_allowed("Next Presentation")
    assert preview_control_allowed("View Details")
    assert preview_control_allowed("Copy Device Code")
    assert not preview_control_allowed("Run Scan")
    assert not preview_control_allowed("Export Evidence")
    assert not preview_control_allowed("Enable Lockdown", checkable=True)


def test_demo_controller_locks_operations_but_keeps_preview_and_license_import() -> None:
    app = QApplication.instance() or QApplication([])
    window = QWidget()
    pages = QStackedWidget(window)
    page = QWidget()
    layout = QVBoxLayout(page)
    run_button = QPushButton("Run Scan")
    next_button = QPushButton("Next Presentation")
    input_field = QLineEdit()
    license_frame = QFrame()
    license_frame.setProperty("demoAllowed", True)
    license_layout = QVBoxLayout(license_frame)
    import_button = QPushButton("Import Offline License…")
    license_layout.addWidget(import_button)
    layout.addWidget(run_button)
    layout.addWidget(next_button)
    layout.addWidget(input_field)
    layout.addWidget(license_frame)
    pages.addWidget(page)
    banner = QFrame(window)
    banner_label = QLabel(banner)
    export_action = QAction("Export Evidence", window)
    window.addAction(export_action)

    class Manager:
        unlocked = False

        def status(self) -> LicenseStatus:
            return LicenseStatus(LicenseState.VALID if self.unlocked else LicenseState.UNLICENSED, "test", activation_mode="offline" if self.unlocked else "none")

        def product_access(self, _status: LicenseStatus) -> dict[str, object]:
            return {
                "mode": "LICENSED" if self.unlocked else "DEMO_PREVIEW",
                "operator_actions_enabled": self.unlocked,
                "reason": "Licensed" if self.unlocked else "Demo Preview",
            }

    manager = Manager()
    controller = DemoPreviewController(
        window=window,
        pages=pages,
        banner=banner,
        banner_message=banner_label.setText,
        manager_factory=lambda: manager,
    )
    controller.refresh()
    app.processEvents()

    assert banner.isHidden() is False
    assert run_button.isEnabled() is False
    assert export_action.isEnabled() is False
    assert input_field.isEnabled() is False
    assert next_button.isEnabled() is True
    assert import_button.isEnabled() is True

    run_button.setEnabled(True)
    app.processEvents()
    app.processEvents()
    assert run_button.isEnabled() is False

    dynamic_button = QPushButton("Repair Sensor", page)
    layout.addWidget(dynamic_button)
    app.processEvents()
    app.processEvents()
    assert dynamic_button.isEnabled() is False

    manager.unlocked = True
    controller.refresh()
    assert banner.isHidden() is True
    assert run_button.isEnabled() is True
    assert export_action.isEnabled() is True
    assert input_field.isEnabled() is True

    window.close()


def test_clickfix_presentations_remain_viewable_without_writing_completion_state() -> None:
    app = QApplication.instance() or QApplication([])
    pages = QStackedWidget()
    pages.setProperty("demoPreviewMode", True)
    panel = ClickFixAwarenessPanel()
    pages.addWidget(panel)

    panel.start_presentation_button.click()
    app.processEvents()
    viewer = panel._presentation_viewer

    assert viewer is not None
    assert viewer.next_button.isEnabled()
    assert viewer.complete_button.isEnabled() is False
    assert "Fake CAPTCHA Verification" in viewer.slide.toPlainText()
    viewer.next_button.click()
    assert "Urgent Browser Update" in viewer.slide.toPlainText()
    assert panel.completed_presentations == set()

    viewer.close()
    pages.close()
