import os
import subprocess
import sys
from pathlib import Path

from mac_audit_agent.quality.button_functionality_auditor import audit_visible_buttons


def test_critical_protection_buttons_are_connected_and_explained() -> None:
    report = audit_visible_buttons(Path(__file__).parents[1])
    assert report["status"] == "pass", report["blockers"]
    labels = {item["label"] for item in report["critical_items"]}
    assert {"Install Active Protection", "Repair Active Protection", "Verify Active Protection", "Export Protection Diagnostics"} <= labels
    assert all(item["callback_connected"] and item["tooltip_present"] for item in report["critical_items"])


def test_gui_callbacks_target_shared_protection_backend() -> None:
    panel = (Path(__file__).parents[1] / "mac_audit_agent/ui/anti_ransomware_panel.py").read_text(encoding="utf-8")
    main = (Path(__file__).parents[1] / "mac_audit_agent/ui/main_window.py").read_text(encoding="utf-8")
    assert "install_active_protection(ActiveProtectionInstallOptions" in panel
    assert "repair_active_protection(ActiveProtectionRepairOptions" in panel
    assert "install_active_protection(ActiveProtectionInstallOptions" in main
    assert "repair_active_protection(ActiveProtectionRepairOptions" in main


def test_demo_price_advertisement_starts_stripe_checkout() -> None:
    main = (Path(__file__).parents[1] / "mac_audit_agent/ui/main_window.py").read_text(encoding="utf-8")
    panel = (Path(__file__).parents[1] / "mac_audit_agent/ui/licensing_panel.py").read_text(encoding="utf-8")

    assert 'clicked.connect(self._begin_demo_preview_checkout)' in main
    assert "self.licensing_panel.begin_checkout()" in main
    assert "def begin_checkout(self)" in panel
    assert 'self._start(_LicenseWorker("checkout"))' in panel


def test_anti_ransomware_panel_public_callbacks_exist_in_source() -> None:
    from mac_audit_agent.ui.button_callback_registry import validate_callback_source
    missing = [item.to_dict() for item in validate_callback_source(Path(__file__).parents[1]) if not item.exists]
    assert not missing
    source = (Path(__file__).parents[1] / "mac_audit_agent/ui/anti_ransomware_panel.py").read_text(encoding="utf-8")
    for callback in ("install_protection", "repair_protection", "verify_protection", "refresh_protection_status", "open_protection_diagnostics"):
        assert f"def {callback}(" in source


def test_missing_callback_disables_button_instead_of_raising() -> None:
    from mac_audit_agent.ui.button_callback_registry import connect_or_disable

    class Signal:
        def connect(self, callback):
            raise AssertionError("missing callback must not connect")

    class Button:
        clicked = Signal()
        enabled = True
        tooltip = ""
        def setEnabled(self, value): self.enabled = value
        def setToolTip(self, value): self.tooltip = value

    button = Button()
    assert connect_or_disable(button, object(), "missing") is False
    assert button.enabled is False
    assert "callback not implemented" in button.tooltip


def test_anti_ransomware_awareness_panel_instantiates_without_app999() -> None:
    environment = os.environ.copy()
    environment["QT_QPA_PLATFORM"] = "offscreen"
    environment["MSAA_ALLOW_EXPERIMENTAL_PY314_GUI"] = "1"
    code = "from PySide6.QtWidgets import QApplication; from mac_audit_agent.ui.anti_ransomware_panel import AntiRansomwarePanel; app=QApplication.instance() or QApplication([]); panel=AntiRansomwarePanel(); assert not panel.consulting_image.pixmap().isNull(); assert panel.action_buttons == []; panel.close()"
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=environment, timeout=30, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
