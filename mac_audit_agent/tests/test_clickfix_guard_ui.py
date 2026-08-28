import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QSizePolicy

from mac_audit_agent.ui.clickfix_guard_panel import ClickFixGuardPanel


def test_clickfix_current_status_is_a_full_width_expanding_section(monkeypatch, tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr(ClickFixGuardPanel, "refresh", lambda self: None)

    panel = ClickFixGuardPanel(evidence_path=tmp_path / "clickfix.sqlite3")

    assert panel.layout().indexOf(panel.status_group) < panel.layout().indexOf(panel.alert_center)
    assert panel.status_group.title() == "Current status"
    assert panel.status_label.wordWrap()
    assert panel.status_label.minimumWidth() == 0
    assert panel.status_label.sizePolicy().horizontalPolicy() == QSizePolicy.Expanding
    assert panel.status_label.sizePolicy().verticalPolicy() == QSizePolicy.Minimum
    assert panel.status_label.accessibleName() == "ClickFix Guard current status"
    assert panel.prevention_readiness.accessibleName() == "ClickFix attack prevention readiness"
    assert "most recognized" in panel.prevention_readiness.text()
    assert panel.shell_status_label.accessibleName() == "ClickFix shell guard detailed status"
    assert panel.shell_mode.accessibleName() == "ClickFix shell enforcement mode"
    assert panel.shell_warn_threshold.accessibleName() == "ClickFix warning threshold"
    assert panel.shell_block_threshold.accessibleName() == "ClickFix block threshold"
    assert panel.shell_proxy_enabled.accessibleName() == "ClickFix generic proxy policy"

    panel.close()
    app.processEvents()


def test_clickfix_status_state_is_visually_distinct(monkeypatch, tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr(ClickFixGuardPanel, "refresh", lambda self: None)
    panel = ClickFixGuardPanel(evidence_path=tmp_path / "clickfix.sqlite3")

    panel._set_status("Degraded: CFX001", "degraded")

    assert panel.status_label.text() == "Degraded: CFX001"
    assert "padding: 10px" in panel.status_label.styleSheet()
    assert "font-weight: 700" in panel.status_label.styleSheet()

    panel.close()
    app.processEvents()
