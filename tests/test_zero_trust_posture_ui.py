import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QComboBox, QPushButton

from mac_audit_agent.ui.zero_trust_panel import ZeroTrustPosturePanel
from mac_audit_agent.zero_trust import ZeroTrustPostureEngine


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


def test_primary_actions_have_explicit_mechanisms_and_hover_help() -> None:
    _app()
    panel = ZeroTrustPosturePanel()
    buttons = {button.text(): button for button in panel.findChildren(QPushButton)}
    assert {"Verify Device", "Generate Attestation", "Start Investigation"}.issubset(buttons)
    assert "read-only endpoint scan" in buttons["Verify Device"].toolTip()
    assert "integrity-hashed" in buttons["Generate Attestation"].toolTip()
    assert "No process is killed" in buttons["Start Investigation"].toolTip()


def test_every_control_has_automatic_and_manual_actions() -> None:
    _app()
    panel = ZeroTrustPosturePanel()
    assert panel.table.columnCount() == 11
    for row in range(panel.table.rowCount()):
        evidence = panel.table.cellWidget(row, 3)
        automatic = panel.table.cellWidget(row, 9)
        manual = panel.table.cellWidget(row, 10)
        assert isinstance(evidence, QComboBox)
        assert [evidence.itemText(index) for index in range(evidence.count())] == ["not collected", "collected"]
        assert isinstance(automatic, QPushButton)
        assert isinstance(manual, QPushButton)
        assert automatic.text() == "Validate Now"
        assert manual.text() == "How to Verify"
        assert automatic.toolTip()
        assert manual.toolTip()


def test_manual_evidence_selection_emits_without_changing_control_state() -> None:
    _app()
    panel = ZeroTrustPosturePanel()
    observed = []
    panel.manual_evidence_changed.connect(lambda signal_id, state: observed.append((signal_id, state)))
    original = panel._posture.signals[0]
    evidence = panel.table.cellWidget(0, 3)
    evidence.setCurrentText("collected")
    assert observed == [(original.signal_id, "collected")]
    assert panel._posture.signals[0].state == original.state


def test_automatic_evidence_disables_redundant_manual_collection() -> None:
    _app()
    panel = ZeroTrustPosturePanel()
    posture = ZeroTrustPostureEngine().calculate({
        "firewall_enabled": True,
        "_evidence_metadata": {
            "firewall_enabled": {
                "source": "Firewall Status",
                "collected_at": "2026-08-26T12:00:00+00:00",
                "freshness": "current",
                "automatic": True,
            }
        },
    })
    panel.set_posture(posture)
    row = next(index for index, signal in enumerate(posture.signals) if signal.signal_id == "firewall_enabled")
    collection = panel.table.cellWidget(row, 3)
    assert collection.currentText() == "automatically collected"
    assert collection.isEnabled() is False
    assert "Firewall Status" in panel.table.item(row, 4).text()
