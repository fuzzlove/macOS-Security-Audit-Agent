from __future__ import annotations

import os

# Select the non-AppKit platform before importing PySide6. These tests can run
# under Codex/CI processes that are not registered GUI applications on macOS.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from mac_audit_agent.ui.network_segmentation_panel import NetworkSegmentationPanel


def test_provider_status_remains_visible_and_uncropped_at_narrow_width():
    app = QApplication.instance() or QApplication([])
    panel = NetworkSegmentationPanel()
    panel.resize(520, 720)
    panel.show()
    app.processEvents()

    status = panel.provider_info
    assert status.isVisible()
    assert status.wordWrap()
    assert status.width() > 300
    assert status.height() >= status.sizeHint().height()
    assert status.toolTip() == status.text()
    assert "DNS addresses, ASN, and RIR" in status.text()
    panel.close()


def test_provider_status_updates_for_unqualified_provider():
    app = QApplication.instance() or QApplication([])
    panel = NetworkSegmentationPanel()
    index = panel.provider.findData("egresser")
    panel.provider.setCurrentIndex(index)
    app.processEvents()

    assert "UNQUALIFIED" in panel.provider_info.text()
    assert "Qualification required" in panel.provider_info.text()
    assert not panel.run_button.isEnabled()
    panel.close()


def test_full_range_and_custom_range_selection_are_explicit():
    app = QApplication.instance() or QApplication([])
    panel = NetworkSegmentationPanel()
    panel.provider.setCurrentIndex(panel.provider.findData("portquiz"))
    assert panel.full_range.isEnabled()
    panel.full_range.setChecked(True)
    assert not panel.ports.isEnabled()
    ports=panel._parsed_ports()
    assert ports[0]==1 and ports[-1]==65535 and len(ports)==65535
    panel.full_range.setChecked(False)
    panel.ports.setText("53,80,8000-8002")
    assert panel._parsed_ports()==[53,80,8000,8001,8002]
    app.processEvents();panel.close()


def test_network_segmentation_separates_egress_and_ingress_workflows():
    app = QApplication.instance() or QApplication([])
    panel = NetworkSegmentationPanel()
    assert [panel.segmentation_tabs.tabText(index) for index in range(panel.segmentation_tabs.count())] == ["Egress Tests", "Ingress Tests"]
    assert panel.ingress_target.placeholderText() == "Exact target IP or CIDR"
    assert panel.ingress_authorized_cidr.placeholderText().startswith("Authorized destination CIDR")
    assert panel.ingress_profile.count() >= 10
    assert panel.ingress_export_button.isEnabled() is False
    app.processEvents();panel.close()
