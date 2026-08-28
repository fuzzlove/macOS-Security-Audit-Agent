from __future__ import annotations

import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush
from PySide6.QtWidgets import QApplication, QPushButton

from mac_audit_agent.not_signed.models import InstalledSoftwareItem, SigningAssessment, SoftwareTrustClassification
from mac_audit_agent.ui.add_remove_programs_page import AddRemoveProgramsPage
from mac_audit_agent.ui.not_signed.page import NotSignedPage
from mac_audit_agent.ui.not_signed.software_table_model import SoftwareTableModel


def test_not_signed_exposes_reversible_forced_controls():
    app = QApplication.instance() or QApplication([])
    page = NotSignedPage()
    disable = page.findChild(QPushButton, "notSignedForceDisableButton")
    uninstall = page.findChild(QPushButton, "notSignedForceUninstallButton")
    assert disable is not None and disable.text() == "Force Disable Selected"
    assert uninstall is not None and uninstall.text() == "Force Uninstall to Trash"
    assert "revers" in (disable.toolTip() + uninstall.toolTip()).lower()
    page.close(); app.processEvents()


def test_not_signed_severity_cell_color_and_text_communicate_impact():
    app = QApplication.instance() or QApplication([])
    model = SoftwareTableModel()
    assessment = SigningAssessment(SoftwareTrustClassification.REVOKED, False, False, False)
    model.add_item(InstalledSoftwareItem(
        "revoked", "Revoked Fixture", Path("/tmp/revoked-fixture"), None, None, None, None,
        assessment, severity="critical", risk_reasons=("Certificate was revoked.",),
    ))
    index = model.index(0, 0)

    assert model.headerData(0, Qt.Horizontal) == "Severity / Impact"
    assert model.data(index, Qt.DisplayRole) == "CRITICAL · Severe"
    assert isinstance(model.data(index, Qt.BackgroundRole), QBrush)
    assert model.data(index, Qt.BackgroundRole).color().isValid()
    assert model.data(index, Qt.ForegroundRole).color().isValid()
    assert "not proof of malware" in model.data(index, Qt.ToolTipRole)
    assert model.data(index, SoftwareTableModel.SORT_ROLE) > 0


def test_add_remove_programs_labels_forced_actions_and_keeps_quarantine_explicit():
    app = QApplication.instance() or QApplication([])
    page = AddRemoveProgramsPage()
    standard = page.findChild(QPushButton, "forceUninstallApplicationButton")
    disable = page.findChild(QPushButton, "forceDisableSystemApplicationButton")
    system = page.findChild(QPushButton, "forceUninstallSystemApplicationButton")
    assert standard is not None and standard.text() == "Force Uninstall Selected"
    assert disable is not None and "Quarantine" in disable.text()
    assert system is not None and "System Quarantine" in system.text()
    page.close(); app.processEvents()


def test_add_remove_programs_colors_impact_and_sorts_highest_severity_first():
    app = QApplication.instance() or QApplication([])
    page = AddRemoveProgramsPage()
    assessment = SigningAssessment(SoftwareTrustClassification.UNSIGNED, False, False, False)
    for identifier, name, severity in (
        ("limited", "Limited Fixture", "low"),
        ("severe", "Severe Fixture", "critical"),
    ):
        page.model.add_item(InstalledSoftwareItem(
            item_id=identifier,
            display_name=name,
            executable_path=Path(f"/Applications/{name}.app/Contents/MacOS/{name}"),
            bundle_path=Path(f"/Applications/{name}.app"),
            bundle_identifier=f"test.{identifier}",
            version=None,
            icon_path=None,
            signing=assessment,
            severity=severity,
            risk_reasons=(f"{severity.title()} review factor.",),
        ))
    page.table.sortByColumn(0, Qt.DescendingOrder)
    app.processEvents()

    severity_index = page.proxy.index(0, 0)
    assert page.proxy.headerData(0, Qt.Horizontal) == "Severity / Impact"
    assert page.proxy.data(severity_index, Qt.DisplayRole) == "CRITICAL · Severe"
    assert isinstance(page.proxy.data(severity_index, Qt.BackgroundRole), QBrush)
    assert "not proof of malware" in page.proxy.data(severity_index, Qt.ToolTipRole)
    assert page.proxy.sortRole() == SoftwareTableModel.SORT_ROLE
    assert "color-coded severity" in page.table.accessibleDescription()
    assert page.table.horizontalHeader().sectionSize(0) >= 150
    page.close(); app.processEvents()
