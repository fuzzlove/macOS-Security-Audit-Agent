from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QPushButton

from mac_audit_agent.ui.anti_typosquatting_page import AntiTyposquattingPage, TYPO_SQUATTING_EXAMPLES
from mac_audit_agent.anti_typosquatting.models import AssetType, ProtectedAsset
from mac_audit_agent.anti_typosquatting.service import AntiTyposquattingService


def test_page_has_complete_accessible_actions_and_dynamic_ecosystem():
    app = QApplication.instance() or QApplication([])
    page = AntiTyposquattingPage()
    assert page.examples.text() == TYPO_SQUATTING_EXAMPLES
    assert {"microsoftt.co", "npmm", "python4"} <= set(page.examples.text().replace("—", " ").split())
    assert "educational examples only" in page.examples.text()
    labels = {button.text() for button in page.findChildren(QPushButton)}
    assert labels == {
        "Generate Likely Typographical Variants", "Check Registration and Publication Status",
        "Add Selected Variants to Protection Watchlist", "Export Analysis Results", "Clear Analysis Results",
    }
    for button in page.findChildren(QPushButton):
        assert button.accessibleName() == button.text()
        assert button.toolTip()
    assert not page.ecosystem.isVisible()
    page.asset_type.setCurrentIndex(1)
    assert not page.ecosystem.isHidden()
    assert page.ecosystem.count() == 8
    page.ecosystem.setCurrentIndex(5)
    assert not page.namespace_part.isHidden() and page.namespace_label.text() == "Group Identifier"
    page.ecosystem.setCurrentIndex(7)
    assert page.namespace_label.text() == "Vendor"
    page.ecosystem.setCurrentIndex(6)
    assert not page.go_privacy.isHidden()
    page._complete(AntiTyposquattingService().analyze(ProtectedAsset(AssetType.DOMAIN, "examplebrand.test")))
    headers = {page.table.horizontalHeaderItem(column).text() for column in range(page.table.columnCount())}
    assert {"Risk Band", "Attacker-use Assumption %", "Name Closeness %", "Registration Guidance"} <= headers
    assert page.table.item(0, 1).background().color().isValid()
    page.table.setCurrentCell(0, 0); app.processEvents()
    assert "Attacker-use assumption:" in page.details.toPlainText()
    assert "not evidence of attacker intent" in page.details.toPlainText()
    page.close(); app.processEvents()
