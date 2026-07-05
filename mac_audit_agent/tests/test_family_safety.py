from __future__ import annotations

import os
from pathlib import Path
import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QLabel, QMessageBox, QPushButton, QScrollArea, QTextEdit

from mac_audit_agent.family_safety import (
    FamilySafetyAuditor,
    export_family_safety_excel,
    export_family_safety_html,
    export_family_safety_json,
    export_family_safety_word,
)
from mac_audit_agent.family_safety.categories import canonical_family_safety_categories, category_score, lockdown_plus_status
from mac_audit_agent.ui.family_safety_panel import FamilySafetyPanel
from mac_audit_agent.ui.main_window import MainWindow


def test_family_safety_report_is_privacy_first_and_scored(tmp_path: Path, monkeypatch) -> None:
    auditor = FamilySafetyAuditor(home=tmp_path)
    monkeypatch.setattr(auditor, "_run", lambda command: "FileVault is On." if "fdesetup" in command else "")
    monkeypatch.setattr(auditor, "_app_review", lambda: [])

    report = auditor.build_report("Young Child")
    payload = report.to_dict()

    assert 0 <= payload["score"]["score"] <= 100
    assert payload["wizard_recommendations"]["profile"] == ["Young Child"]
    assert any("browsing history" in item for item in payload["privacy_notice"])
    assert any(item["title"] == "Screen Time enabled" for item in payload["findings"])
    assert any(card["topic"] == "Cyberbullying" for card in payload["education_cards"])
    assert "category_definitions" in payload
    assert "government_lockdown_score" in payload
    assert "lockdown_plus_score" in payload


def test_family_safety_exports_html_and_json(tmp_path: Path, monkeypatch) -> None:
    auditor = FamilySafetyAuditor(home=tmp_path)
    monkeypatch.setattr(auditor, "_run", lambda command: "")
    monkeypatch.setattr(auditor, "_app_review", lambda: [])
    report = auditor.build_report("School Device")

    html_path = export_family_safety_html(report, tmp_path / "family.html")
    json_path = export_family_safety_json(report, tmp_path / "family.json")

    assert "Family Safety Report" in html_path.read_text(encoding="utf-8")
    assert "Privacy-first report" in html_path.read_text(encoding="utf-8")
    assert "Government / NIST Lockdown Profile" in html_path.read_text(encoding="utf-8")
    assert "Lockdown Mode Plus" in html_path.read_text(encoding="utf-8")
    assert '"wizard_recommendations"' in json_path.read_text(encoding="utf-8")
    assert '"category_definitions"' in json_path.read_text(encoding="utf-8")


def test_family_safety_exports_word_and_excel_when_available(tmp_path: Path, monkeypatch) -> None:
    auditor = FamilySafetyAuditor(home=tmp_path)
    monkeypatch.setattr(auditor, "_run", lambda command: "")
    monkeypatch.setattr(auditor, "_app_review", lambda: [])
    report = auditor.build_report("School Device")
    try:
        word_path = export_family_safety_word(report, tmp_path / "family.docx")
        excel_path = export_family_safety_excel(report, tmp_path / "family.xlsx")
    except RuntimeError as exc:
        pytest.skip(str(exc))
    assert word_path.exists()
    assert excel_path.exists()


def test_main_navigation_includes_family_safety(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")

    items = [window.sidebar.item(index).text() for index in range(window.sidebar.count())]
    assert "Family & Safety" in items
    assert hasattr(window, "family_safety_panel")
    window.show_family_safety_page()
    assert window.sidebar.currentItem().text() == "Family & Safety"

    window.close()
    app.processEvents()


def test_family_category_model_is_complete() -> None:
    categories = canonical_family_safety_categories()
    assert len(categories) >= 14
    for category in categories:
        assert category.category_id
        assert category.title
        assert category.short_description
        assert category.detailed_description
        assert category.why_it_matters
        assert category.what_is_checked
        assert category.what_the_user_can_change
        assert category.macos_settings_paths
        assert category.checklist_items
        assert category.reset_available is True


def test_government_nist_category_uses_supported_language() -> None:
    category = next(item for item in canonical_family_safety_categories() if item.category_id == "government_nist_lockdown")
    text = " ".join(
        [
            category.title,
            category.short_description,
            category.detailed_description,
            " ".join(category.nist_mappings),
            " ".join(category.checklist_items),
        ]
    ).lower()
    assert "nist-aligned" in text
    assert "nist sp 800-53" in text
    assert "nist sp 800-61" in text
    disallowed = [
        "nist " + "compliant",
        "government " + "certified",
        "approved for " + "federal use",
    ]
    assert all(phrase not in text for phrase in disallowed)
    assert 0 <= category_score(category, ["configured", "needs_review", "manual_verification_required"]) <= 100


def test_lockdown_plus_category_and_score() -> None:
    category = next(item for item in canonical_family_safety_categories() if item.category_id == "lockdown_mode_plus")
    assert "does not replace Apple Lockdown Mode" in category.detailed_description
    assert any("Manually verify Apple Lockdown Mode status" == item for item in category.checklist_items)
    assert lockdown_plus_status(90) == "Ready"
    assert lockdown_plus_status(70) == "Strengthen"
    assert lockdown_plus_status(45) == "Review Required"
    assert lockdown_plus_status(10) == "High Exposure"


def test_family_panel_category_header_and_state_isolation() -> None:
    app = QApplication.instance() or QApplication([])
    panel = FamilySafetyPanel()
    device_id = "usb-device-1"
    panel.select_device_for_category("device_physical_access_safety", device_id)
    panel.category_list.setCurrentRow(panel._category_order.index("device_physical_access_safety"))
    assert device_id in panel.category_selected_device_label.text()
    panel.category_list.setCurrentRow(panel._category_order.index("web_browser_safety"))
    assert "Currently viewing: Web and Browser Safety" in panel.category_context_label.text()
    assert "No item selected" in panel.category_selected_device_label.text()
    panel.category_list.setCurrentRow(panel._category_order.index("device_physical_access_safety"))
    assert device_id in panel.category_selected_device_label.text()
    panel.close()
    app.processEvents()


def test_family_panel_reset_view_and_pending_are_per_category(monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    panel = FamilySafetyPanel()
    account_id = "account_safety"
    web_id = "web_browser_safety"
    panel.simulate_pending_change(account_id, "Disable Guest access")
    panel.simulate_pending_change(web_id, "Block popups")
    panel.category_list.setCurrentRow(panel._category_order.index(account_id))
    monkeypatch.setattr("mac_audit_agent.ui.family_safety_panel.QMessageBox.question", lambda *args, **kwargs: QMessageBox.Yes)
    panel.reset_current_category_pending_changes()
    assert panel._view_state[account_id].pending_changes == []
    assert panel._view_state[web_id].pending_changes == ["Block popups"]
    panel._view_state[account_id].selected_checklist_item = "Review admin users"
    panel.reset_current_category_view_state()
    assert panel._view_state[account_id].selected_checklist_item == ""
    assert panel._view_state[web_id].pending_changes == ["Block popups"]
    panel.close()
    app.processEvents()


def test_family_panel_layout_uses_readable_columns_and_scroll_area() -> None:
    app = QApplication.instance() or QApplication([])
    panel = FamilySafetyPanel()

    assert panel.minimumWidth() >= 820
    assert panel.category_list.minimumWidth() >= 220
    assert isinstance(panel.category_detail_scroll, QScrollArea)
    assert panel.category_detail_scroll.widgetResizable() is True
    assert panel.category_detail_scroll.minimumWidth() >= 520
    assert panel.category_title_label.wordWrap() is True
    assert panel.category_context_label.wordWrap() is True
    assert panel.category_status_label.wordWrap() is True
    assert panel.category_description_view.lineWrapMode() == QTextEdit.WidgetWidth
    assert panel.category_checklist_table.minimumHeight() >= 260

    panel.close()
    app.processEvents()


def test_family_panel_buttons_fit_and_have_tooltips() -> None:
    app = QApplication.instance() or QApplication([])
    panel = FamilySafetyPanel()

    for button in panel.findChildren(QPushButton):
        if button.isHidden():
            continue
        assert button.text().strip()
        assert button.toolTip().strip()
        assert button.minimumHeight() >= 34
        assert button.minimumWidth() >= 120

    panel.close()
    app.processEvents()


def test_family_panel_nist_and_lockdown_categories_render_without_blank_titles() -> None:
    app = QApplication.instance() or QApplication([])
    panel = FamilySafetyPanel()

    for category_id, expected_title in [
        ("government_nist_lockdown", "Government / NIST Lockdown Profile"),
        ("lockdown_mode_plus", "Lockdown Mode Plus"),
    ]:
        panel.category_list.setCurrentRow(panel._category_order.index(category_id))
        assert panel.category_title_label.text() == expected_title
        assert "Currently viewing:" in panel.category_context_label.text()
        assert panel.category_description_view.toPlainText().strip()
        assert panel.category_checklist_table.rowCount() > 0

    panel.close()
    app.processEvents()


def test_family_panel_empty_states_explain_missing_data() -> None:
    app = QApplication.instance() or QApplication([])
    panel = FamilySafetyPanel()
    panel.set_report({})

    assert "Run the Safety Audit" in panel.audit_table.item(0, 0).text()
    assert "No item selected" in panel.category_selected_device_label.text()
    assert "Pending changes: none" in panel.category_pending_label.text()
    labels = [label.text() for label in panel.findChildren(QLabel) if label.isVisible()]
    assert all(text is not None for text in labels)

    panel.close()
    app.processEvents()
