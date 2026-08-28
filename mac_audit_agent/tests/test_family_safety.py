from __future__ import annotations

import os
from pathlib import Path
import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QLabel, QMessageBox, QPushButton, QScrollArea, QTextEdit

from mac_audit_agent.family_safety import (
    FamilySafetyAuditor,
    FamilySafetyRecommendationEngine,
    apply_family_safety_recommendation,
    canonical_family_safety_profiles,
    canonical_family_safety_questions,
    export_family_safety_configuration_html,
    export_family_safety_configuration_json,
    export_family_safety_configuration_markdown,
    export_family_safety_configuration_excel,
    export_family_safety_configuration_word,
    restore_family_safety_snapshot,
    export_family_safety_excel,
    export_family_safety_html,
    export_family_safety_json,
    export_family_safety_word,
)
from mac_audit_agent.family_safety.categories import canonical_family_safety_categories, category_score, lockdown_plus_status
from mac_audit_agent.family_safety.system_setup import (
    SCREEN_TIME_SETTINGS_URL,
    build_family_system_setup_plan,
    execute_family_system_setup_handoff,
)
from mac_audit_agent.monitor_settings import load_settings, save_settings
from mac_audit_agent.storage import AuditDatabase
from mac_audit_agent.ui.family_safety_panel import FamilySafetyPanel, FamilySafetyWizardDialog
from mac_audit_agent.ui.main_window import MainWindow
from mac_audit_agent.ui.responsive_actions import ResponsiveActionRow
from mac_audit_agent.quality.functional_registry import build_registry


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

    assert panel.minimumWidth() == 640
    assert panel.category_list.minimumWidth() >= 180
    assert isinstance(panel.category_detail_scroll, QScrollArea)
    assert panel.category_detail_scroll.widgetResizable() is True
    assert panel.category_detail_scroll.minimumWidth() >= 420
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


def test_family_panel_long_action_groups_use_responsive_rows() -> None:
    app = QApplication.instance() or QApplication([])
    panel = FamilySafetyPanel()

    for actions in (
        panel.setup_actions,
        panel.report_actions,
        panel.category_reset_actions,
        panel.category_navigation_actions,
    ):
        assert isinstance(actions, ResponsiveActionRow)
        assert actions.heightForWidth(360) >= actions.heightForWidth(900)
    for button in panel.findChildren(QPushButton):
        assert button.minimumWidth() >= button.fontMetrics().horizontalAdvance(button.text()) + 32

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


def test_family_safety_wizard_questions_and_profiles_are_complete() -> None:
    questions = canonical_family_safety_questions()
    profiles = canonical_family_safety_profiles()
    assert len(questions) == 11
    assert {profile.profile_id for profile in profiles} >= {
        "balanced_family_safety",
        "child_minor_safety",
        "teen_shared_device_safety",
        "elder_at_risk_safety",
        "school_student_device",
        "high_security_government_lockdown",
        "custom_profile",
    }
    for question in questions:
        assert question.prompt
        assert question.help_text
        assert question.options
        assert question.default_option in question.options
        assert question.affects_settings
        assert question.standards_context
    for profile in profiles:
        assert profile.expected_behavior
        assert profile.privacy_notes
        assert profile.manual_review_items
        assert isinstance(profile.revert_supported, bool)


def test_family_device_role_builds_screen_time_and_managed_action_plan() -> None:
    child = build_family_system_setup_plan("child_minor_safety")
    school = build_family_system_setup_plan("school_student_device")

    screen_time = next(item for item in child if item.action_id == "macos.screen_time")
    assert screen_time.settings_url == SCREEN_TIME_SETTINGS_URL
    assert screen_time.automation == "USER_APPROVAL_REQUIRED"
    assert "owner or Family Sharing parent/guardian" in screen_time.reason
    assert any(item.automation == "MDM_REQUIRED" for item in school)


def test_family_system_handoff_opens_only_one_allowlisted_setting_and_never_claims_change() -> None:
    opened: list[str] = []
    results = execute_family_system_setup_handoff(
        build_family_system_setup_plan("child_minor_safety"),
        opener=lambda url: opened.append(url) or True,
        max_opened=1,
    )

    assert opened == [SCREEN_TIME_SETTINGS_URL]
    assert results[0]["status"] == "OPENED_FOR_USER_APPROVAL"
    assert results[0]["changed"] is False
    assert all(item["verified"] is False for item in results)
    assert any(item["status"] == "QUEUED_FOR_USER_REVIEW" for item in results)


def test_family_device_role_selection_builds_profile_and_preview_immediately(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    dialog = FamilySafetyWizardDialog(db)

    dialog.device_role_combo.setCurrentIndex(dialog.device_role_combo.findData("Young Child"))

    assert dialog.recommendation is not None
    assert dialog.recommendation.selected_profile.profile_id == "child_minor_safety"
    assert dialog.stack.currentWidget() is dialog._preview_page
    assert dialog.question_widgets["auto_apply"].currentText() == "Apply after confirmation"
    assert dialog.system_actions_table.rowCount() >= 2
    assert "Screen Time" in dialog.system_actions_table.item(0, 0).text()

    dialog.close()
    app.processEvents()


def test_family_safety_recommendation_is_explainable_and_reviewable(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    settings = load_settings(db)
    answers = {
        "primary_user": "Child",
        "shared_device": "Shared by family",
        "alert_style": "High visibility",
        "bottom_right_alerts": "Yes",
        "device_monitoring": "Yes, alert for all new devices",
        "network_monitoring": "Yes, alert for DNS/gateway/VPN/new listeners",
        "admin_persistence_monitoring": "Yes, high visibility",
        "preserve_evidence": "Yes",
        "privacy_visibility": "Visibility-first",
        "government_hardening": "Yes, balanced recommendations",
        "auto_apply": "Preview only",
    }
    rec = FamilySafetyRecommendationEngine().recommend(answers, settings)

    assert rec.selected_profile.profile_id == "child_minor_safety"
    assert rec.confidence > 0
    assert rec.reasoning
    assert rec.proposed_changes
    assert rec.privacy_notes
    assert rec.standards_alignment
    assert rec.revert_plan
    assert any(change.expected_effect for change in rec.proposed_changes)
    assert all(change.setting_path and change.reason for change in rec.proposed_changes)
    assert all(change.apply_status == "pending" for change in rec.proposed_changes)
    assert any("does not claim compliance" in item or "Mapped to" in item for item in rec.standards_alignment)


def test_family_safety_apply_selected_changes_only_and_restore(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    settings = load_settings(db)
    settings.notification.bottom_right_alerts = False
    settings.event_categories.usb_monitoring_enabled = False
    settings.event_categories.network_activity_monitoring_enabled = False
    save_settings(db, settings)
    before = load_settings(db)

    answers = {"primary_user": "Security/admin workstation", "government_hardening": "Yes, NIST/CISA/NSA-style strict recommendations", "alert_style": "Strict / security-focused"}
    rec = FamilySafetyRecommendationEngine().recommend(answers, before)
    selected = [change.change_id for change in rec.proposed_changes if change.setting_path in {"notification.bottom_right_alerts", "event_categories.usb_monitoring_enabled"}]

    result = apply_family_safety_recommendation(rec, selected, db)
    after = load_settings(db)

    assert result["applied_changes"]
    assert result["settings_version_after"] == before.settings_version + 1
    assert after.notification.bottom_right_alerts is True
    assert after.event_categories.usb_monitoring_enabled is True
    assert after.event_categories.network_activity_monitoring_enabled is False
    assert result["settings_sync"]["status"] == "synced"
    assert result["skipped_changes"]
    assert not result["failed_changes"]

    preview = restore_family_safety_snapshot(db, preview_only=True)
    assert preview["status"] == "preview"
    restored = restore_family_safety_snapshot(db)
    final = load_settings(db)
    assert restored["status"] == "restored"
    assert final.notification.bottom_right_alerts is False
    assert final.event_categories.usb_monitoring_enabled is False
    assert final.event_categories.network_activity_monitoring_enabled is False


def test_family_safety_configuration_report_exports_required_sections(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    rec = FamilySafetyRecommendationEngine().recommend(
        {"primary_user": "Elder / at-risk user", "privacy_visibility": "Balanced", "auto_apply": "Preview only"},
        load_settings(db),
    )
    json_path = export_family_safety_configuration_json(rec, tmp_path / "config.json")
    md_path = export_family_safety_configuration_markdown(rec, tmp_path / "config.md")
    html_path = export_family_safety_configuration_html(rec, tmp_path / "config.html")
    word_path = export_family_safety_configuration_word(rec, tmp_path / "config.docx")
    excel_path = export_family_safety_configuration_excel(rec, tmp_path / "config.xlsx")
    payload = json_path.read_text(encoding="utf-8")
    markdown = md_path.read_text(encoding="utf-8")
    html = html_path.read_text(encoding="utf-8")
    assert "Family & Safety Configuration Report" in payload
    assert "User Answers" in markdown
    assert "Proposed Changes" in markdown
    assert "Manual Review Checklist" in markdown
    assert "macOS and MDM Setup Actions" in markdown
    assert "Standards Alignment" in markdown
    assert "Privacy Notes" in markdown
    assert "Revert Plan" in markdown
    assert "Family &amp; Safety Configuration Report" in html or "Family & Safety Configuration Report" in html
    assert word_path.exists()
    assert excel_path.exists()


def test_family_panel_exposes_html_word_and_excel_report_exports() -> None:
    app = QApplication.instance() or QApplication([])
    panel = FamilySafetyPanel()

    assert panel.export_html_button.text() == "Export HTML"
    assert panel.export_word_button.text() == "Export Word"
    assert panel.export_excel_button.text() == "Export Excel"
    panel.close()
    app.processEvents()


def test_family_panel_guided_setup_controls_and_status_card() -> None:
    app = QApplication.instance() or QApplication([])
    panel = FamilySafetyPanel()
    assert panel.guided_setup_button.text() == "Start Guided Setup"
    assert panel.configure_family_settings_button.text() == "Configure Family & Safety Settings"
    assert panel.restore_previous_settings_button.text() == "Restore Previous Settings"
    assert panel.guided_setup_button.toolTip()
    assert panel.configure_family_settings_button.toolTip()
    assert "MSAA applies local settings only" in panel.findChildren(QLabel)[1].text() or any("MSAA applies local settings only" in label.text() for label in panel.findChildren(QLabel))
    assert "Current Profile:" in panel.current_profile_label.text()
    panel.close()
    app.processEvents()


def test_family_safety_pre_uat_checks_are_registered() -> None:
    ids = {check.check_id for check in build_registry()}
    assert {
        "family_safety.wizard_questions",
        "family_safety.recommendation_engine",
        "family_safety.preview_required",
        "family_safety.apply_transaction",
        "family_safety.revert_snapshot",
        "family_safety.report_export",
        "family_safety.no_silent_changes",
        "family_safety.settings_sync_after_apply",
    }.issubset(ids)
