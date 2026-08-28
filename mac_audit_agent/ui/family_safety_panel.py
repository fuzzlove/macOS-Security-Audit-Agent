from __future__ import annotations

from typing import Any

from PySide6.QtCore import QUrl, Qt, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFrame,
    QGridLayout,
    QHeaderView,
    QHBoxLayout,
    QListWidget,
    QMessageBox,
    QLabel,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSplitter,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from mac_audit_agent.family_safety.categories import (
    FamilyCategoryViewState,
    canonical_family_safety_categories,
    new_view_state,
    reset_all_family_view_state,
    reset_category_view_state,
)
from mac_audit_agent.family_safety.apply_engine import (
    CURRENT_PROFILE_KEY,
    LAST_APPLY_REPORT_KEY,
    LAST_RUN_KEY,
    apply_family_safety_recommendation,
    restore_family_safety_snapshot,
)
from mac_audit_agent.family_safety.recommendation_engine import FamilySafetyRecommendationEngine
from mac_audit_agent.family_safety.system_setup import (
    build_family_system_setup_plan,
    execute_family_system_setup_handoff,
)
from mac_audit_agent.family_safety.reporting import (
    export_family_safety_configuration_excel,
    export_family_safety_configuration_html,
    export_family_safety_configuration_json,
    export_family_safety_configuration_markdown,
    export_family_safety_configuration_word,
)
from mac_audit_agent.family_safety.wizard_questions import canonical_family_safety_questions
from mac_audit_agent.monitor_settings import load_settings
from mac_audit_agent.ui.responsive_actions import ResponsiveActionRow


PROFILE_OPTIONS = [
    "Young Child",
    "Teen",
    "Adult",
    "Senior",
    "Shared Family Computer",
    "Special Needs User",
    "School Device",
    "Security Research Device",
    "Government Asset",
    "Doctor's Device",
    "Nurse's Workstation",
    "Health Device",
    "Lawyer's Device / Legal Asset",
]


DEVICE_ROLE_DEFAULTS: dict[str, dict[str, str]] = {
    "Young Child": {"primary_user": "Child", "shared_device": "Shared by family", "alert_style": "High visibility", "device_monitoring": "Yes, alert for all new devices", "network_monitoring": "Yes, alert for DNS/gateway/VPN/new listeners", "admin_persistence_monitoring": "Yes, high visibility", "privacy_visibility": "Balanced"},
    "Teen": {"primary_user": "Teen", "shared_device": "Shared by family", "alert_style": "Balanced alerts", "privacy_visibility": "Balanced"},
    "Adult": {"primary_user": "Adult / owner", "shared_device": "Private device", "alert_style": "Balanced alerts", "privacy_visibility": "Balanced"},
    "Senior": {"primary_user": "Elder / at-risk user", "alert_style": "High visibility", "privacy_visibility": "Balanced"},
    "Shared Family Computer": {"primary_user": "Shared family device", "shared_device": "Shared by family", "alert_style": "Balanced alerts"},
    "Special Needs User": {"primary_user": "Adult / owner", "alert_style": "Important alerts only", "privacy_visibility": "Privacy-first"},
    "School Device": {"primary_user": "School/student device", "shared_device": "Shared by school/work", "alert_style": "Balanced alerts"},
    "Security Research Device": {"primary_user": "Security research device", "alert_style": "Strict / security-focused", "privacy_visibility": "Visibility-first"},
    "Government Asset": {"primary_user": "Government asset", "shared_device": "Shared by school/work", "alert_style": "Strict / security-focused", "government_hardening": "Yes, NIST/CISA/NSA-style strict recommendations", "privacy_visibility": "Visibility-first"},
    "Doctor's Device": {"primary_user": "Doctor / clinician device", "alert_style": "High visibility", "privacy_visibility": "Privacy-first"},
    "Nurse's Workstation": {"primary_user": "Nurse workstation", "shared_device": "Shared by school/work", "alert_style": "High visibility", "privacy_visibility": "Privacy-first"},
    "Health Device": {"primary_user": "Health device", "alert_style": "High visibility", "privacy_visibility": "Privacy-first"},
    "Lawyer's Device / Legal Asset": {"primary_user": "Lawyer / legal asset", "alert_style": "High visibility", "privacy_visibility": "Privacy-first"},
}


def _make_table(headers: list[str]) -> QTableWidget:
    table = QTableWidget(0, len(headers))
    table.setHorizontalHeaderLabels(headers)
    table.setSelectionBehavior(QAbstractItemView.SelectRows)
    table.setSelectionMode(QAbstractItemView.SingleSelection)
    table.setEditTriggers(QAbstractItemView.NoEditTriggers)
    table.setAlternatingRowColors(True)
    table.setWordWrap(True)
    table.verticalHeader().setVisible(False)
    table.verticalHeader().setMinimumSectionSize(32)
    table.horizontalHeader().setStretchLastSection(True)
    table.horizontalHeader().setMinimumSectionSize(96)
    table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
    if headers:
        table.horizontalHeader().setSectionResizeMode(len(headers) - 1, QHeaderView.Stretch)
    table.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
    table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
    return table


def make_family_button(text: str, tooltip: str, style: str = "secondary", min_width: int | None = None) -> QPushButton:
    button = QPushButton(text)
    button.setToolTip(tooltip)
    button.setAccessibleName(text)
    button.setCursor(Qt.PointingHandCursor)
    button.setMinimumHeight(38)
    text_width = button.fontMetrics().horizontalAdvance(text)
    button.setMinimumWidth(max(120, min_width or 0, text_width + 32))
    button.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
    if style == "primary":
        button.setProperty("role", "primary")
    return button


def _scroll_page(widget: QWidget, *, min_width: int = 0) -> QScrollArea:
    scroll = QScrollArea()
    scroll.setWidgetResizable(True)
    scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
    scroll.setFrameShape(QFrame.NoFrame)
    scroll.setMinimumWidth(min_width)
    scroll.setWidget(widget)
    return scroll


class FamilySafetyWizardDialog(QDialog):
    def __init__(self, db: Any, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.db = db
        self.questions = canonical_family_safety_questions()
        self.answers: dict[str, str] = {question.question_id: question.default_option for question in self.questions}
        self.recommendation = None
        self.system_actions = []
        self.apply_result: dict[str, Any] = {}
        self.setWindowTitle("Family & Safety Configuration Wizard")
        self.resize(980, 720)
        layout = QVBoxLayout(self)
        title = QLabel("Family & Safety Configuration Wizard")
        title.setStyleSheet("font-size: 22px; font-weight: 700;")
        layout.addWidget(title)
        guardrail = QLabel(
            "After final confirmation, MSAA applies supported local settings automatically and opens the first Apple-protected setting that needs owner, guardian, or administrator approval. "
            "It does not upload device information or edit protected Screen Time databases."
        )
        guardrail.setWordWrap(True)
        guardrail.setStyleSheet("color: #D6E4FF; font-weight: 600;")
        layout.addWidget(guardrail)
        self.stack = QStackedWidget()
        self.question_widgets: dict[str, QComboBox] = {}
        self._question_page = self._build_question_page()
        self._preview_page = self._build_preview_page()
        self.stack.addWidget(self._question_page)
        self.stack.addWidget(self._preview_page)
        layout.addWidget(self.stack, 1)
        self.wizard_navigation_actions = ResponsiveActionRow(spacing=10)
        self.back_button = make_family_button("Back to Questions", "Return to questions and revise answers.", min_width=170)
        self.back_button.clicked.connect(lambda: self.stack.setCurrentWidget(self._question_page))
        self.preview_button = make_family_button("Review Recommendation", "Generate and preview recommended changes before applying.", "primary", min_width=190)
        self.preview_button.clicked.connect(self.generate_preview)
        self.close_button = make_family_button("Cancel", "Close the wizard without applying settings.", min_width=120)
        self.close_button.clicked.connect(self.reject)
        self.wizard_navigation_actions.add_buttons([self.back_button, self.preview_button, self.close_button])
        layout.addWidget(self.wizard_navigation_actions)

    def _build_question_page(self) -> QWidget:
        page = QWidget()
        outer = QVBoxLayout(page)
        intro = QLabel(
            "Fast setup: choose how this Mac will be used and MSAA will fill the recommended profile immediately. "
            "You can then review or fine-tune every setting before the one final apply confirmation."
        )
        intro.setWordWrap(True)
        outer.addWidget(intro)
        role_frame = QFrame()
        role_frame.setProperty("themeCard", True)
        role_layout = QHBoxLayout(role_frame)
        role_label = QLabel("This Mac is a:")
        role_label.setStyleSheet("font-weight: 700;")
        self.device_role_combo = QComboBox()
        self.device_role_combo.setAccessibleName("Select the Family and Safety device role")
        self.device_role_combo.addItem("Choose a device role…", "")
        for option in PROFILE_OPTIONS:
            self.device_role_combo.addItem(option, option)
        self.device_role_combo.setMinimumWidth(280)
        self.device_role_status = QLabel("Selecting a role builds the profile; nothing changes until final confirmation.")
        self.device_role_status.setWordWrap(True)
        self.device_role_status.setProperty("textRole", "muted")
        role_layout.addWidget(role_label)
        role_layout.addWidget(self.device_role_combo)
        role_layout.addWidget(self.device_role_status, 1)
        outer.addWidget(role_frame)
        form = QWidget()
        grid = QGridLayout(form)
        grid.setContentsMargins(4, 4, 4, 4)
        grid.setHorizontalSpacing(14)
        grid.setVerticalSpacing(10)
        grid.setColumnStretch(0, 2)
        grid.setColumnStretch(1, 1)
        grid.setColumnStretch(2, 2)
        for row, question in enumerate(self.questions):
            prompt = QLabel(question.prompt)
            prompt.setWordWrap(True)
            prompt.setToolTip(question.help_text)
            combo = QComboBox()
            combo.addItems(question.options)
            combo.setCurrentText(question.default_option)
            combo.setToolTip(question.help_text + (f"\nPrivacy: {question.privacy_note}" if question.privacy_note else ""))
            self.question_widgets[question.question_id] = combo
            help_label = QLabel(question.help_text)
            help_label.setWordWrap(True)
            help_label.setStyleSheet("color: #9DB0C9;")
            grid.addWidget(prompt, row, 0)
            grid.addWidget(combo, row, 1)
            grid.addWidget(help_label, row, 2)
        scroll = _scroll_page(form, min_width=560)
        outer.addWidget(scroll, 1)
        self.device_role_combo.currentIndexChanged.connect(self._device_role_selected)
        return page

    def _device_role_selected(self, _index: int = -1) -> None:
        role = str(self.device_role_combo.currentData() or "")
        if not role:
            return
        defaults = {
            "preserve_evidence": "Yes",
            "bottom_right_alerts": "Yes",
            "device_monitoring": "Yes, alert only for unknown/high-risk devices",
            "network_monitoring": "Yes, alert only for suspicious changes",
            "admin_persistence_monitoring": "Yes, important alerts only",
            "government_hardening": "No, family-only recommendations",
            "auto_apply": "Apply after confirmation",
            **DEVICE_ROLE_DEFAULTS.get(role, {}),
        }
        for question_id, value in defaults.items():
            combo = self.question_widgets.get(question_id)
            if combo is not None and combo.findText(value) >= 0:
                combo.setCurrentText(value)
        self.device_role_status.setText(f"{role} defaults loaded. Review the generated profile and confirm once to apply supported changes.")
        self.generate_preview()

    def _build_preview_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        review_title = QLabel("Review Recommended Family & Safety Configuration")
        review_title.setStyleSheet("font-size: 18px; font-weight: 700;")
        layout.addWidget(review_title)
        self.profile_summary = QTextEdit()
        self.profile_summary.setReadOnly(True)
        self.profile_summary.setMinimumHeight(170)
        self.profile_summary.setLineWrapMode(QTextEdit.WidgetWidth)
        layout.addWidget(self.profile_summary)
        self.changes_table = QTableWidget(0, 8)
        self.changes_table.setHorizontalHeaderLabels(["Category", "Setting", "Current", "Recommended", "Expected Effect", "Alert Noise", "Requires Restart", "Apply?"])
        self.changes_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.changes_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.changes_table.verticalHeader().setVisible(False)
        self.changes_table.setWordWrap(True)
        layout.addWidget(self.changes_table, 1)
        system_title = QLabel("macOS Setup Actions")
        system_title.setStyleSheet("font-size: 15px; font-weight: 700;")
        system_help = QLabel(
            "AUTOMATIC applies inside MSAA after confirmation. USER APPROVAL REQUIRED opens the relevant Apple setting because MSAA cannot bypass owner/guardian approval. MDM REQUIRED identifies organization-managed policy."
        )
        system_help.setWordWrap(True)
        system_help.setProperty("textRole", "muted")
        self.system_actions_table = QTableWidget(0, 5)
        self.system_actions_table.setHorizontalHeaderLabels(["macOS Control", "Desired State", "Automation", "Why", "Verification"])
        self.system_actions_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.system_actions_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.system_actions_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.system_actions_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.system_actions_table.verticalHeader().setVisible(False)
        self.system_actions_table.setWordWrap(True)
        self.system_actions_table.setMinimumHeight(180)
        layout.addWidget(system_title)
        layout.addWidget(system_help)
        layout.addWidget(self.system_actions_table)
        self.preview_actions = ResponsiveActionRow(spacing=10)
        self.select_all_button = make_family_button("Select all", "Select every proposed setting change for apply.", min_width=120)
        self.select_all_button.clicked.connect(lambda: self._set_all_checks(True))
        self.deselect_all_button = make_family_button("Deselect all", "Deselect every proposed setting change.", min_width=120)
        self.deselect_all_button.clicked.connect(lambda: self._set_all_checks(False))
        self.apply_selected_button = make_family_button("Apply selected changes", "Apply only checked changes after explicit confirmation.", "primary", min_width=190)
        self.apply_selected_button.clicked.connect(self.apply_selected_changes)
        self.save_draft_button = make_family_button("Save as draft", "Save the recommendation locally without applying changes.", min_width=140)
        self.save_draft_button.clicked.connect(self.save_draft)
        self.export_report_button = make_family_button("Export recommendation report", "Export a local report without applying settings.", min_width=230)
        self.export_report_button.clicked.connect(self.export_report)
        self.preview_actions.add_buttons(
            [
                self.select_all_button,
                self.deselect_all_button,
                self.apply_selected_button,
                self.save_draft_button,
                self.export_report_button,
            ]
        )
        layout.addWidget(self.preview_actions)
        self.preview_notes = QTextEdit()
        self.preview_notes.setReadOnly(True)
        self.preview_notes.setMinimumHeight(160)
        self.preview_notes.setLineWrapMode(QTextEdit.WidgetWidth)
        layout.addWidget(self.preview_notes)
        return page

    def generate_preview(self) -> None:
        self.answers = {question_id: widget.currentText() for question_id, widget in self.question_widgets.items()}
        settings = load_settings(self.db)
        engine = FamilySafetyRecommendationEngine()
        self.recommendation = engine.recommend(
            self.answers,
            settings,
            current_monitor_mode=settings.installation.monitor_mode,
            current_user_account_type="local account",
            available_permissions=[],
            existing_family_settings={},
            existing_alert_configuration=settings.alerting.__dict__.copy(),
        )
        self.system_actions = build_family_system_setup_plan(self.recommendation.selected_profile.profile_id)
        self._render_preview()
        self.stack.setCurrentWidget(self._preview_page)

    def _render_preview(self) -> None:
        if self.recommendation is None:
            return
        rec = self.recommendation
        profile = rec.selected_profile
        self.profile_summary.setPlainText(
            "\n\n".join(
                [
                    f"Recommended Profile: {profile.display_name}",
                    profile.description,
                    "Why This Profile Was Selected:\n- " + "\n- ".join(rec.reasoning),
                    "Expected Alerts:\n- " + "\n- ".join(profile.expected_behavior),
                    "Privacy Notes:\n- " + "\n- ".join(rec.privacy_notes),
                    "Manual Review Items:\n- " + "\n- ".join(rec.manual_review_items),
                    "Revert Plan:\n- " + "\n- ".join(rec.revert_plan),
                ]
            )
        )
        self.changes_table.setRowCount(0)
        for row, change in enumerate(rec.proposed_changes):
            self.changes_table.insertRow(row)
            values = [
                change.category,
                change.setting_path,
                str(change.current_value),
                str(change.proposed_value),
                change.expected_effect,
                change.alert_noise_impact,
                "yes" if change.requires_restart else "no",
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                self.changes_table.setItem(row, column, item)
            box = QCheckBox()
            box.setChecked(True)
            box.setToolTip("Apply this individual change if you confirm.")
            self.changes_table.setCellWidget(row, 7, box)
        self.changes_table.resizeRowsToContents()
        self.system_actions_table.setRowCount(0)
        for row, action in enumerate(self.system_actions):
            self.system_actions_table.insertRow(row)
            values = [action.title, action.desired_state, action.automation.replace("_", " "), action.reason, action.verification]
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                item.setToolTip(str(value))
                self.system_actions_table.setItem(row, column, item)
        self.system_actions_table.resizeRowsToContents()
        self.preview_notes.setPlainText(
            "\n".join(
                [
                    "Warnings:",
                    *[f"- {item}" for item in rec.warnings],
                    "",
                    "Standards Alignment:",
                    *[f"- {item}" for item in rec.standards_alignment],
                    "",
                    "Unchanged Settings:",
                    *[f"- {item.setting_path}: already {item.current_value}" for item in rec.unchanged_settings[:12]],
                ]
            )
        )

    def _set_all_checks(self, checked: bool) -> None:
        for row in range(self.changes_table.rowCount()):
            widget = self.changes_table.cellWidget(row, 7)
            if isinstance(widget, QCheckBox):
                widget.setChecked(checked)

    def _selected_change_ids(self) -> list[str]:
        if self.recommendation is None:
            return []
        ids: list[str] = []
        for row, change in enumerate(self.recommendation.proposed_changes):
            widget = self.changes_table.cellWidget(row, 7)
            if isinstance(widget, QCheckBox) and widget.isChecked():
                ids.append(change.change_id)
        return ids

    def apply_selected_changes(self) -> None:
        if self.recommendation is None:
            return
        selected = self._selected_change_ids()
        if not selected:
            QMessageBox.information(self, "No Changes Selected", "Select at least one proposed change to apply.")
            return
        result = QMessageBox.question(
            self,
            "Apply Selected Family Safety Settings",
            "Apply the selected MSAA settings now and continue to the first required Apple setting? A pre-change snapshot will be created first. "
            "Apple-protected controls still require owner, guardian, administrator, or MDM approval; MSAA will not bypass that approval.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if result != QMessageBox.Yes:
            return
        self.apply_result = apply_family_safety_recommendation(self.recommendation, selected, self.db)
        system_results = execute_family_system_setup_handoff(
            self.system_actions,
            opener=lambda url: QDesktopServices.openUrl(QUrl(url)),
            max_opened=1,
        )
        self.apply_result["system_setup_actions"] = system_results
        regenerated_reports = {}
        for format_name, exporter in {
            "json": export_family_safety_configuration_json,
            "markdown": export_family_safety_configuration_markdown,
            "html": export_family_safety_configuration_html,
            "docx": export_family_safety_configuration_word,
            "xlsx": export_family_safety_configuration_excel,
        }.items():
            try:
                regenerated_reports[format_name] = str(exporter(self.recommendation, apply_result=self.apply_result))
            except Exception as exc:
                self.apply_result.setdefault("report_export_errors", {})[format_name] = f"{type(exc).__name__}: {exc}"
        self.apply_result["generated_reports"] = regenerated_reports
        self.db.set_background_monitor_state(LAST_APPLY_REPORT_KEY, __import__("json").dumps(self.apply_result, sort_keys=True, default=str))
        opened = sum(item.get("status") == "OPENED_FOR_USER_APPROVAL" for item in system_results)
        mdm = sum(item.get("status") == "MDM_REQUIRED" for item in system_results)
        QMessageBox.information(
            self,
            "Family Safety Setup Applied",
            f"Applied {len(self.apply_result.get('applied_changes', []))} supported changes. Settings version: {self.apply_result.get('settings_version_after')}.\n\n"
            f"Apple settings opened for approval: {opened}\nMDM-dependent actions: {mdm}\n\n"
            "No Apple-protected control is reported as changed until a later audit verifies it.",
        )
        self.accept()

    def save_draft(self) -> None:
        if self.recommendation is None:
            return
        self.db.set_background_monitor_state("family_safety_draft_recommendation_json", __import__("json").dumps(self.recommendation.to_dict(), sort_keys=True, default=str))
        QMessageBox.information(self, "Draft Saved", "Family & Safety recommendation draft saved locally. No settings were applied.")

    def export_report(self) -> None:
        if self.recommendation is None:
            return
        paths = {
            "json": export_family_safety_configuration_json(self.recommendation),
            "markdown": export_family_safety_configuration_markdown(self.recommendation),
            "html": export_family_safety_configuration_html(self.recommendation),
            "docx": export_family_safety_configuration_word(self.recommendation),
            "xlsx": export_family_safety_configuration_excel(self.recommendation),
        }
        QMessageBox.information(self, "Recommendation Report Exported", "Saved local reports:\n" + "\n".join(str(path) for path in paths.values()))


class FamilySafetyPanel(QFrame):
    audit_requested = Signal(str)
    export_html_requested = Signal()
    export_word_requested = Signal()
    export_excel_requested = Signal()
    export_json_requested = Signal()

    def __init__(self, parent: QWidget | None = None, db: Any | None = None) -> None:
        super().__init__(parent)
        self.db = db
        self.setObjectName("familySafetyPanel")
        self.setFrameShape(QFrame.StyledPanel)
        self.setMinimumSize(640, 560)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self._report: dict[str, Any] = {}
        self._categories = {category.category_id: category for category in canonical_family_safety_categories()}
        self._category_order = [category.category_id for category in canonical_family_safety_categories()]
        self._view_state: dict[str, FamilyCategoryViewState] = reset_all_family_view_state()
        self._active_category_id = self._category_order[0]
        self._build_ui()
        self.set_report({})

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        privacy = QLabel("Privacy-first: no messages, screenshots, keystrokes, browsing history, microphone data, camera data, or uploads.")
        privacy.setWordWrap(True)
        privacy.setStyleSheet("color: #D6E4FF; font-weight: 600;")
        layout.addWidget(privacy)

        setup_frame = QFrame()
        setup_frame.setProperty("themeCard", True)
        setup_layout = QGridLayout(setup_frame)
        setup_layout.setContentsMargins(12, 12, 12, 12)
        setup_layout.setSpacing(8)
        setup_title = QLabel("Guided Family Safety Setup")
        setup_title.setStyleSheet("font-size: 18px; font-weight: 700;")
        setup_desc = QLabel("Answer a few questions and MSAA will recommend a safety configuration. You can preview, apply, export, or manually adjust every setting.")
        setup_desc.setWordWrap(True)
        consent = QLabel("MSAA applies local settings only. The wizard does not send answers, reports, or device information to external services.")
        consent.setWordWrap(True)
        consent.setStyleSheet("color: #D6E4FF; font-weight: 600;")
        self.guided_setup_button = make_family_button("Start Guided Setup", "Start a guided setup wizard that recommends and applies Family & Safety Center settings based on user needs.", "primary", min_width=170)
        self.guided_setup_button.setObjectName("startGuidedFamilySafetySetupButton")
        self.guided_setup_button.clicked.connect(self.open_configuration_wizard)
        self.configure_family_settings_button = make_family_button("Configure Family & Safety Settings", "Start a guided setup wizard that recommends and applies Family & Safety Center settings based on user needs.", "primary", min_width=240)
        self.configure_family_settings_button.setObjectName("configureFamilySafetySettingsButton")
        self.configure_family_settings_button.clicked.connect(self.open_configuration_wizard)
        self.view_current_profile_button = make_family_button("View Current Profile", "Show the current Family & Safety Center profile and last wizard status.", min_width=170)
        self.view_current_profile_button.clicked.connect(self.show_current_profile)
        self.export_current_family_report_button = make_family_button("Export Current Family Safety Report", "Export the most recent Family & Safety configuration report for manual review.", min_width=260)
        self.export_current_family_report_button.clicked.connect(self.export_current_configuration_report)
        self.restore_previous_settings_button = make_family_button("Restore Previous Settings", "Preview and restore the previous wizard-applied Family & Safety settings where supported.", min_width=220)
        self.restore_previous_settings_button.clicked.connect(self.restore_previous_settings)
        setup_layout.addWidget(setup_title, 0, 0, 1, 4)
        setup_layout.addWidget(setup_desc, 1, 0, 1, 4)
        setup_layout.addWidget(consent, 2, 0, 1, 4)
        self.setup_actions = ResponsiveActionRow(spacing=10)
        self.setup_actions.add_buttons(
            [
                self.guided_setup_button,
                self.configure_family_settings_button,
                self.view_current_profile_button,
                self.export_current_family_report_button,
                self.restore_previous_settings_button,
            ]
        )
        setup_layout.addWidget(self.setup_actions, 3, 0, 1, 4)
        layout.addWidget(setup_frame)

        self.wizard_status_frame = QFrame()
        self.wizard_status_frame.setProperty("themeCard", True)
        status_layout = QGridLayout(self.wizard_status_frame)
        status_layout.setContentsMargins(12, 12, 12, 12)
        self.current_profile_label = QLabel("Current Profile: not configured")
        self.last_wizard_run_label = QLabel("Last Wizard Run: not yet")
        self.last_applied_changes_label = QLabel("Last Applied Changes: none")
        self.settings_sync_status_label = QLabel("Settings Sync Status: unknown")
        self.manual_review_needed_label = QLabel("Manual Review Needed: run the wizard or audit to see checklist items")
        for row, label in enumerate([self.current_profile_label, self.last_wizard_run_label, self.last_applied_changes_label, self.settings_sync_status_label, self.manual_review_needed_label]):
            label.setWordWrap(True)
            status_layout.addWidget(label, row, 0)
        layout.addWidget(self.wizard_status_frame)

        audit_frame = QFrame()
        audit_frame.setProperty("themeCard", True)
        audit_layout = QGridLayout(audit_frame)
        audit_layout.setContentsMargins(12, 12, 12, 12)
        audit_layout.setHorizontalSpacing(10)
        audit_layout.setVerticalSpacing(10)
        audit_title = QLabel("Safety Audit & Reports")
        audit_title.setStyleSheet("font-size: 17px; font-weight: 700;")
        audit_layout.addWidget(audit_title, 0, 0, 1, 3)
        profile_label = QLabel("Who uses this Mac?")
        audit_layout.addWidget(profile_label, 1, 0)
        self.profile_combo = QComboBox()
        self.profile_combo.addItems(PROFILE_OPTIONS)
        self.profile_combo.setMinimumHeight(38)
        self.profile_combo.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        audit_layout.addWidget(self.profile_combo, 1, 1)
        self.audit_button = make_family_button("Run Safety Audit", "Run a local Family & Safety audit for the selected user profile.", "primary")
        self.audit_button.clicked.connect(lambda: self.audit_requested.emit(self.profile_combo.currentText()))
        audit_layout.addWidget(self.audit_button, 1, 2)
        self.export_html_button = make_family_button("Export HTML", "Export a local Family & Safety HTML report.", min_width=124)
        self.export_html_button.clicked.connect(self.export_html_requested.emit)
        self.export_word_button = make_family_button("Export Word", "Export a macro-free Family & Safety Word report.", min_width=124)
        self.export_word_button.clicked.connect(self.export_word_requested.emit)
        self.export_excel_button = make_family_button("Export Excel", "Export a formula-free Family & Safety Excel workbook.", min_width=124)
        self.export_excel_button.clicked.connect(self.export_excel_requested.emit)
        self.export_json_button = make_family_button("Export JSON", "Export a local Family & Safety JSON report.", min_width=124)
        self.export_json_button.clicked.connect(self.export_json_requested.emit)
        self.report_actions = ResponsiveActionRow(spacing=10)
        self.report_actions.add_buttons(
            [self.export_html_button, self.export_word_button, self.export_excel_button, self.export_json_button]
        )
        audit_layout.addWidget(self.report_actions, 2, 0, 1, 3)
        audit_layout.setColumnStretch(1, 1)
        layout.addWidget(audit_frame)

        score_frame = QFrame()
        score_frame.setProperty("themeCard", True)
        score_layout = QGridLayout(score_frame)
        score_layout.setContentsMargins(12, 12, 12, 12)
        self.score_label = QLabel("Safety Score: --")
        self.score_label.setStyleSheet("font-size: 24px; font-weight: 700;")
        self.score_bar = QProgressBar()
        self.score_bar.setRange(0, 100)
        self.score_bar.setValue(0)
        self.improvements_label = QLabel("Recommended improvements will appear after an audit.")
        self.improvements_label.setWordWrap(True)
        self.completed_label = QLabel("Completed actions will appear after an audit.")
        self.completed_label.setWordWrap(True)
        score_layout.addWidget(self.score_label, 0, 0)
        score_layout.addWidget(self.score_bar, 0, 1)
        score_layout.addWidget(self.improvements_label, 1, 0, 1, 2)
        score_layout.addWidget(self.completed_label, 2, 0, 1, 2)
        layout.addWidget(score_frame)

        self.tabs = QTabWidget()
        self.category_list = QListWidget()
        self.category_list.setMinimumWidth(180)
        self.category_list.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)
        for category_id in self._category_order:
            self.category_list.addItem(self._categories[category_id].title)
            self.category_list.item(self.category_list.count() - 1).setToolTip(self._categories[category_id].short_description)
        self.category_list.currentRowChanged.connect(self._switch_category_by_row)
        self.category_title_label = QLabel()
        self.category_title_label.setStyleSheet("font-size: 20px; font-weight: 700; color: #F0F6FC;")
        self.category_title_label.setWordWrap(True)
        self.category_title_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
        self.category_context_label = QLabel()
        self.category_context_label.setWordWrap(True)
        self.category_status_label = QLabel()
        self.category_status_label.setWordWrap(True)
        self.category_description_view = QTextEdit()
        self.category_description_view.setReadOnly(True)
        self.category_description_view.setMinimumHeight(220)
        self.category_description_view.setLineWrapMode(QTextEdit.WidgetWidth)
        self.category_checklist_table = _make_table(["Checklist Item", "Status", "Recommended Change"])
        self.category_checklist_table.setMinimumHeight(260)
        self.category_checklist_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.category_checklist_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.category_checklist_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.category_changes_view = QTextEdit()
        self.category_changes_view.setReadOnly(True)
        self.category_changes_view.setMinimumHeight(160)
        self.category_changes_view.setLineWrapMode(QTextEdit.WidgetWidth)
        self.category_selected_device_label = QLabel("No item selected")
        self.category_selected_device_label.setWordWrap(True)
        self.category_pending_label = QLabel("Pending changes: none")
        self.category_pending_label.setWordWrap(True)
        self.reset_view_button = make_family_button("Reset This Category View", "Clear filters and selected checklist/device state for this category only.")
        self.reset_view_button.clicked.connect(self.reset_current_category_view_state)
        self.reset_pending_button = make_family_button("Reset Pending Changes", "Discard unsaved pending changes for the current category only.")
        self.reset_pending_button.clicked.connect(self.reset_current_category_pending_changes)
        self.reset_defaults_button = make_family_button("Reset Category to Recommended Defaults", "Restore the recommended checklist defaults for this category only.", min_width=260)
        self.reset_defaults_button.clicked.connect(self.reset_current_category_to_recommended_defaults)
        self.previous_category_button = make_family_button("Previous Category", "Move to the previous Family & Safety category.", min_width=150)
        self.previous_category_button.clicked.connect(self.previous_category)
        self.next_category_button = make_family_button("Next Category", "Move to the next Family & Safety category.", min_width=130)
        self.next_category_button.clicked.connect(self.next_category)
        self.overview_category_button = make_family_button("Back to Category Overview", "Return focus to the category navigation list.", min_width=210)
        self.overview_category_button.clicked.connect(lambda: self.category_list.setFocus())
        self._add_category_tab()
        self.category_list.setCurrentRow(0)
        self.audit_table = _make_table(["Category", "Check", "Status", "Plain-language guidance"])
        self.checklist_table = _make_table(["Checklist Item", "Status", "Next Step"])
        self.accessibility_table = _make_table(["Accessibility Item", "Status", "Guidance"])
        self.safe_browsing_table = _make_table(["Protection", "Status", "Guidance"])
        self.app_review_table = _make_table(["App", "Status", "Guidance", "Evidence"])
        self.education_view = QTextEdit()
        self.education_view.setReadOnly(True)
        self.wizard_view = QTextEdit()
        self.wizard_view.setReadOnly(True)
        self.caregiver_view = QTextEdit()
        self.caregiver_view.setReadOnly(True)
        self._add_table_tab(self.audit_table, "Safety Audit")
        self._add_table_tab(self.checklist_table, "Parent Checklist")
        self._add_table_tab(self.accessibility_table, "Accessibility")
        self._add_table_tab(self.safe_browsing_table, "Safe Browsing")
        self._add_text_tab(self.wizard_view, "Wizard")
        self._add_table_tab(self.app_review_table, "Apps")
        self._add_text_tab(self.caregiver_view, "Caregiver")
        self._add_text_tab(self.education_view, "Guidance")
        layout.addWidget(self.tabs, 1)
        self._render_active_category()
        self.refresh_wizard_status()

    def _add_category_tab(self) -> None:
        page = QWidget()
        page_layout = QHBoxLayout(page)
        page_layout.setContentsMargins(6, 6, 6, 6)
        page_layout.setSpacing(10)
        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)
        splitter.setHandleWidth(8)
        splitter.addWidget(self.category_list)
        detail = QFrame()
        detail.setProperty("themeCard", True)
        detail.setMinimumWidth(420)
        detail.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        detail_layout = QVBoxLayout(detail)
        detail_layout.setContentsMargins(14, 14, 14, 14)
        detail_layout.setSpacing(8)
        self.category_navigation_actions = ResponsiveActionRow(spacing=10)
        self.category_navigation_actions.add_buttons(
            [self.previous_category_button, self.next_category_button, self.overview_category_button]
        )
        self.category_reset_actions = ResponsiveActionRow(spacing=10)
        self.category_reset_actions.add_buttons(
            [self.reset_view_button, self.reset_pending_button, self.reset_defaults_button]
        )
        detail_layout.addWidget(self.category_title_label)
        detail_layout.addWidget(self.category_context_label)
        detail_layout.addWidget(self.category_status_label)
        detail_layout.addWidget(self.category_description_view, 2)
        checklist_label = QLabel("Checklist")
        checklist_label.setStyleSheet("font-weight: 700;")
        detail_layout.addWidget(checklist_label)
        detail_layout.addWidget(self.category_checklist_table, 2)
        changes_label = QLabel("Your Changes")
        changes_label.setStyleSheet("font-weight: 700;")
        detail_layout.addWidget(changes_label)
        detail_layout.addWidget(self.category_selected_device_label)
        detail_layout.addWidget(self.category_pending_label)
        detail_layout.addWidget(self.category_changes_view, 1)
        detail_layout.addWidget(self.category_reset_actions)
        detail_layout.addWidget(self.category_navigation_actions)
        self.category_detail_scroll = _scroll_page(detail, min_width=420)
        splitter.addWidget(self.category_detail_scroll)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([220, 760])
        self.category_splitter = splitter
        page_layout.addWidget(splitter, 1)
        self.tabs.addTab(page, "Category Guide")

    def _add_table_tab(self, table: QTableWidget, title: str) -> None:
        page = QWidget()
        page_layout = QVBoxLayout(page)
        page_layout.setContentsMargins(6, 6, 6, 6)
        page_layout.addWidget(table)
        self.tabs.addTab(page, title)

    def _add_text_tab(self, text: QTextEdit, title: str) -> None:
        text.setLineWrapMode(QTextEdit.WidgetWidth)
        text.setMinimumHeight(360)
        page = QWidget()
        page_layout = QVBoxLayout(page)
        page_layout.setContentsMargins(6, 6, 6, 6)
        page_layout.addWidget(text)
        self.tabs.addTab(page, title)

    def set_report(self, report: dict[str, Any]) -> None:
        self._report = report or {}
        self._load_report_categories()
        score = self._report.get("score", {}) if isinstance(self._report.get("score", {}), dict) else {}
        score_value = int(score.get("score", 0) or 0)
        self.score_label.setText(f"Safety Score: {score_value if self._report else '--'}")
        self.score_bar.setValue(score_value)
        improvements = list(score.get("recommended_improvements", []))[:5]
        completed = list(score.get("completed_actions", []))[:5]
        self.improvements_label.setText("Recommended Improvements: " + ("; ".join(improvements) if improvements else "Run an audit to see next steps."))
        self.completed_label.setText("Completed Actions: " + ("; ".join(completed) if completed else "Run an audit to see configured protections."))
        self._set_rows(self.audit_table, list(self._report.get("findings", [])), ["category", "title", "status", "recommendation"])
        self._set_rows(self.checklist_table, list(self._report.get("parent_checklist", [])), ["title", "status", "recommendation"])
        self._set_rows(self.accessibility_table, list(self._report.get("accessibility_checklist", [])), ["title", "status", "recommendation"])
        self._set_rows(self.safe_browsing_table, list(self._report.get("safe_browsing_status", [])), ["title", "status", "recommendation"])
        self._set_rows(self.app_review_table, list(self._report.get("app_review", [])), ["title", "status", "recommendation", "evidence"])
        self.wizard_view.setPlainText(self._wizard_text())
        self.caregiver_view.setPlainText(self._caregiver_text())
        self.education_view.setPlainText(self._education_text())
        self._render_active_category()

    def _load_report_categories(self) -> None:
        raw_categories = self._report.get("category_definitions", []) if isinstance(self._report, dict) else []
        if not raw_categories:
            return
        for raw in raw_categories:
            if not isinstance(raw, dict):
                continue
            category_id = str(raw.get("category_id", ""))
            if category_id in self._categories:
                category = self._categories[category_id]
                category.current_status = str(raw.get("current_status", category.current_status))
                category.pending_changes = list(raw.get("pending_changes", []))
                category.last_reviewed_at = str(raw.get("last_reviewed_at", category.last_reviewed_at))

    def _switch_category_by_row(self, row: int) -> None:
        if row < 0 or row >= len(self._category_order):
            return
        next_category_id = self._category_order[row]
        if next_category_id == self._active_category_id:
            self._render_active_category()
            return
        current_state = self._view_state[self._active_category_id]
        if current_state.pending_changes:
            result = QMessageBox.question(
                self,
                "Unsaved Category Changes",
                f"You have unsaved changes in {self._categories[self._active_category_id].title}. Save, discard, or cancel?",
                QMessageBox.Save | QMessageBox.Discard | QMessageBox.Cancel,
                QMessageBox.Cancel,
            )
            if result == QMessageBox.Cancel:
                self.category_list.blockSignals(True)
                self.category_list.setCurrentRow(self._category_order.index(self._active_category_id))
                self.category_list.blockSignals(False)
                return
            if result == QMessageBox.Discard:
                current_state.pending_changes.clear()
            if result == QMessageBox.Save:
                self._categories[self._active_category_id].pending_changes = list(current_state.pending_changes)
                current_state.pending_changes.clear()
        self._active_category_id = next_category_id
        next_state = self._view_state[next_category_id]
        next_state.last_opened = self._timestamp()
        self._clear_invalid_selection(next_state)
        self._render_active_category()

    def _clear_invalid_selection(self, state: FamilyCategoryViewState) -> None:
        if state.category_id != "device_physical_access_safety":
            state.selected_device_id = ""
        category = self._categories[state.category_id]
        if state.selected_checklist_item and state.selected_checklist_item not in category.checklist_items:
            state.selected_checklist_item = ""

    def _render_active_category(self) -> None:
        category = self._categories[self._active_category_id]
        state = self._view_state[self._active_category_id]
        score = self._category_score(category.category_id)
        self.category_title_label.setText(category.title)
        self.category_context_label.setText(f"Currently viewing: {category.title} | Category ID: {category.category_id}")
        self.category_status_label.setText(
            f"Status: {category.current_status} | Score: {score}/100 | Last reviewed: {category.last_reviewed_at or 'not reviewed yet'}"
        )
        self.category_description_view.setPlainText(
            "\n\n".join(
                [
                    category.short_description,
                    category.detailed_description,
                    f"Who this helps: {category.who_it_helps}",
                    f"Why this matters: {category.why_it_matters}",
                    "What to check:\n- " + "\n- ".join(category.what_is_checked),
                    "What changes you can make:\n- " + "\n- ".join(category.what_the_user_can_change),
                    "Where to change it in macOS:\n- " + "\n- ".join(category.macos_settings_paths),
                    f"Risk if unconfigured: {category.risk_if_unconfigured}",
                    "NIST mappings:\n- " + "\n- ".join(category.nist_mappings),
                ]
            )
        )
        self._render_category_checklist(category)
        selected = state.selected_device_id or state.selected_checklist_item or "No item selected"
        self.category_selected_device_label.setText(f"Selected item: {selected}")
        pending = state.pending_changes or category.pending_changes
        self.category_pending_label.setText("Pending changes: " + ("; ".join(pending) if pending else "none"))
        self.category_changes_view.setPlainText(self._changes_text(category, state))

    def _render_category_checklist(self, category) -> None:
        self.category_checklist_table.setRowCount(0)
        completed = set(self._completed_for_category(category.title))
        if not category.checklist_items:
            self.category_checklist_table.insertRow(0)
            self.category_checklist_table.setItem(0, 0, QTableWidgetItem("No checklist items are available for this category yet."))
            self.category_checklist_table.setItem(0, 1, QTableWidgetItem("Unavailable"))
            self.category_checklist_table.setItem(0, 2, QTableWidgetItem("Review this category after a future MSAA update."))
            self.category_checklist_table.resizeRowsToContents()
            return
        for row_index, item in enumerate(category.checklist_items):
            self.category_checklist_table.insertRow(row_index)
            status = "configured" if item in completed else "needs review"
            item_cell = QTableWidgetItem(item)
            item_cell.setToolTip(item)
            status_cell = QTableWidgetItem(status)
            status_cell.setToolTip(f"Checklist status: {status}")
            action_cell = QTableWidgetItem("Review and adjust in the listed macOS settings path.")
            action_cell.setToolTip("Review and adjust in the listed macOS settings path.")
            self.category_checklist_table.setItem(row_index, 0, item_cell)
            self.category_checklist_table.setItem(row_index, 1, status_cell)
            self.category_checklist_table.setItem(row_index, 2, action_cell)
        self.category_checklist_table.resizeRowsToContents()

    def _changes_text(self, category, state: FamilyCategoryViewState) -> str:
        completed = self._completed_for_category(category.title)
        remaining = [item for item in category.checklist_items if item not in completed]
        lines = ["Current settings observed:", f"- {category.current_status}", "", "Unsaved changes:"]
        lines.extend(f"- {item}" for item in state.pending_changes)
        if not state.pending_changes:
            lines.append("- none")
        lines.extend(["", "Saved changes:"])
        lines.extend(f"- {item}" for item in category.pending_changes)
        if not category.pending_changes:
            lines.append("- none")
        lines.extend(["", "Completed checklist items:"])
        lines.extend(f"- {item}" for item in completed)
        if not completed:
            lines.append("- none recorded")
        lines.extend(["", "Remaining recommended items:"])
        lines.extend(f"- {item}" for item in remaining[:12])
        if not remaining:
            lines.append("- none")
        lines.extend(["", "Skipped items:", "- none recorded", "", "User notes:", "- Add notes in exported reports or local case notes as appropriate."])
        return "\n".join(lines)

    def _completed_for_category(self, title: str) -> list[str]:
        completed = self._report.get("completed_actions", {}) if isinstance(self._report, dict) else {}
        if not isinstance(completed, dict):
            return []
        aliases = {
            "Screen Time and Usage Controls": ["Screen Time", "Content Restrictions"],
            "Privacy Permissions": ["Privacy", "Location Sharing", "App Permissions"],
            "Web and Browser Safety": ["Web Safety"],
            "Downloads and File Safety": ["Downloads"],
            "App Store and Application Controls": ["Application Review"],
            "Special Needs and Accessibility Safety": ["Accessibility"],
            "Government / NIST Lockdown Profile": ["System Security"],
        }
        values = list(completed.get(title, []))
        for alias in aliases.get(title, []):
            values.extend(completed.get(alias, []))
        return values

    def _category_score(self, category_id: str) -> int:
        scores = self._report.get("category_scores", {}) if isinstance(self._report, dict) else {}
        try:
            return int(scores.get(category_id, 0))
        except (TypeError, ValueError):
            return 0

    def reset_current_category_view_state(self) -> None:
        self._view_state[self._active_category_id] = reset_category_view_state(self._active_category_id)
        self._render_active_category()

    def reset_current_category_pending_changes(self) -> None:
        state = self._view_state[self._active_category_id]
        if state.pending_changes:
            result = QMessageBox.question(
                self,
                "Reset Pending Changes",
                f"Discard unsaved changes for {self._categories[self._active_category_id].title} only?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if result != QMessageBox.Yes:
                return
        state.pending_changes.clear()
        self._render_active_category()

    def reset_current_category_to_recommended_defaults(self) -> None:
        category = self._categories[self._active_category_id]
        preview = "\n".join(f"- {item}" for item in category.checklist_items[:12])
        result = QMessageBox.question(
            self,
            "Reset Category Defaults",
            f"Reset recommended checklist selections for {category.title} only?\n\nThis does not apply macOS system changes automatically.\n\n{preview}",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if result != QMessageBox.Yes:
            return
        self._view_state[self._active_category_id].pending_changes = [f"Recommended defaults restored for {category.title}"]
        self._render_active_category()

    def previous_category(self) -> None:
        row = max(0, self._category_order.index(self._active_category_id) - 1)
        self.category_list.setCurrentRow(row)

    def next_category(self) -> None:
        row = min(len(self._category_order) - 1, self._category_order.index(self._active_category_id) + 1)
        self.category_list.setCurrentRow(row)

    def reset_category_view_state(self, category_id: str) -> None:
        if category_id in self._view_state:
            self._view_state[category_id] = reset_category_view_state(category_id)
            if category_id == self._active_category_id:
                self._render_active_category()

    def reset_all_family_view_state(self) -> None:
        self._view_state = reset_all_family_view_state()
        self._render_active_category()

    def simulate_pending_change(self, category_id: str, change: str) -> None:
        if category_id in self._view_state:
            self._view_state[category_id].pending_changes.append(change)
            if category_id == self._active_category_id:
                self._render_active_category()

    def select_device_for_category(self, category_id: str, device_id: str) -> None:
        if category_id in self._view_state:
            self._view_state[category_id].selected_device_id = device_id
            if category_id == self._active_category_id:
                self._render_active_category()

    def _timestamp(self) -> str:
        from datetime import datetime

        return datetime.now().isoformat(timespec="seconds")

    def _set_rows(self, table: QTableWidget, rows: list[dict[str, Any]], keys: list[str]) -> None:
        table.setRowCount(0)
        if not rows:
            table.insertRow(0)
            empty = QTableWidgetItem("No data is available yet. Run the Safety Audit to populate this section.")
            empty.setToolTip(empty.text())
            table.setItem(0, 0, empty)
            for column in range(1, len(keys)):
                table.setItem(0, column, QTableWidgetItem("Not collected"))
            table.resizeRowsToContents()
            return
        for row_index, row in enumerate(rows):
            table.insertRow(row_index)
            for column, key in enumerate(keys):
                value = str(row.get(key, "") or "Unknown")
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                table.setItem(row_index, column, item)
        table.resizeRowsToContents()

    def _wizard_text(self) -> str:
        wizard = self._report.get("wizard_recommendations", {})
        if not isinstance(wizard, dict) or not wizard:
            return "Choose who uses this Mac, then run the Safety Audit to generate recommendations."
        profile = ", ".join(str(item) for item in wizard.get("profile", []))
        recs = "\n".join(f"- {item}" for item in wizard.get("recommendations", []))
        return f"Profile: {profile}\n\nRecommended setup:\n{recs}"

    def _caregiver_text(self) -> str:
        dashboard = self._report.get("caregiver_dashboard", {})
        forecast = self._report.get("family_security_forecast", [])
        if not isinstance(dashboard, dict) or not dashboard:
            return "Run the Safety Audit to see a simple caregiver dashboard."
        lines = [
            f"Safety score: {dashboard.get('safety_score', '--')}",
            f"Recent changes: {dashboard.get('recent_changes', '')}",
            "New apps to review: " + ", ".join(str(item) for item in dashboard.get("new_apps", [])[:8]),
            "Safety recommendations:",
        ]
        lines.extend(f"- {item}" for item in dashboard.get("safety_recommendations", []))
        lines.append("\nFamily Security Forecast:")
        for card in forecast:
            lines.append(f"- {card.get('topic', '')}: {card.get('guidance', '')} Action: {card.get('action', '')}")
        return "\n".join(lines)

    def _education_text(self) -> str:
        cards = list(self._report.get("education_cards", []))
        notice = list(self._report.get("privacy_notice", []))
        if not cards:
            return "Plain-language online safety cards will appear after an audit."
        lines = ["Online Safety Guidance:"]
        for card in cards:
            lines.append(f"\n{card.get('topic', '')}\n{card.get('guidance', '')}\nAction: {card.get('action', '')}")
        lines.append("\nPrivacy Requirements:")
        lines.extend(f"- {item}" for item in notice)
        return "\n".join(lines)

    def open_configuration_wizard(self) -> None:
        if self.db is None:
            QMessageBox.information(self, "Wizard Requires Settings", "Open the full application to configure Family & Safety settings. This standalone panel can still show audits and reports.")
            return
        dialog = FamilySafetyWizardDialog(self.db, self)
        if dialog.exec() == QDialog.Accepted:
            self.refresh_wizard_status()

    def refresh_wizard_status(self) -> None:
        if self.db is None:
            self.current_profile_label.setText("Current Profile: not configured")
            self.last_wizard_run_label.setText("Last Wizard Run: not yet")
            self.last_applied_changes_label.setText("Last Applied Changes: none")
            self.settings_sync_status_label.setText("Settings Sync Status: unavailable in standalone panel")
            self.manual_review_needed_label.setText("Manual Review Needed: run the wizard or audit to see checklist items")
            return
        profile = self.db.get_background_monitor_state(CURRENT_PROFILE_KEY, "not configured")
        last_run = self.db.get_background_monitor_state(LAST_RUN_KEY, "not yet")
        raw = self.db.get_background_monitor_state(LAST_APPLY_REPORT_KEY, "")
        applied_count = 0
        sync_status = "unknown"
        system_action_status = "no macOS handoff recorded"
        if raw:
            try:
                import json

                payload = json.loads(raw)
                applied_count = len(payload.get("applied_changes", []))
                sync_status = str(payload.get("settings_sync", {}).get("status", "unknown"))
                system_actions = payload.get("system_setup_actions", [])
                if isinstance(system_actions, list) and system_actions:
                    opened = sum(item.get("status") == "OPENED_FOR_USER_APPROVAL" for item in system_actions if isinstance(item, dict))
                    mdm = sum(item.get("status") == "MDM_REQUIRED" for item in system_actions if isinstance(item, dict))
                    queued = sum(item.get("status") == "QUEUED_FOR_USER_REVIEW" for item in system_actions if isinstance(item, dict))
                    system_action_status = f"{opened} opened for approval, {queued} queued, {mdm} MDM-dependent"
            except Exception:
                sync_status = "status unavailable"
        self.current_profile_label.setText(f"Current Profile: {profile}")
        self.last_wizard_run_label.setText(f"Last Wizard Run: {last_run}")
        self.last_applied_changes_label.setText(f"Last Applied Changes: {applied_count}")
        self.settings_sync_status_label.setText(f"Settings Sync Status: {sync_status}")
        self.manual_review_needed_label.setText(f"Protected macOS / MDM Actions: {system_action_status}. Re-run the Safety Audit to verify effective state.")

    def show_current_profile(self) -> None:
        self.refresh_wizard_status()
        QMessageBox.information(
            self,
            "Current Family Safety Profile",
            "\n".join(
                [
                    self.current_profile_label.text(),
                    self.last_wizard_run_label.text(),
                    self.last_applied_changes_label.text(),
                    self.settings_sync_status_label.text(),
                    self.manual_review_needed_label.text(),
                ]
            ),
        )

    def export_current_configuration_report(self) -> None:
        if self.db is None:
            QMessageBox.information(self, "Export Unavailable", "Open the full application to export the current Family & Safety configuration report.")
            return
        raw = self.db.get_background_monitor_state("family_safety_draft_recommendation_json", "") or self.db.get_background_monitor_state("family_safety_last_recommendation_json", "")
        if not raw:
            QMessageBox.information(self, "No Recommendation Available", "Run the guided setup wizard first to create an exportable recommendation report.")
            return
        from pathlib import Path
        import json

        recommendation = json.loads(raw)
        paths = [
            export_family_safety_configuration_html(recommendation),
            export_family_safety_configuration_word(recommendation),
            export_family_safety_configuration_excel(recommendation),
            export_family_safety_configuration_json(recommendation),
        ]
        QMessageBox.information(
            self,
            "Family Safety Configuration Report Exported",
            "Saved local HTML, Word, Excel, and JSON reports:\n" + "\n".join(str(Path(path)) for path in paths),
        )

    def restore_previous_settings(self) -> None:
        if self.db is None:
            QMessageBox.information(self, "Restore Unavailable", "Open the full application to restore wizard-applied settings.")
            return
        preview = restore_family_safety_snapshot(self.db, preview_only=True)
        if preview.get("status") == "no_snapshot":
            QMessageBox.information(self, "No Snapshot Available", "No previous wizard snapshot is available to restore.")
            return
        changes = preview.get("restore_changes", [])
        text = "Restore only these wizard-changed MSAA setting paths?\n\n" + "\n".join(
            f"- {item.get('setting_path')}: {item.get('current_value')} -> {item.get('restore_value')}" for item in changes
        )
        result = QMessageBox.question(self, "Restore Previous Family Safety Settings", text, QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if result != QMessageBox.Yes:
            return
        restored = restore_family_safety_snapshot(self.db)
        QMessageBox.information(self, "Family Safety Settings Restored", f"Restore status: {restored.get('status')}\nSettings version: {restored.get('settings_version_after')}")
        self.refresh_wizard_status()
