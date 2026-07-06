from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
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


PROFILE_OPTIONS = [
    "Young Child",
    "Teen",
    "Adult",
    "Senior",
    "Shared Family Computer",
    "Special Needs User",
    "School Device",
]


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
    button.setMinimumHeight(36)
    button.setMinimumWidth(min_width or max(120, len(text) * 8 + 32))
    button.setSizePolicy(QSizePolicy.MinimumExpanding, QSizePolicy.Fixed)
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


class FamilySafetyPanel(QFrame):
    audit_requested = Signal(str)
    export_html_requested = Signal()
    export_json_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("familySafetyPanel")
        self.setFrameShape(QFrame.StyledPanel)
        self.setMinimumSize(820, 620)
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

        controls = QHBoxLayout()
        controls.addWidget(QLabel("Who uses this Mac?"))
        self.profile_combo = QComboBox()
        self.profile_combo.addItems(PROFILE_OPTIONS)
        self.profile_combo.setMinimumHeight(34)
        controls.addWidget(self.profile_combo)
        self.audit_button = make_family_button("Run Safety Audit", "Run a local Family & Safety audit for the selected user profile.", "primary")
        self.audit_button.clicked.connect(lambda: self.audit_requested.emit(self.profile_combo.currentText()))
        controls.addWidget(self.audit_button)
        self.export_html_button = make_family_button("Export HTML", "Export a local Family & Safety HTML report.", min_width=124)
        self.export_html_button.clicked.connect(self.export_html_requested.emit)
        controls.addWidget(self.export_html_button)
        self.export_json_button = make_family_button("Export JSON", "Export a local Family & Safety JSON report.", min_width=124)
        self.export_json_button.clicked.connect(self.export_json_requested.emit)
        controls.addWidget(self.export_json_button)
        controls.addStretch(1)
        layout.addLayout(controls)

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
        self.category_list.setMinimumWidth(220)
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
        detail.setMinimumWidth(520)
        detail.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        detail_layout = QVBoxLayout(detail)
        detail_layout.setContentsMargins(14, 14, 14, 14)
        detail_layout.setSpacing(8)
        nav = QHBoxLayout()
        nav.addWidget(self.previous_category_button)
        nav.addWidget(self.next_category_button)
        nav.addWidget(self.overview_category_button)
        nav.addStretch(1)
        reset_row = QHBoxLayout()
        reset_row.addWidget(self.reset_view_button)
        reset_row.addWidget(self.reset_pending_button)
        reset_row.addWidget(self.reset_defaults_button)
        reset_row.addStretch(1)
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
        detail_layout.addLayout(reset_row)
        detail_layout.addLayout(nav)
        self.category_detail_scroll = _scroll_page(detail, min_width=520)
        splitter.addWidget(self.category_detail_scroll)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([260, 760])
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
