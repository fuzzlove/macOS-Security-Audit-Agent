from __future__ import annotations

import json
import html
from typing import Any

from PySide6.QtCore import QTimer, Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QSizePolicy,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


FORECAST_STYLES = {
    "urgent": "background: rgba(82, 28, 92, 175); border: 1px solid rgba(186, 118, 255, 190);",
    "elevated": "background: rgba(110, 82, 18, 165); border: 1px solid rgba(240, 180, 70, 185);",
    "watch": "background: rgba(18, 58, 102, 150); border: 1px solid rgba(110, 168, 232, 170);",
    "clear": "background: rgba(40, 52, 74, 120); border: 1px solid rgba(120, 138, 168, 130);",
}

BUTTON_STYLES = {
    "primary": """
        QPushButton[forecastButtonRole="primary"] {
            background: #1F6FEB;
            color: #FFFFFF;
            border: 1px solid #58A6FF;
            border-radius: 6px;
            min-height: 34px;
            padding: 6px 10px;
            font-size: 12px;
            font-weight: 600;
        }
        QPushButton[forecastButtonRole="primary"]:hover { background: #256ADF; }
        QPushButton[forecastButtonRole="primary"]:pressed { background: #195BB8; }
        QPushButton[forecastButtonRole="primary"]:focus { border: 2px solid #F0F6FC; }
    """,
    "secondary": """
        QPushButton[forecastButtonRole="secondary"] {
            background: #30363D;
            color: #F0F6FC;
            border: 1px solid #8B949E;
            border-radius: 6px;
            min-height: 34px;
            padding: 6px 10px;
            font-size: 12px;
            font-weight: 600;
        }
        QPushButton[forecastButtonRole="secondary"]:hover { background: #3A4047; }
        QPushButton[forecastButtonRole="secondary"]:pressed { background: #262B31; }
        QPushButton[forecastButtonRole="secondary"]:focus { border: 2px solid #F0F6FC; }
    """,
    "warning": """
        QPushButton[forecastButtonRole="warning"] {
            background: #9A6700;
            color: #FFFFFF;
            border: 1px solid #D29922;
            border-radius: 6px;
            min-height: 34px;
            padding: 6px 10px;
            font-size: 12px;
            font-weight: 600;
        }
        QPushButton[forecastButtonRole="warning"]:hover { background: #B07800; }
        QPushButton[forecastButtonRole="warning"]:pressed { background: #7F5600; }
        QPushButton[forecastButtonRole="warning"]:focus { border: 2px solid #F0F6FC; }
    """,
    "urgent": """
        QPushButton[forecastButtonRole="urgent"] {
            background: #7A1F5C;
            color: #FFFFFF;
            border: 1px solid #D2A8FF;
            border-radius: 6px;
            min-height: 34px;
            padding: 6px 10px;
            font-size: 12px;
            font-weight: 600;
        }
        QPushButton[forecastButtonRole="urgent"]:hover { background: #8A2468; }
        QPushButton[forecastButtonRole="urgent"]:pressed { background: #65184B; }
        QPushButton[forecastButtonRole="urgent"]:focus { border: 2px solid #F0F6FC; }
    """,
    "disabled": """
        QPushButton:disabled {
            background: #484F58;
            color: #8B949E;
            border: 1px solid #6E7681;
            border-radius: 6px;
            min-height: 34px;
            padding: 6px 10px;
            font-size: 12px;
            font-weight: 600;
        }
    """,
}

BUTTON_TOOLTIPS = {
    "update": "Check Apple security advisories and refresh the local forecast.",
    "diagnostics": "Show source status, cache age, inventory, and forecast generation details.",
    "demo": "Create simulated forecast cards to test the UI.",
    "safari_demo": "Create a simulated Safari/WebKit forecast card without using Safari browsing state.",
    "details": "Open full CVE/advisory details for this forecast card.",
    "review": "Mark this forecast item as reviewed without hiding it permanently.",
    "snooze": "Temporarily hide alerts for this forecast item.",
    "guidance": "Show recommended Apple update steps.",
}


def make_forecast_button(text: str, tooltip: str, style: str = "primary", min_width: int | None = None) -> QPushButton:
    button = QPushButton(text)
    button.setToolTip(tooltip)
    button.setMinimumHeight(36)
    button.setSizePolicy(QSizePolicy.MinimumExpanding, QSizePolicy.Fixed)
    button.setProperty("forecastButtonRole", style)
    button.setCursor(Qt.PointingHandCursor)
    button.setStyleSheet(BUTTON_STYLES.get(style, BUTTON_STYLES["secondary"]) + BUTTON_STYLES["disabled"])
    if min_width is not None:
        button.setMinimumWidth(min_width)
    else:
        button.setMinimumWidth(max(110, len(text) * 8 + 28))
    return button


class CveRadarDetailsDialog(QDialog):
    def __init__(self, title: str, body: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        layout = QVBoxLayout(self)
        viewer = QTextEdit()
        viewer.setReadOnly(True)
        viewer.setPlainText(body)
        layout.addWidget(viewer)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)


class CveRadarSnoozeDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Snooze Apple Security Forecast")
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Choose how long to snooze this radar card."))
        self.time_checkbox = QCheckBox("Use time-based snooze")
        self.time_checkbox.setChecked(True)
        layout.addWidget(self.time_checkbox)
        self.days_1 = QCheckBox("1 day")
        self.days_7 = QCheckBox("7 days")
        self.version_change = QCheckBox("Until next version change")
        self.days_1.setChecked(True)
        layout.addWidget(self.days_1)
        layout.addWidget(self.days_7)
        layout.addWidget(self.version_change)
        self.days_1.stateChanged.connect(lambda state: self._sync(self.days_1, state))
        self.days_7.stateChanged.connect(lambda state: self._sync(self.days_7, state))
        self.version_change.stateChanged.connect(lambda state: self._sync(self.version_change, state))
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _sync(self, selected: QCheckBox, state: int) -> None:
        if state != Qt.Checked:
            return
        for box in [self.days_1, self.days_7, self.version_change]:
            if box is not selected:
                box.setChecked(False)

    def values(self) -> dict[str, Any]:
        if self.version_change.isChecked():
            return {"until_next_version_change": True, "days": None}
        if self.days_7.isChecked():
            return {"until_next_version_change": False, "days": 7}
        return {"until_next_version_change": False, "days": 1}


class CveRadarCardWidget(QFrame):
    details_requested = Signal(object)
    review_requested = Signal(object)
    snooze_requested = Signal(object)
    guidance_requested = Signal(object)

    def __init__(self, card: dict[str, Any], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.card = card
        self.setObjectName("cveRadarCard")
        self.setFrameShape(QFrame.StyledPanel)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(6)
        title = QLabel(str(card.get("title", "")))
        title.setWordWrap(True)
        title.setStyleSheet("font-weight: 700; font-size: 13px;")
        layout.addWidget(title)
        layout.addWidget(self._meta_label(card))
        layout.addWidget(self._summary_label("Why shown", self._why_text(card)))
        layout.addWidget(self._summary_label("What to do now", str(card.get("recommended_action", card.get("what_to_do", "")))))
        layout.addWidget(self._summary_label("Update guidance", str(card.get("update_guidance", card.get("update_path", "")))))
        references = ", ".join(str(item) for item in card.get("references", []))
        if references:
            layout.addWidget(self._summary_label("References", references))
        layout.addLayout(self._action_layout())
        self.setStyleSheet(self._card_stylesheet(card))

    def _meta_label(self, card: dict[str, Any]) -> QLabel:
        badges = []
        if card.get("kev") or card.get("kev_cves"):
            badges.append("KEV")
        if float(card.get("epss_percentile") or 0.0) >= 0.90 or card.get("epss_high_cves"):
            badges.append("EPSS high")
        confidence = str(card.get("applicability_confidence", card.get("confidence", ""))).title()
        badges.append(f"Confidence: {confidence}")
        badges.append(f"Forecast: {str(card.get('forecast_level', 'watch')).title()}")
        badges.append(f"Source: {card.get('source', '')}")
        badges.append(f"CVE(s): {', '.join(card.get('cve_ids', card.get('cves', []))) or card.get('cve_id', '')}")
        badges.append(f"Product: {card.get('detected_product', card.get('affected_local_product', ''))} {card.get('detected_version', '')}".strip())
        label = QLabel(" | ".join(badges))
        label.setWordWrap(True)
        return label

    def _summary_label(self, heading: str, text: str) -> QLabel:
        label = QLabel(f"<b>{html.escape(heading)}:</b> {html.escape(text)}")
        label.setWordWrap(True)
        return label

    def _action_layout(self) -> QVBoxLayout:
        container = QVBoxLayout()
        container.setSpacing(6)
        primary = make_forecast_button("Details", BUTTON_TOOLTIPS["details"], "primary", min_width=110)
        review = make_forecast_button("Reviewed", BUTTON_TOOLTIPS["review"], "secondary", min_width=110)
        snooze = make_forecast_button("Snooze", BUTTON_TOOLTIPS["snooze"], "warning", min_width=110)
        guidance = make_forecast_button("Update Guide", BUTTON_TOOLTIPS["guidance"], "urgent", min_width=120)
        for button in [primary, review, snooze, guidance]:
            button.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        primary.clicked.connect(lambda: self.details_requested.emit(self.card))
        review.clicked.connect(lambda: self.review_requested.emit(self.card))
        snooze.clicked.connect(lambda: self.snooze_requested.emit(self.card))
        guidance.clicked.connect(lambda: self.guidance_requested.emit(self.card))
        top_row = QHBoxLayout()
        top_row.setSpacing(6)
        top_row.addWidget(primary)
        bottom_row = QHBoxLayout()
        bottom_row.setSpacing(6)
        bottom_row.addWidget(review)
        bottom_row.addWidget(snooze)
        bottom_row.addWidget(guidance)
        container.addLayout(top_row)
        container.addLayout(bottom_row)
        return container

    def _why_text(self, card: dict[str, Any]) -> str:
        if card.get("why_shown_to_you") or card.get("why_shown"):
            return str(card.get("why_shown_to_you") or card.get("why_shown"))
        confidence = str(card.get("applicability_confidence", card.get("confidence", "review-needed")))
        evidence = card.get("local_match_evidence", [])
        if evidence:
            return f"Installed software matched locally with {confidence} applicability confidence."
        if card.get("apple_related") or card.get("source") == "apple":
            return "Apple-related CVE matched your detected macOS or browser family."
        return "Review needed because version data is incomplete."

    def _card_stylesheet(self, card: dict[str, Any]) -> str:
        forecast_level = str(card.get("forecast_level", "watch"))
        base = FORECAST_STYLES.get(forecast_level, FORECAST_STYLES["watch"])
        accent = "rgba(147, 197, 253, 160)" if forecast_level == "clear" else "rgba(216, 180, 254, 140)" if forecast_level == "urgent" else "rgba(120, 169, 255, 150)"
        return (
            "QFrame#cveRadarCard {"
            f" {base}"
            f" border-radius: 12px;"
            f" border-left: 4px solid {accent};"
            " color: #E5EEF7;"
            "}"
        )


class CveRadarPanel(QFrame):
    update_requested = Signal()
    diagnostics_requested = Signal()
    demo_requested = Signal()
    safari_demo_requested = Signal()
    clear_demo_requested = Signal()
    export_requested = Signal()
    review_requested = Signal(object)
    snooze_requested = Signal(object, object)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("cveRadarPanel")
        self.setMinimumWidth(520)
        self.setMaximumWidth(16777215)
        self.setFrameShape(QFrame.StyledPanel)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self._radar_payload: dict[str, Any] = {}
        self._display_cards: list[dict[str, Any]] = []
        self._selected_card: dict[str, Any] | None = None
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        header = QLabel("Apple Security Forecast")
        header.setStyleSheet("font-size: 18px; font-weight: 700; color: #D9E6FF;")
        subtitle = QLabel("Apple-related security advisories matched to this Mac.")
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet("color: #9DB0C9;")
        self.radar_sweep = QLabel("◐")
        self.radar_sweep.setStyleSheet("font-size: 18px; color: #A78BFA;")
        header_row = QHBoxLayout()
        header_row.addWidget(header)
        header_row.addStretch(1)
        header_row.addWidget(self.radar_sweep)
        layout.addLayout(header_row)
        layout.addWidget(subtitle)

        self.last_updated_label = QLabel("Last updated: not yet")
        self.next_check_label = QLabel("Next check: not yet")
        self.cves_evaluated_label = QLabel("CVEs evaluated: 0")
        self.applicable_label = QLabel("Applicable CVEs: 0")
        self.kev_label = QLabel("KEV matches: 0")
        self.apple_updates_label = QLabel("Apple updates available: no")
        self.status_label = QLabel("Forecast not checked yet")
        self.reason_label = QLabel("No forecast has been checked yet.")
        self.reason_label.setWordWrap(True)
        for widget in [
            self.last_updated_label,
            self.next_check_label,
            self.cves_evaluated_label,
            self.applicable_label,
            self.kev_label,
            self.apple_updates_label,
            self.status_label,
            self.reason_label,
        ]:
            widget.setStyleSheet("color: #D6E4FF;")
            layout.addWidget(widget)
        self.status_label.setStyleSheet("color: #E9F2FF; font-weight: 700;")
        self.reason_label.setStyleSheet("color: #9DB0C9;")

        filters_row = QVBoxLayout()
        self.apple_only = QCheckBox("Apple/macOS only")
        self.kev_only = QCheckBox("CISA KEV only")
        self.epss_only = QCheckBox("EPSS high only")
        self.installed_only = QCheckBox("Installed software only")
        self.critical_high_only = QCheckBox("Critical/high only")
        self.review_needed_only = QCheckBox("Show review needed")
        for checkbox in [
            self.apple_only,
            self.kev_only,
            self.epss_only,
            self.installed_only,
            self.critical_high_only,
            self.review_needed_only,
        ]:
            checkbox.stateChanged.connect(self.refresh_cards)
            filters_row.addWidget(checkbox)
        layout.addLayout(filters_row)

        button_grid = QVBoxLayout()
        top_button_row = QHBoxLayout()
        bottom_button_row = QHBoxLayout()
        self.update_button = make_forecast_button("Update Forecast", BUTTON_TOOLTIPS["update"], "primary")
        self.diagnostics_button = make_forecast_button("Diagnostics", BUTTON_TOOLTIPS["diagnostics"], "secondary")
        self.demo_button = make_forecast_button("Generate Demo", BUTTON_TOOLTIPS["demo"], "warning")
        self.safari_demo_button = make_forecast_button("Safari/WebKit Demo", BUTTON_TOOLTIPS["safari_demo"], "warning")
        self.clear_demo_button = make_forecast_button("Clear Demo", "Remove simulated forecast cards from the local cache.", "secondary")
        self.export_button = make_forecast_button("Export Forecast", "Export the current Apple Security Forecast report.", "secondary")
        self.details_button = make_forecast_button("View Details", BUTTON_TOOLTIPS["details"], "primary")
        self.review_button = make_forecast_button("Reviewed", BUTTON_TOOLTIPS["review"], "secondary")
        self.snooze_button = make_forecast_button("Snooze", BUTTON_TOOLTIPS["snooze"], "warning")
        self.guidance_button = make_forecast_button("Update Guide", BUTTON_TOOLTIPS["guidance"], "urgent")
        for button in [self.update_button, self.diagnostics_button, self.demo_button, self.safari_demo_button, self.clear_demo_button, self.export_button]:
            button.setEnabled(False)
        for button in [self.update_button, self.diagnostics_button, self.demo_button]:
            top_button_row.addWidget(button)
        for button in [self.safari_demo_button, self.clear_demo_button, self.export_button]:
            bottom_button_row.addWidget(button)
        button_grid.addLayout(top_button_row)
        button_grid.addLayout(bottom_button_row)
        layout.addLayout(button_grid)

        self.cards = QListWidget()
        self.cards.currentItemChanged.connect(self._refresh_selected_card)
        self.cards.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        layout.addWidget(self.cards, 1)

        self.details = QTextEdit()
        self.details.setReadOnly(True)
        self.details.setPlaceholderText("Select a forecast card to view details.")
        self.details.setMaximumHeight(260)
        self.details.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        layout.addWidget(self.details)

        self.update_button.clicked.connect(self.update_requested.emit)
        self.diagnostics_button.clicked.connect(self.diagnostics_requested.emit)
        self.demo_button.clicked.connect(self.demo_requested.emit)
        self.safari_demo_button.clicked.connect(self.safari_demo_requested.emit)
        self.clear_demo_button.clicked.connect(self.clear_demo_requested.emit)
        self.export_button.clicked.connect(self.export_requested.emit)
        self.details_button.clicked.connect(self.open_details)
        self.review_button.clicked.connect(self.mark_reviewed)
        self.snooze_button.clicked.connect(self.snooze_selected)
        self.guidance_button.clicked.connect(self.open_update_guidance)

        self._pulse_timer = QTimer(self)
        self._pulse_timer.timeout.connect(self._animate_pulse)
        self._pulse_timer.start(300)
        self.diagnostics_button.setEnabled(True)
        self.demo_button.setEnabled(True)
        self.safari_demo_button.setEnabled(True)
        self.clear_demo_button.setEnabled(True)
        self.update_button.setEnabled(True)
        self.export_button.setEnabled(True)

        self.setStyleSheet(
            """
            QFrame#cveRadarPanel {
                background: rgba(14, 20, 40, 168);
                border: 1px solid rgba(127, 139, 166, 90);
                border-radius: 16px;
            }
            QListWidget {
                background: rgba(10, 14, 24, 110);
                border: 1px solid rgba(127, 139, 166, 60);
                border-radius: 10px;
            }
            QPushButton {
                background: rgba(54, 65, 91, 185);
                color: #ECF4FF;
                border: 1px solid rgba(143, 155, 180, 120);
                border-radius: 8px;
                padding: 6px 8px;
            }
            QPushButton:disabled {
                color: rgba(236, 244, 255, 120);
                background: rgba(54, 65, 91, 85);
            }
            QCheckBox {
                color: #D6E4FF;
            }
            QTextEdit {
                background: rgba(10, 14, 24, 100);
                border: 1px solid rgba(127, 139, 166, 60);
                border-radius: 8px;
                color: #ECF4FF;
            }
            """
        )

    def _animate_pulse(self) -> None:
        frames = ["◐", "◓", "◑", "◒"]
        current = self._pulse_timer.property("frame") or 0
        current = (int(current) + 1) % len(frames)
        self._pulse_timer.setProperty("frame", current)
        self.radar_sweep.setText(frames[current])

    def set_radar_data(self, payload: dict[str, Any]) -> None:
        self._radar_payload = dict(payload or {})
        self.last_updated_label.setText(f"Last updated: {self._radar_payload.get('generated_at', self._radar_payload.get('timestamp', 'not yet'))}")
        self.next_check_label.setText(f"Next check: {self._radar_payload.get('next_check_at', 'not yet')}")
        self.cves_evaluated_label.setText(f"CVEs evaluated: {self._radar_payload.get('cve_count', self._radar_payload.get('cves_evaluated', 0))}")
        self.applicable_label.setText(f"Applicable CVEs: {self._radar_payload.get('card_count', self._radar_payload.get('applicable_cves', len(self._radar_payload.get('display_cards', []))))}")
        self.kev_label.setText(f"KEV matches: {self._radar_payload.get('kev_count', self._radar_payload.get('kev_matches', 0))}")
        self.apple_updates_label.setText(f"Apple updates available: {'yes' if self._radar_payload.get('level') in {'elevated', 'urgent'} or self._radar_payload.get('apple_updates_available') else 'no'}")
        self.status_label.setText(self._state_text(self._radar_payload))
        self.reason_label.setText(self._reason_text(self._radar_payload))
        self._display_cards = [card for card in self._radar_payload.get("display_cards", self._radar_payload.get("cards", [])) if isinstance(card, dict)]
        self.refresh_cards()
        self.style_for_action_buttons()

    def refresh_cards(self, *_args) -> None:
        self.cards.clear()
        filtered = [card for card in self._display_cards if self._card_visible(card)]
        if not filtered:
            item = QListWidgetItem()
            item.setFlags(Qt.NoItemFlags)
            widget = QFrame()
            title = QLabel("Clear — no applicable Apple security forecast cards.")
            title.setWordWrap(True)
            title.setStyleSheet("font-weight: 700; color: #D9E6FF;")
            label = QLabel(self._reason_text(self._radar_payload))
            label.setWordWrap(True)
            layout = QVBoxLayout(widget)
            layout.setSpacing(6)
            layout.addWidget(label)
            layout.insertWidget(0, title)
            item.setSizeHint(widget.sizeHint())
            self.cards.addItem(item)
            self.cards.setItemWidget(item, widget)
            self._selected_card = None
            self._refresh_selected_card()
            self._set_buttons_enabled(False)
            return
        for card in filtered:
            item = QListWidgetItem()
            widget = CveRadarCardWidget(card)
            item.setSizeHint(widget.sizeHint())
            item.setData(Qt.UserRole, card)
            widget.details_requested.connect(self._open_card_details)
            widget.review_requested.connect(self._review_card)
            widget.snooze_requested.connect(self._snooze_card)
            widget.guidance_requested.connect(self._open_card_update_guidance)
            self.cards.addItem(item)
            self.cards.setItemWidget(item, widget)
        self.cards.setCurrentRow(0)
        self._refresh_selected_card()

    def _card_visible(self, card: dict[str, Any]) -> bool:
        alerts = card.get("alerts") or [card]
        alerts = [alert for alert in alerts if isinstance(alert, dict)]
        if self.apple_only.isChecked() and not any(alert.get("source") == "apple" or alert.get("apple_related") for alert in alerts):
            return False
        if self.kev_only.isChecked() and not any(alert.get("kev") or alert.get("kev_cves") for alert in alerts):
            return False
        if self.epss_only.isChecked() and not any(float(alert.get("epss_percentile") or 0.0) >= 0.90 or alert.get("epss_high_cves") for alert in alerts):
            return False
        if self.installed_only.isChecked() and not any(alert.get("local_match_evidence") for alert in alerts):
            return False
        if self.critical_high_only.isChecked() and not any(str(alert.get("highest_severity", alert.get("severity", ""))) in {"critical", "high"} for alert in alerts):
            return False
        if not self.review_needed_only.isChecked() and any(str(alert.get("applicability", "")) == "review_needed" for alert in alerts):
            return False
        return True

    def _refresh_selected_card(self, *_args) -> None:
        item = self.cards.currentItem()
        if item is None:
            self._selected_card = None
            self.details.clear()
            self._set_buttons_enabled(False)
            return
        card = item.data(Qt.UserRole)
        if not isinstance(card, dict):
            self._selected_card = None
            self.details.clear()
            self._set_buttons_enabled(False)
            return
        self._selected_card = card
        self._set_buttons_enabled(True)
        self.details.setPlainText(self._detail_text(card))

    def _set_buttons_enabled(self, enabled: bool) -> None:
        self.diagnostics_button.setEnabled(True)
        self.demo_button.setEnabled(True)
        self.clear_demo_button.setEnabled(True)
        self.details_button.setEnabled(enabled)
        self.review_button.setEnabled(enabled)
        self.snooze_button.setEnabled(enabled)
        self.guidance_button.setEnabled(enabled)

    def _detail_text(self, card: dict[str, Any]) -> str:
        alerts = card.get("alerts") or [card]
        lines = [
            f"Title: {card.get('title', '')}",
            f"Forecast level: {card.get('forecast_level', '')}",
            f"Applicability: {card.get('applicability', card.get('applicability_confidence', ''))}",
            f"Confidence: {card.get('confidence', card.get('applicability_confidence', ''))}",
            f"Source: {card.get('source', '')}",
            f"KEV: {'yes' if card.get('kev') or card.get('kev_cves') else 'no'}",
            f"Apple related: {'yes' if card.get('apple_related') or card.get('source') == 'apple' else 'no'}",
            f"Why shown: {card.get('why_shown_to_you') or card.get('why_shown') or self._why_text(card)}",
            f"What to do now: {card.get('recommended_action', card.get('what_to_do', ''))}",
            f"Update guidance: {card.get('update_guidance', card.get('update_path', ''))}",
            f"References: {', '.join(str(item) for item in card.get('references', [])) or 'none'}",
            f"First seen: {card.get('first_seen', card.get('generated_at', ''))}",
            f"Last seen: {card.get('last_seen', card.get('generated_at', ''))}",
            "",
            "Surrounding evidence:",
        ]
        for alert in alerts:
            lines.extend(
                [
                    f"- CVE: {alert.get('cve_id', '')}",
                    f"  Product: {alert.get('detected_product', '')} {alert.get('detected_version', '')}".strip(),
                    f"  Local match: {json.dumps(alert.get('local_match_evidence', []), indent=2, sort_keys=True)}",
                    f"  Source trace: {alert.get('source_trace', '')}",
                    f"  Status: {alert.get('status', '')}",
                ]
            )
        return "\n".join(lines)

    def _why_text(self, card: dict[str, Any]) -> str:
        if card.get("why_shown_to_you") or card.get("why_shown"):
            return str(card.get("why_shown_to_you") or card.get("why_shown"))
        if card.get("apple_related") or card.get("source") == "apple":
            return "Apple-related CVE matched the detected macOS/browser family."
        evidence = card.get("local_match_evidence", [])
        if evidence:
            return f"Installed software match found with {card.get('applicability_confidence', card.get('confidence', 'review-needed'))} confidence."
        return "Version data is incomplete, so review is recommended."

    def _state_text(self, payload: dict[str, Any]) -> str:
        if not payload.get("timestamp") and not payload.get("generated_at"):
            return "Forecast not checked yet"
        if payload.get("last_error") and not payload.get("display_cards"):
            if payload.get("timestamp"):
                return "Unable to update forecast — using cache"
            return "Unable to update forecast — no cache available"
        level = str(payload.get("level", payload.get("forecast_level", ""))).lower()
        if level == "urgent":
            return "Urgent"
        if level == "elevated":
            return "Elevated"
        if level == "watch":
            return "Watch"
        if payload.get("display_cards"):
            return "Clear — no applicable Apple security updates found"
        return "Forecast not checked yet"

    def _reason_text(self, payload: dict[str, Any]) -> str:
        if not payload.get("timestamp") and not payload.get("generated_at"):
            return "No Apple Security Forecast has been checked yet."
        if payload.get("simulated"):
            return "Demo forecast is active."
        if payload.get("last_error") and not payload.get("display_cards"):
            return "Update failed and the panel is using cached data." if payload.get("timestamp") else "Update failed and no cache exists."
        cards = payload.get("alerts") or payload.get("cards") or payload.get("display_cards") or []
        statuses = [str(item.get("status", "")) for item in cards if isinstance(item, dict)]
        if cards and statuses and all(status in {"reviewed", "snoozed", "resolved"} for status in statuses):
            return "All matching items are snoozed or reviewed."
        if not payload.get("display_cards") and int(payload.get("hidden_review_needed_count", 0)) > 0:
            return "Only review-needed items were found and are hidden by default."
        if not payload.get("display_cards"):
            inventory = payload.get("inventory", {}) if isinstance(payload.get("inventory", {}), dict) else {}
            if str(inventory.get("software_update_check_status", "")) == "failed":
                return "Software update check failed; using cached advisory data."
            if not inventory.get("safari_version") and payload.get("safari_required"):
                return "Safari version could not be detected."
            if payload.get("catalog_update_status") == "offline-rules":
                return "Offline and no cache is available."
            return "No applicable Apple security advisories matched this Mac."
        return str(payload.get("summary", "")) or "Forecast data loaded."

    def current_card(self) -> dict[str, Any] | None:
        return self._selected_card

    def open_details(self) -> None:
        card = self.current_card()
        if not card:
            return
        self._open_card_details(card)

    def open_update_guidance(self) -> None:
        card = self.current_card()
        if not card:
            return
        self._open_card_update_guidance(card)

    def mark_reviewed(self) -> None:
        card = self.current_card()
        if not card:
            return
        self.review_requested.emit(card)

    def snooze_selected(self) -> None:
        card = self.current_card()
        if not card:
            return
        self._snooze_card(card)

    def _open_card_details(self, card: dict[str, Any]) -> None:
        dialog = CveRadarDetailsDialog(str(card.get("title", "Apple Security Forecast Details")), self._detail_text(card), self)
        dialog.exec()

    def _open_card_update_guidance(self, card: dict[str, Any]) -> None:
        dialog = CveRadarDetailsDialog(
            "Update Guidance",
            f"{card.get('update_guidance', '')}\n\nRecommended action:\n{card.get('recommended_action', '')}",
            self,
        )
        dialog.exec()

    def _review_card(self, card: dict[str, Any]) -> None:
        self.review_requested.emit(card)

    def _snooze_card(self, card: dict[str, Any]) -> None:
        dialog = CveRadarSnoozeDialog(self)
        if dialog.exec() != QDialog.Accepted:
            return
        self.snooze_requested.emit(card, dialog.values())

    def set_status(self, message: str) -> None:
        self.status_label.setText(message)

    def style_for_action_buttons(self) -> None:
        for button in [
            self.update_button,
            self.diagnostics_button,
            self.demo_button,
            self.safari_demo_button,
            self.clear_demo_button,
            self.export_button,
            self.details_button,
            self.review_button,
            self.snooze_button,
            self.guidance_button,
        ]:
            role = str(button.property("forecastButtonRole") or "secondary")
            button.setStyleSheet(BUTTON_STYLES.get(role, BUTTON_STYLES["secondary"]) + BUTTON_STYLES["disabled"])
