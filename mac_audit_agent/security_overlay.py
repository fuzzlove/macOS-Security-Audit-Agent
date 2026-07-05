from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from datetime import datetime, timedelta, timezone

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import QApplication, QHBoxLayout, QLabel, QPushButton, QSizePolicy, QVBoxLayout, QWidget

from mac_audit_agent.alert_styles import SEVERITY_STYLES, canonical_alert_severity, get_alert_style

POLL_MILLISECONDS = 750


class SecurityOverlay(QWidget):
    def __init__(self, state_path: Path) -> None:
        super().__init__()
        self.state_path = state_path
        self._last_payload = ""
        self.setWindowTitle("Mac Audit Agent Security Notice")
        self.setWindowFlags(
            Qt.WindowType.Tool
            | Qt.WindowType.WindowStaysOnTopHint
            | Qt.WindowType.FramelessWindowHint
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, False)
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating, True)
        self.setFixedWidth(460)
        self.setObjectName("securityOverlayRoot")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 16, 16)
        layout.setSpacing(10)
        self.header_row = QHBoxLayout()
        self.header_row.setSpacing(10)
        self.icon = QLabel()
        self.icon.setObjectName("securityOverlayIcon")
        self.icon.setFixedSize(28, 28)
        self.icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.title = QLabel()
        self.title.setWordWrap(True)
        self.badge = QLabel()
        self.badge.setObjectName("securityOverlayBadge")
        self.badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.header_text = QVBoxLayout()
        self.header_text.setSpacing(6)
        self.header_text.addWidget(self.badge, 0, Qt.AlignmentFlag.AlignLeft)
        self.header_text.addWidget(self.title)
        self.header_row.addWidget(self.icon, 0, Qt.AlignmentFlag.AlignTop)
        self.header_row.addLayout(self.header_text, 1)
        self.details = QLabel()
        self.details.setWordWrap(True)
        self.evidence = QLabel()
        self.evidence.setWordWrap(True)
        self.evidence.setObjectName("securityOverlayEvidence")
        self.notice = QLabel(
            "Authorized use only. Activity is logged. This indicator is not a legal determination."
        )
        self.notice.setWordWrap(True)
        self.button_row = QVBoxLayout()
        self.open_timeline = QPushButton("Open Timeline")
        self.preserve_snapshot = QPushButton("Preserve Evidence Snapshot")
        self.acknowledge = QPushButton("Acknowledge")
        self.open_timeline.setObjectName("securityOverlayPrimaryButton")
        self.acknowledge.setObjectName("securityOverlayPrimaryButton")
        self.preserve_snapshot.setObjectName("securityOverlaySecondaryButton")
        self.open_timeline.setToolTip("Open the Security Timeline for this alert.")
        self.preserve_snapshot.setToolTip("Preserve a non-destructive evidence snapshot for review.")
        self.acknowledge.setToolTip("Acknowledge and hide this alert.")
        for button in [self.open_timeline, self.preserve_snapshot, self.acknowledge]:
            button.setMinimumHeight(34)
            button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.open_timeline.clicked.connect(lambda: self._set_requested_action("open_timeline"))
        self.preserve_snapshot.clicked.connect(lambda: self._set_requested_action("preserve_evidence_snapshot"))
        self.acknowledge.clicked.connect(self._acknowledge)
        for button in [self.open_timeline, self.preserve_snapshot, self.acknowledge]:
            self.button_row.addWidget(button)
        self.button_row.setSpacing(8)
        layout.addLayout(self.header_row)
        for widget in [self.details, self.evidence, self.notice]:
            layout.addWidget(widget)
        layout.addLayout(self.button_row)
        timer = QTimer(self)
        timer.timeout.connect(self.refresh)
        timer.start(POLL_MILLISECONDS)
        self.refresh()

    def refresh(self) -> None:
        try:
            raw = self.state_path.read_text(encoding="utf-8")
            payload = json.loads(raw)
        except (OSError, json.JSONDecodeError):
            self.hide()
            return
        if not payload.get("active", False):
            self.hide()
            return
        style_key = str(payload.get("style") or payload.get("severity", "info")).lower()
        severity = canonical_alert_severity(str(payload.get("severity") or style_key))
        style = get_alert_style(style_key)
        count = int(payload.get("count", 1) or 1)
        expires = self._expires_at(payload)
        if expires is not None and datetime.now(timezone.utc) > expires:
            self.hide()
            return
        if raw == self._last_payload:
            return
        self._last_payload = raw
        self.icon.setText(style.icon)
        self.title.setText(str(payload.get("title") or f"{severity.upper()} security alert"))
        self.badge.setText(severity.upper())
        self.details.setText(
            f"{payload.get('details') or payload.get('event_type', 'security_event')}\n\n"
            f"Detected: {payload.get('timestamp', '')}\n"
            f"Recommended action: {payload.get('recommended_action', 'Review Timeline')}\n"
            f"Grouped events: {count}"
            + (f"\n{payload.get('grouped_message')}" if payload.get("grouped_message") else "")
        )
        self.evidence.setText(f"Evidence: {payload.get('summary', '')}")
        self.setWindowOpacity(1.0)
        self.setStyleSheet(
            "#securityOverlayRoot {"
            f"background-color: {style.background};"
            f"border-left: 10px solid {style.border};"
            f"border-top: 2px solid {style.border};"
            f"border-right: 2px solid {style.border};"
            f"border-bottom: 2px solid {style.border};"
            "border-radius: 8px;"
            "}"
            f"QLabel {{ color: {style.body_text}; font-size: 13px; line-height: 1.35; }}"
            f"QLabel#securityOverlayIcon {{ color: {style.badge_text}; background-color: {style.badge_background}; border: 1px solid {style.border}; border-radius: 14px; font-size: 16px; font-weight: 900; }}"
            f"QLabel#securityOverlayBadge {{ background-color: {style.badge_background}; color: {style.badge_text}; border: 1px solid {style.border}; border-radius: 6px; padding: 4px 9px; font-size: 12px; font-weight: 800; }}"
            f"QLabel#securityOverlayEvidence {{ color: {style.body_text}; font-size: 12px; }}"
            f"QLabel {{ selection-background-color: {style.border}; }}"
            f"QLabel[objectName=''] {{ color: {style.body_text}; }}"
            "QPushButton {"
            f"background-color: {style.secondary_button_background};"
            f"border: 1px solid {style.border};"
            "border-radius: 6px;"
            "padding: 7px 10px;"
            f"color: {style.secondary_button_text};"
            "font-size: 12px;"
            "font-weight: 700;"
            "}"
            "QPushButton:hover {"
            "background-color: #344054;"
            "}"
            "QPushButton:focus {"
            f"border: 2px solid {style.focus_border};"
            "}"
            "QPushButton#securityOverlayPrimaryButton {"
            f"background-color: {style.primary_button_background};"
            f"color: {style.primary_button_text};"
            f"border: 1px solid {style.primary_button_background};"
            "}"
        )
        self.title.setStyleSheet(f"color: {style.title_text}; font-size: 15px; font-weight: 800;")
        self.adjustSize()
        self._move_to_bottom_right()
        self.show()
        self.raise_()
        self.activateWindow()

    def _expires_at(self, payload: dict[str, object]) -> datetime | None:
        raw = str(payload.get("expires_at") or "")
        if raw:
            try:
                parsed = datetime.fromisoformat(raw)
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                return parsed
            except ValueError:
                return None
        dismiss_after = int(payload.get("dismiss_after_seconds", 0) or 0)
        if dismiss_after <= 0:
            return None
        try:
            timestamp = datetime.fromisoformat(str(payload.get("timestamp", "")))
        except ValueError:
            return None
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        return timestamp + timedelta(seconds=dismiss_after)

    def _move_to_bottom_right(self) -> None:
        screen = QApplication.primaryScreen()
        if screen is None:
            return
        available = screen.availableGeometry()
        margin = 24
        self.move(available.right() - self.width() - margin, available.bottom() - self.height() - margin)

    def _acknowledge(self) -> None:
        try:
            payload = json.loads(self.state_path.read_text(encoding="utf-8"))
            payload["active"] = False
            payload["acknowledged_by_pid"] = os.getpid()
            payload["requested_action"] = "acknowledge"
            self.state_path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
        except (OSError, json.JSONDecodeError):
            pass
        self.hide()

    def _set_requested_action(self, action: str) -> None:
        try:
            payload = json.loads(self.state_path.read_text(encoding="utf-8"))
            payload["requested_action"] = action
            payload["requested_by_pid"] = os.getpid()
            self.state_path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
        except (OSError, json.JSONDecodeError):
            pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Mac Audit Agent persistent security overlay")
    parser.add_argument("--state-path", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    app = QApplication(sys.argv[:1])
    overlay = SecurityOverlay(args.state_path)
    overlay.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
