from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from datetime import datetime, timedelta, timezone

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import QApplication, QHBoxLayout, QLabel, QPushButton, QSizePolicy, QVBoxLayout, QWidget


POLL_MILLISECONDS = 750
SEVERITY_STYLES = {
    "neutral_grey": {"background": "rgba(60, 65, 75, 214)", "border": "rgba(210, 216, 230, 120)", "opacity": 0.90},
    "high_orange": {"background": "rgba(185, 95, 25, 219)", "border": "rgba(255, 214, 153, 140)", "opacity": 0.94},
    "critical_red": {"background": "rgba(170, 14, 28, 248)", "border": "rgba(255, 225, 225, 210)", "opacity": 1.0},
}


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
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating, True)
        self.setFixedWidth(390)
        self.setObjectName("securityOverlayRoot")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 14)
        self.title = QLabel()
        self.title.setStyleSheet("font-size: 15px; font-weight: bold;")
        self.badge = QLabel()
        self.badge.setObjectName("securityOverlayBadge")
        self.badge.setStyleSheet(
            "font-size: 11px; font-weight: 700; letter-spacing: 1px; "
            "padding: 3px 8px; border-radius: 8px; color: #FFFFFF;"
        )
        self.details = QLabel()
        self.details.setWordWrap(True)
        self.evidence = QLabel()
        self.evidence.setWordWrap(True)
        self.notice = QLabel(
            "Authorized use only. Activity is logged. This indicator is not a legal determination."
        )
        self.notice.setWordWrap(True)
        self.notice.setStyleSheet("font-size: 11px;")
        self.button_row = QVBoxLayout()
        self.open_timeline = QPushButton("Open Timeline")
        self.preserve_snapshot = QPushButton("Preserve Evidence Snapshot")
        self.acknowledge = QPushButton("Acknowledge")
        for button in [self.open_timeline, self.preserve_snapshot, self.acknowledge]:
            button.setMinimumHeight(34)
            button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            button.setStyleSheet(
                "QPushButton {"
                "padding: 6px 10px;"
                "font-size: 12px;"
                "font-weight: 600;"
                "border-radius: 8px;"
                "}"
            )
        self.open_timeline.clicked.connect(lambda: self._set_requested_action("open_timeline"))
        self.preserve_snapshot.clicked.connect(lambda: self._set_requested_action("preserve_evidence_snapshot"))
        self.acknowledge.clicked.connect(self._acknowledge)
        for button in [self.open_timeline, self.preserve_snapshot, self.acknowledge]:
            self.button_row.addWidget(button)
        self.button_row.setSpacing(8)
        for widget in [self.title, self.details, self.evidence, self.notice]:
            widget.setStyleSheet("color: #FFFFFF;")
            layout.addWidget(widget)
        layout.insertWidget(0, self.badge)
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
        severity = str(payload.get("style") or payload.get("severity", "neutral_grey")).lower()
        count = int(payload.get("count", 1) or 1)
        expires = self._expires_at(payload)
        if expires is not None and datetime.now(timezone.utc) > expires:
            self.hide()
            return
        if raw == self._last_payload:
            return
        self._last_payload = raw
        self.title.setText(str(payload.get("title") or f"{severity.replace('_', ' ').upper()} security indicator"))
        if severity == "critical_red":
            self.badge.setText("CRITICAL ALERT")
        elif severity == "high_orange":
            self.badge.setText("HIGH PRIORITY")
        else:
            self.badge.setText("INFORMATIONAL")
        self.details.setText(
            f"{payload.get('details') or payload.get('event_type', 'security_event')}\n"
            f"Detected: {payload.get('timestamp', '')}\n"
            f"Grouped events: {count}"
            + (f"\n{payload.get('grouped_message')}" if payload.get("grouped_message") else "")
        )
        self.evidence.setText(str(payload.get("summary", "")))
        style = SEVERITY_STYLES.get(severity, SEVERITY_STYLES["neutral_grey"])
        self.setWindowOpacity(style["opacity"])
        badge_style = {
            "critical_red": "background-color: rgba(110, 8, 18, 255); border: 1px solid rgba(255, 220, 220, 220);",
            "high_orange": "background-color: rgba(135, 71, 18, 255); border: 1px solid rgba(255, 227, 182, 200);",
            "neutral_grey": "background-color: rgba(72, 78, 88, 255); border: 1px solid rgba(220, 226, 235, 150);",
        }.get(severity, "background-color: rgba(72, 78, 88, 255); border: 1px solid rgba(220, 226, 235, 150);")
        self.setStyleSheet(
            "#securityOverlayRoot {"
            f"background-color: {style['background']};"
            f"border: 1px solid {style['border']};"
            "border-radius: 14px;"
            "}"
            f"QLabel {{ color: #FFFFFF; }}"
            f"QLabel[objectName='securityOverlayBadge'] {{ {badge_style} }}"
            "QPushButton {"
            "background-color: rgba(255, 255, 255, 28);"
            "border: 1px solid rgba(255, 255, 255, 60);"
            "border-radius: 8px;"
            "padding: 6px 10px;"
            "color: #FFFFFF;"
            "}"
            "QPushButton:hover {"
            "background-color: rgba(255, 255, 255, 40);"
            "}"
        )
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
        margin = 18
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
