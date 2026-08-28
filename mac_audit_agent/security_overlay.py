from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from datetime import datetime, timedelta, timezone

from mac_audit_agent.runtime.gui_preflight import require_gui_preflight

_IMPORT_PREFLIGHT = require_gui_preflight()

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QCursor
from PySide6.QtWidgets import QApplication, QHBoxLayout, QLabel, QPushButton, QSizePolicy, QVBoxLayout, QWidget

from mac_audit_agent.alerts.action_handler import enqueue_and_handle_alert_action
from mac_audit_agent.alerts.action_model import request_from_alert_payload
from mac_audit_agent.alert_styles import SEVERITY_STYLES, canonical_alert_severity, get_alert_style
from mac_audit_agent.storage import AuditDatabase

POLL_MILLISECONDS = 750


class SecurityOverlay(QWidget):
    def __init__(self, state_path: Path, *, parent_pid: int = 0) -> None:
        super().__init__()
        self.state_path = state_path
        self.parent_pid = int(parent_pid or 0)
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
        self.action_status = QLabel("")
        self.action_status.setWordWrap(True)
        self.action_status.setObjectName("securityOverlayActionStatus")
        self.button_row = QVBoxLayout()
        self.open_timeline = QPushButton("Open Timeline")
        self.preserve_snapshot = QPushButton("Preserve Evidence Snapshot")
        self.acknowledge = QPushButton("Acknowledge")
        self.open_timeline.setObjectName("securityOverlayPrimaryButton")
        self.acknowledge.setObjectName("securityOverlayPrimaryButton")
        self.preserve_snapshot.setObjectName("securityOverlaySecondaryButton")
        self.open_timeline.setToolTip("Opens the complete event timeline. This does not acknowledge the alert, suppress future notifications, or modify evidence.")
        self.preserve_snapshot.setToolTip("Creates a non-destructive evidence snapshot for authorized review. This does not acknowledge or suppress the alert.")
        self.acknowledge.setToolTip("Records acknowledgment and hides this presentation only. Evidence is retained; this does not authorize the change or suppress future events.")
        for button in [self.open_timeline, self.preserve_snapshot, self.acknowledge]:
            button.setMinimumHeight(34)
            button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.open_timeline.clicked.connect(lambda: self._handle_action("open_timeline"))
        self.preserve_snapshot.clicked.connect(lambda: self._handle_action("preserve_evidence_snapshot"))
        self.acknowledge.clicked.connect(self._acknowledge)
        for button in [self.open_timeline, self.preserve_snapshot, self.acknowledge]:
            self.button_row.addWidget(button)
        self.button_row.setSpacing(8)
        layout.addLayout(self.header_row)
        for widget in [self.details, self.evidence, self.notice, self.action_status]:
            layout.addWidget(widget)
        layout.addLayout(self.button_row)
        timer = QTimer(self)
        timer.timeout.connect(self.refresh)
        timer.start(POLL_MILLISECONDS)
        parent_timer = QTimer(self)
        parent_timer.timeout.connect(self._verify_notifier_parent)
        parent_timer.start(2000)
        self.refresh()

    def _verify_notifier_parent(self) -> None:
        if self.parent_pid <= 1:
            return
        try:
            os.kill(self.parent_pid, 0)
        except OSError:
            QApplication.quit()

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
        from mac_audit_agent.alert_styles import resolve_alert_severity
        severity = resolve_alert_severity(str(payload.get("severity") or style_key), cvss_score=payload.get("cvss_score"))
        style = get_alert_style(severity)
        count = int(payload.get("count", 1) or 1)
        expires = self._expires_at(payload)
        if severity not in {"high", "critical"} and expires is not None and datetime.now(timezone.utc) > expires:
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
        self.action_status.setText(str(payload.get("action_feedback") or ""))
        missing_context = not str(payload.get("event_id") or "").strip()
        for button in [self.open_timeline, self.preserve_snapshot]:
            button.setEnabled(not missing_context)
            if missing_context:
                button.setToolTip("Unavailable: missing event ID.")
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
            f"QLabel#securityOverlayActionStatus {{ color: {style.body_text}; font-size: 12px; font-weight: 700; }}"
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
            "QPushButton:disabled { background-color: #667085; color: #d0d5dd; }"
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
        # Delay the acknowledgement until Qt has processed the native show
        # request.  The notifier must never equate process launch with a visible
        # bottom-right alert.
        QTimer.singleShot(500, lambda payload=dict(payload): self._record_visible_acknowledgement(payload))

    def _record_visible_acknowledgement(self, payload: dict[str, object]) -> None:
        event_id = str(payload.get("event_id") or "").strip()
        trace_id = str(payload.get("trace_id") or f"trace-{event_id}").strip()
        db_path = str(payload.get("source_db_path") or "").strip()
        screen = self.screen() or QApplication.primaryScreen()
        on_screen = bool(screen and screen.availableGeometry().intersects(self.frameGeometry()))
        visible = bool(event_id and self.isVisible() and self.winId() and on_screen)
        now = datetime.now(timezone.utc).isoformat()
        if db_path and trace_id:
            try:
                with AuditDatabase(Path(db_path).expanduser()) as db:
                    db.update_event_alert_trace(
                        trace_id,
                        overlay_dispatch_result="SUCCESS" if visible else "FAILED",
                        overlay_error="" if visible else "overlay_window_not_visible_on_screen",
                        visible_alert_id=event_id if visible else "",
                        displayed_at=now if visible else "",
                        render_verification_status="verified_visible" if visible else "failed_window_not_visible",
                    )
                    db.set_background_monitor_state("overlay_manager_alive", "1")
                    db.set_background_monitor_state("overlay_dispatch_result", "SUCCESS" if visible else "FAILED")
                    db.set_background_monitor_state("last_alert_displayed_at", now if visible else "")
                    db.set_background_monitor_state("last_alert_failure_stage", "" if visible else "overlay_window_visibility")
                    db.set_background_monitor_state("last_overlay_error", "" if visible else "overlay_window_not_visible_on_screen")
            except Exception:
                return
        try:
            current = json.loads(self.state_path.read_text(encoding="utf-8"))
            if str(current.get("event_id") or "") == event_id:
                current["visible_alert_shown"] = visible
                current["render_acknowledged_at"] = now
                current["render_pid"] = os.getpid()
                current["render_geometry"] = [self.x(), self.y(), self.width(), self.height()]
                self.state_path.write_text(json.dumps(current, sort_keys=True), encoding="utf-8")
        except (OSError, json.JSONDecodeError):
            pass

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
        screen = QApplication.screenAt(QCursor.pos()) or QApplication.primaryScreen()
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
            self._enqueue_action_from_payload(payload, "acknowledge")
            self.state_path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
        except (OSError, json.JSONDecodeError):
            pass
        self.hide()

    def _handle_action(self, action: str) -> None:
        try:
            payload = json.loads(self.state_path.read_text(encoding="utf-8"))
            payload["requested_action"] = action
            payload["requested_by_pid"] = os.getpid()
            payload["action_feedback"] = "Working..."
            self.action_status.setText("Working...")
            self.state_path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
            result_message = self._enqueue_action_from_payload(payload, action)
            payload["action_feedback"] = result_message
            self.state_path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
            self.action_status.setText(result_message)
        except (OSError, json.JSONDecodeError):
            pass

    def _enqueue_action_from_payload(self, payload: dict[str, object], action: str) -> str:
        db_path = str(payload.get("source_db_path") or payload.get("db_path") or "")
        if not db_path:
            return "Action failed: db_write_failed."
        try:
            with AuditDatabase(Path(db_path).expanduser()) as db:
                request = request_from_alert_payload(
                    payload,
                    action,
                    source_component="user_notifier",
                    source_db_path=db_path,
                )
                result = enqueue_and_handle_alert_action(db, request)
        except Exception as exc:  # noqa: BLE001
            return f"{self._label_for_action(action)} failed: {exc}"
        if result.status == "succeeded":
            if action == "preserve_evidence_snapshot":
                path = result.artifact_paths[0] if result.artifact_paths else ""
                package_hash = str(result.diagnostic_details.get("package_sha256", ""))
                return f"Evidence snapshot saved. {path} {package_hash}".strip()
            if action == "open_timeline":
                return "Timeline opened."
            return result.user_message or "Action complete."
        if result.status == "queued_for_main_gui":
            return result.user_message or "Timeline queued. Open MSAA to view it."
        if action == "preserve_evidence_snapshot":
            return f"Evidence snapshot failed: {result.failure_stage or 'unknown'}."
        if action == "open_timeline":
            return f"Open Timeline failed: {result.failure_stage or 'unknown'}."
        return result.user_message or f"{self._label_for_action(action)} failed."

    def _label_for_action(self, action: str) -> str:
        return {
            "open_timeline": "Open Timeline",
            "preserve_evidence_snapshot": "Evidence snapshot",
            "acknowledge": "Acknowledge",
        }.get(action, action)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Mac Audit Agent persistent security overlay")
    parser.add_argument("--state-path", type=Path, required=True)
    parser.add_argument("--parent-pid", type=int, default=0)
    return parser


def main(argv: list[str] | None = None) -> int:
    from mac_audit_agent.runtime.qapplication_guard import assert_qapplication_allowed

    args = build_parser().parse_args(argv)
    assert_qapplication_allowed()
    app = QApplication(sys.argv[:1])
    overlay = SecurityOverlay(args.state_path, parent_pid=args.parent_pid)
    overlay.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
