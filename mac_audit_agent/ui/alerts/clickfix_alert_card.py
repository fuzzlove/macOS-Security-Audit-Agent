from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QGridLayout, QLabel, QPushButton, QVBoxLayout, QWidget


class ClickFixAlertCard(QWidget):
    action_requested = Signal(str, str)

    def __init__(self, alert: dict, parent: QWidget | None = None) -> None:
        super().__init__(parent); self.alert = dict(alert)
        severity = str(alert.get("severity", "medium")).lower(); event_id = str(alert.get("event_id", "")); action_id = str(alert.get("alert_id") or event_id)
        self.setObjectName("clickFixCriticalAlert" if severity == "critical" else "clickFixMediumAlert")
        self.setAccessibleName(f"{severity.title()} ClickFix Guard alert {event_id}")
        self.setStyleSheet("#clickFixCriticalAlert { border: 3px solid #d93025; border-radius: 8px; background: #321414; } #clickFixMediumAlert { border: 2px solid #c69026; border-radius: 8px; background: #292313; }")
        layout = QVBoxLayout(self)
        title = QLabel(f"{'⛔ CRITICAL' if severity == 'critical' else '◆ MEDIUM'} — {alert.get('title', 'ClickFix Guard Event')}")
        title.setWordWrap(True); layout.addWidget(title)
        body = QLabel(str(alert.get("message") or alert.get("description") or "")); body.setWordWrap(True); layout.addWidget(body)
        self.occurrence_label = QLabel(""); self.occurrence_label.setWordWrap(True); self.occurrence_label.hide(); layout.addWidget(self.occurrence_label)
        self.occurrence_event_ids = [event_id]
        if severity == "critical":
            evidence = QLabel("\n".join((f"Event identifier: {event_id}", f"Incident identifier: {alert.get('incident_id') or 'pending'}", f"Classification: {alert.get('clipboard_classification') or 'unknown'}", f"Clipboard SHA-256: {alert.get('clipboard_sha256') or 'unavailable'}", f"ATT&CK: {alert.get('attack_mapping') or 'T1204.004'}", f"Spotlight suppressed: {bool(alert.get('spotlight_suppressed'))}", f"Clipboard quarantined: {bool(alert.get('clipboard_quarantined'))}")))
            evidence.setWordWrap(True); layout.addWidget(evidence)
        buttons = QGridLayout()
        actions = self._actions(severity)
        for index, (action, label, tooltip) in enumerate(actions):
            button = QPushButton(label); button.setToolTip(tooltip); button.clicked.connect(lambda _checked=False, a=action: self.action_requested.emit(a, action_id)); buttons.addWidget(button, index // 2, index % 2)
        layout.addLayout(buttons)

    def add_grouped_occurrence(self, event_id: str, timestamp: str) -> None:
        self.occurrence_event_ids.append(event_id)
        self.occurrence_label.setText(f"{len(self.occurrence_event_ids)} occurrences during the last 60 seconds\nLatest: {timestamp}")
        self.occurrence_label.show()

    @staticmethod
    def _actions(severity: str) -> tuple[tuple[str, str, str], ...]:
        if severity != "critical":
            return (
                ("view_shortcut", "View Shortcut Event", "Opens the immutable shortcut event, clipboard inspection result, foreground application, and sensor permission state."),
                ("open_settings", "Open ClickFix Guard Settings", "Opens ClickFix Guard mode, permission, alert, quarantine, and self-test settings. This does not change the current event."),
                ("dismiss", "Close Alert", "Closes this alert and records the dismissal. Detection evidence remains preserved."),
            )
        return (
            ("quarantine_open", "Quarantine Clipboard and Open Incident", "Replaces the current clipboard only when it still matches this incident, records the action, and opens incident details. The original is not restored automatically."),
            ("restore_quarantined", "Restore Quarantined Clipboard Content", "Restores the original clipboard content associated with this incident. The content may contain executable commands. Restoring it does not mark the content as safe and creates a new audited security event."),
            ("open_incident", "Open Incident Details", "Opens privacy-safe evidence, correlation status, and response guidance without displaying the complete raw command."),
            ("copy_incident_id", "Copy Incident Identifier", "Copies only the incident identifier for use with the approved incident-response team."),
            ("contact_ir", "Contact Incident Response Team", "Opens the configured incident-response workflow. MSAA does not transmit raw clipboard content."),
            ("acknowledge", "Acknowledge Potential ClickFix Incident", "Records the acknowledging user, time, and required reason. Evidence remains immutable and the disposition remains POTENTIAL_CLICKFIX."),
            ("dismiss", "Close Alert", "Closes this alert and records the dismissal. Detection and incident evidence remain preserved."),
        )
