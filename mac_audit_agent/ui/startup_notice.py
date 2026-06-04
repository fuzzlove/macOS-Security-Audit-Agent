from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from PySide6.QtWidgets import QDialog, QDialogButtonBox, QLabel, QTextBrowser, QVBoxLayout


STARTUP_NOTICE_VERSION = "2026-06-02"
STARTUP_NOTICE_TITLE = "One-Time EULA Preview - Friendly, Non-Binding Reminder"
STARTUP_NOTICE_TEXT = """Before you continue

This is a one-time preview of the user notice that may later become part of a formal EULA. It is a friendly operational reminder only. It has not been reviewed by legal counsel, is not a contract, and does not ask you to waive rights or accept legal terms.

Please continue only if you understand the following:

1. Use this app only on Macs, accounts, and networks you own or are explicitly authorized to assess. This reminder does not grant permission to inspect anyone else's device, account, traffic, or data.

2. This is defensive security software, not a guarantee of protection. Findings, risk scores, CVE matches, alerts, and recommendations may be incomplete, delayed, or wrong. Normal activity may look suspicious, and harmful activity may be missed. An alert is a reason to review context, not proof of compromise, misconduct, or a legal violation.

3. Evidence can be sensitive. Local logs, reports, notes, process details, network metadata, packet-capture files, device identifiers, and exported artifacts may reveal private or regulated information. Review before collecting, retain only what you need, protect access, and share carefully.

4. Background monitoring is optional. If you install or start it, it can continue in your user session after the main window closes until you stop or uninstall it. Review monitor settings and event priorities before relying on notifications.

5. Read-only inspection is the default, but some optional workflows can create files, capture local traffic, perform network discovery, install monitoring components, or propose cleanup and recovery actions. Those actions should remain visible and separately confirmed. Do not treat this preview as approval for future actions.

6. Avoid automatic or disruptive response based only on an alert. Validate scope, preserve evidence when appropriate, consider business impact, and involve qualified incident-response, IT, privacy, or legal professionals when the situation calls for them.

7. You remain in control. You may exit now, use only the features you choose, stop monitoring, and review exports before sharing them.

Selecting "Continue to App" records only that this reminder was previewed on this Mac so it is not shown every launch. It is not consent to surveillance, not authorization to assess third parties, and not acceptance of a binding agreement."""


def default_startup_notice_state_path() -> Path:
    return Path.home() / ".mac_audit_agent" / "state" / "startup_notice.json"


def startup_notice_has_been_previewed(state_path: Path | None = None) -> bool:
    path = state_path or default_startup_notice_state_path()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return False
    return payload.get("notice_version") == STARTUP_NOTICE_VERSION and payload.get("previewed") is True


def record_startup_notice_preview(state_path: Path | None = None) -> None:
    path = state_path or default_startup_notice_state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_suffix(f"{path.suffix}.tmp")
    payload = {
        "notice_version": STARTUP_NOTICE_VERSION,
        "previewed": True,
        "previewed_at": datetime.now(timezone.utc).isoformat(),
        "binding_agreement": False,
    }
    temporary_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary_path, path)


class StartupNoticeDialog(QDialog):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(STARTUP_NOTICE_TITLE)
        self.resize(760, 680)

        layout = QVBoxLayout(self)
        summary = QLabel(
            "<b>Please preview this reminder before using macOS Security Audit Agent.</b><br>"
            "You can exit without recording anything or continue to the app."
        )
        summary.setWordWrap(True)
        layout.addWidget(summary)

        notice = QTextBrowser()
        notice.setPlainText(STARTUP_NOTICE_TEXT)
        layout.addWidget(notice)

        buttons = QDialogButtonBox()
        exit_button = buttons.addButton("Exit for Now", QDialogButtonBox.RejectRole)
        continue_button = buttons.addButton("Continue to App", QDialogButtonBox.AcceptRole)
        exit_button.clicked.connect(self.reject)
        continue_button.clicked.connect(self.accept)
        layout.addWidget(buttons)


def preview_startup_notice(parent=None, state_path: Path | None = None) -> bool:
    if startup_notice_has_been_previewed(state_path):
        return True
    if StartupNoticeDialog(parent).exec() != QDialog.Accepted:
        return False
    try:
        record_startup_notice_preview(state_path)
    except OSError:
        # A read-only home directory should not block use of the app.
        # The reminder will appear again next launch if it cannot be recorded.
        pass
    return True
