from __future__ import annotations

import hashlib
import os
from pathlib import Path

from PySide6.QtWidgets import QCheckBox, QDialog, QDialogButtonBox, QLabel, QTextBrowser, QVBoxLayout

from mac_audit_agent.mission_governance import EULAAcceptanceStore
from mac_audit_agent.version import APP_VERSION

EULA_VERSION = "DRAFT-1.0"
OPENING_NOTICE = """IMPORTANT — AUTHORIZED USE ONLY; MISUSE PROHIBITED

MSAA is intended solely for lawful and explicitly authorized cybersecurity, mission-assurance, defensive, research, compliance, and security-validation activities.

The software license and an NDA do not grant permission to access or affect another party's systems. You must possess current authority for every system, network, account, application, device, data set, and action. MSAA must not be used to exceed authorization, impair systems, evade controls, misuse data, conduct unlawful surveillance, or act outside approved rules of engagement.

AI and machine-learning outputs may be inaccurate, incomplete, inconsistent, outdated, or unsupported. Independently verify material outputs, commands, configurations, citations, vulnerability identifiers, control mappings, and MITRE ATT&CK mappings before consequential use.

This is draft legal language requiring qualified legal review. Acceptance records software terms only; it is not system authorization."""


def default_eula_database() -> Path:
    return Path.home() / ".mac_audit_agent" / "governance.sqlite3"


def local_user_reference() -> str:
    return "local-user-" + hashlib.sha256(str(os.getuid()).encode()).hexdigest()[:16]


class EULAAcceptanceDialog(QDialog):
    def __init__(self, parent=None) -> None:
        super().__init__(parent); self.setWindowTitle("Draft MSAA EULA — Authorized Use Only"); self.resize(760, 620)
        layout=QVBoxLayout(self); heading=QLabel("<b>Review and accept the current draft EULA version before continuing.</b>");heading.setWordWrap(True);layout.addWidget(heading)
        text=QTextBrowser();text.setPlainText(OPENING_NOTICE);layout.addWidget(text)
        self.confirm=QCheckBox("I accept the software terms and understand this does not grant target authorization.");layout.addWidget(self.confirm)
        buttons=QDialogButtonBox();accept=buttons.addButton("Accept and Continue",QDialogButtonBox.AcceptRole);decline=buttons.addButton("Decline and Exit",QDialogButtonBox.RejectRole);accept.setEnabled(False);self.confirm.toggled.connect(accept.setEnabled);accept.clicked.connect(self.accept);decline.clicked.connect(self.reject);layout.addWidget(buttons)


def require_current_eula_acceptance(parent=None, *, database: Path | None = None, user_reference: str | None = None) -> bool:
    store=EULAAcceptanceStore(database or default_eula_database()); user=user_reference or local_user_reference()
    dialog=EULAAcceptanceDialog(parent)
    if dialog.exec()!=QDialog.Accepted or not dialog.confirm.isChecked(): return False
    store.accept(user,EULA_VERSION,APP_VERSION);return True


__all__=["EULA_VERSION","EULAAcceptanceDialog","OPENING_NOTICE","require_current_eula_acceptance"]
