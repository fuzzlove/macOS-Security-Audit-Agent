from __future__ import annotations

from PySide6.QtWidgets import QPushButton, QWidget

from mac_audit_agent.help.glossary import glossary_tooltip
from mac_audit_agent.help.help_controller import DEFAULT_HELP_CONTROLLER
from mac_audit_agent.help.help_registry import get_help_topic
from mac_audit_agent.help.help_viewer import HelpViewer

CONTEXT_HELP_TOPICS: dict[str, str] = {
    "Dashboard": "dashboard",
    "Operational Health": "operational_health",
    "Apple Exposure Assessment": "apple_exposure",
    "Persistence Intelligence": "persistence_intelligence",
    "Keylogger Detection": "keylogger_detection",
    "Network Intelligence": "network_intelligence",
    "Live Response Collection": "live_response",
    "Family & Safety Center": "family_safety",
    "Family & Safety": "family_safety",
    "Reports": "reports_exports",
    "Settings": "settings",
    "Integrity Verification": "integrity_verification",
    "Pre-UAT Audit": "pre_uat_audit",
    "Framework Coverage": "framework_coverage",
}


def show_context_help(parent: QWidget | None, topic_id: str) -> HelpViewer:
    opener = getattr(parent, "open_help_topic", None)
    if callable(opener):
        opener(topic_id)
        viewer = getattr(parent, "help_viewer", None)
        if isinstance(viewer, HelpViewer):
            return viewer
    return DEFAULT_HELP_CONTROLLER.navigate_to_topic(topic_id, parent=parent)


def make_help_button(parent: QWidget | None, topic_id: str) -> QPushButton:
    topic = get_help_topic(topic_id)
    button = QPushButton("?")
    button.setObjectName(f"helpButton_{topic_id}")
    button.setFixedSize(28, 28)
    button.setToolTip(f"Contextual help: {topic.title if topic else topic_id}.")
    button.clicked.connect(lambda: show_context_help(parent, topic_id))
    return button


def glossary_tooltip_for(term: str) -> str:
    return glossary_tooltip(term)
