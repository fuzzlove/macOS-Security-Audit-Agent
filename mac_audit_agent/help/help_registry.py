from __future__ import annotations

from mac_audit_agent.help.help_center import DEFAULT_HELP_CENTER
from mac_audit_agent.help.topic_models import HelpTopic


def _topics() -> dict[str, HelpTopic]:
    return DEFAULT_HELP_CENTER.topics


def get_help_topic(topic_id: str) -> HelpTopic | None:
    return DEFAULT_HELP_CENTER.get_topic(topic_id)


def list_help_topics() -> list[HelpTopic]:
    return DEFAULT_HELP_CENTER.list_topics()


def get_related_topics(topic_id: str) -> list[HelpTopic]:
    return DEFAULT_HELP_CENTER.related_topics(topic_id)


def search_help_topics(query: str) -> list[HelpTopic]:
    return DEFAULT_HELP_CENTER.search(query)
