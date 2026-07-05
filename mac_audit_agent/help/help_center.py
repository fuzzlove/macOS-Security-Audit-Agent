from __future__ import annotations

from functools import cached_property

from mac_audit_agent.help.glossary import GlossaryTerm, get_glossary_entry, search_glossary
from mac_audit_agent.help.navigation_tree import HELP_CATEGORIES
from mac_audit_agent.help.topic_models import HelpTopic, TroubleshootingGuide
from mac_audit_agent.help.topic_registry import get_topic, list_topics, search_topics
from mac_audit_agent.help.troubleshooting_guides import get_troubleshooting_guide, list_troubleshooting_guides


class HelpCenter:
    """Central navigation and structured knowledge base for MSAA Help."""

    @cached_property
    def topics(self) -> dict[str, HelpTopic]:
        return {topic.topic_id: topic for topic in list_topics()}

    def get_topic(self, topic_id: str) -> HelpTopic | None:
        return self.topics.get(topic_id) or get_topic(topic_id)

    def list_topics(self) -> list[HelpTopic]:
        return [topic for topic in list_topics()]

    def related_topics(self, topic_id: str) -> list[HelpTopic]:
        topic = self.get_topic(topic_id)
        if topic is None:
            return []
        return [related for related_id in topic.related_topics if (related := self.get_topic(related_id)) is not None]

    def search(self, query: str) -> list[HelpTopic]:
        return search_topics(query)

    def navigation(self) -> dict[str, list[HelpTopic]]:
        return {
            category: [topic for topic_id in topic_ids if (topic := self.get_topic(topic_id)) is not None]
            for category, topic_ids in HELP_CATEGORIES.items()
        }

    def glossary_entry(self, term: str) -> GlossaryTerm | None:
        return get_glossary_entry(term)

    def search_glossary(self, query: str) -> list[GlossaryTerm]:
        return search_glossary(query)

    def troubleshooting_guide(self, guide_id: str) -> TroubleshootingGuide | None:
        return get_troubleshooting_guide(guide_id)

    def troubleshooting_guides(self) -> list[TroubleshootingGuide]:
        return list_troubleshooting_guides()


DEFAULT_HELP_CENTER = HelpCenter()
