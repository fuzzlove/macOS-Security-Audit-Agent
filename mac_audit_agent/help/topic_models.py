from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class GlossaryTerm:
    term: str
    simple_definition: str
    technical_definition: str
    example: str = ""
    related_terms: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class TroubleshootingGuide:
    guide_id: str
    title: str
    category: str
    symptom: str
    likely_cause: str
    fix_steps: list[str]
    verification_steps: list[str]
    related_topics: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class HelpTopic:
    topic_id: str
    title: str
    short_summary: str
    user_friendly_explanation: str
    when_this_matters: list[str]
    what_you_should_do: list[str]
    advanced_details: str
    related_topics: list[str] = field(default_factory=list)
    glossary_terms: list[str] = field(default_factory=list)
    troubleshooting_steps: list[str] = field(default_factory=list)
    safety_notes: list[str] = field(default_factory=list)
    category: str = "Getting Started"
    audience: str = "Users, analysts, administrators, and incident responders."
    last_updated: str = "2026-07-05"
    resource: str = ""
    resource_content: str = ""
    diagnostic_codes: list[str] = field(default_factory=list)

    @property
    def summary(self) -> str:
        return self.short_summary

    @property
    def feature_area(self) -> str:
        return self.category

    @property
    def content(self) -> str:
        sections = [
            "What is this?",
            self.user_friendly_explanation,
            "Why does it matter?",
            "\n".join(f"- {item}" for item in self.when_this_matters),
            "What the user should do:",
            "\n".join(f"- {item}" for item in self.what_you_should_do),
            "Technical view",
            self.advanced_details,
        ]
        if self.safety_notes:
            sections.extend(["Safety notes", "\n".join(f"- {item}" for item in self.safety_notes)])
        return "\n\n".join(section for section in sections if section)

    @property
    def explanation(self) -> str:
        return self.content
