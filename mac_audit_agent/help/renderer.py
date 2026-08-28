from __future__ import annotations

import html

from mac_audit_agent.build_identity import detect_build_identity
from mac_audit_agent.help.help_center import HelpCenter
from mac_audit_agent.help.onboarding_guides import onboarding_html
from mac_audit_agent.help.topic_models import HelpTopic


def _items(items: list[str], empty: str = "No items configured.") -> str:
    if not items:
        return f"<li>{html.escape(empty)}</li>"
    return "".join(f"<li>{html.escape(item)}</li>" for item in items)


def _paragraph(text: str) -> str:
    return "".join(f"<p>{html.escape(part)}</p>" for part in text.split("\n\n") if part.strip())


class HelpRenderer:
    def __init__(self, help_center: HelpCenter) -> None:
        self.help_center = help_center

    def render_topic(self, topic: HelpTopic, *, advanced: bool = False) -> str:
        related = "".join(
            f'<li><a href="{related.topic_id}">{html.escape(related.title)}</a></li>'
            for related in self.help_center.related_topics(topic.topic_id)
        )
        glossary = "".join(self._render_glossary_term(term, advanced=advanced) for term in topic.glossary_terms)
        troubleshooting = "".join(self._render_troubleshooting(guide_id) for guide_id in topic.troubleshooting_steps)
        safety = f"<section class='safety'><h2>Safety Notes</h2><ul>{_items(topic.safety_notes)}</ul></section>" if topic.safety_notes else ""
        about = self._about_metadata_html() if topic.topic_id == "about_msaa" else ""
        onboarding = onboarding_html() if topic.topic_id == "help_center" else ""
        advanced_body = _paragraph(topic.advanced_details)
        advanced_section = (
            f"<section><h2>Technical View</h2>{advanced_body}</section>"
            if advanced
            else f"<details><summary>Technical View</summary>{advanced_body}</details>"
        )
        glossary_heading = "Glossary Terms" if topic.topic_id != "glossary" else "Searchable Glossary Terms"
        return f"""
        <html>
        <head>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; line-height: 1.48; color: #172033; }}
            h1 {{ font-size: 26px; margin-bottom: 4px; }}
            h2 {{ font-size: 18px; margin-top: 22px; }}
            section.action {{ border-left: 4px solid #2563EB; background: #EFF6FF; padding: 10px 14px; margin: 16px 0; }}
            section.safety {{ border-left: 4px solid #B45309; background: #FFF7ED; padding: 10px 14px; margin: 16px 0; }}
            details {{ margin-top: 18px; padding: 10px 12px; border: 1px solid #CBD5E1; border-radius: 6px; }}
            summary {{ font-weight: 700; cursor: pointer; }}
            a {{ color: #1D4ED8; text-decoration: none; }}
            .meta {{ color: #475569; font-size: 12px; }}
            .term {{ margin-bottom: 10px; }}
            table {{ border-collapse: collapse; }}
            th, td {{ padding: 4px 10px 4px 0; vertical-align: top; }}
        </style>
        </head>
        <body>
        <h1>{html.escape(topic.title)}</h1>
        <p><b>{html.escape(topic.short_summary)}</b></p>
        <p class="meta">Category: {html.escape(topic.category)} | Last updated: {html.escape(topic.last_updated)}</p>
        {onboarding}
        <section><h2>What Is This?</h2>{_paragraph(topic.user_friendly_explanation)}</section>
        <section><h2>Why It Matters</h2><ul>{_items(topic.when_this_matters)}</ul></section>
        <section class="action"><h2>How To — New to This?</h2><p>Start with these steps. You do not need prior MSAA experience.</p><ol>{_items(topic.what_you_should_do)}</ol></section>
        {advanced_section}
        {safety}
        {troubleshooting}
        {about}
        <section><h2>Related Topics</h2><ul>{related or "<li>No related topics configured.</li>"}</ul></section>
        <section><h2>{glossary_heading}</h2>{glossary or "<p>No glossary terms configured.</p>"}</section>
        </body>
        </html>
        """

    def _render_glossary_term(self, term: str, *, advanced: bool) -> str:
        entry = self.help_center.glossary_entry(term)
        if entry is None:
            return f"<div class='term'><b>{html.escape(term)}</b>: Open Help for more.</div>"
        detail = entry.technical_definition if advanced else entry.simple_definition
        example = f"<br><i>Example:</i> {html.escape(entry.example)}" if entry.example else ""
        related = f"<br><i>Related:</i> {html.escape(', '.join(entry.related_terms))}" if entry.related_terms else ""
        return f"<div class='term'><b>{html.escape(entry.term)}</b>: {html.escape(detail)}{example}{related}</div>"

    def _render_troubleshooting(self, guide_id: str) -> str:
        guide = self.help_center.troubleshooting_guide(guide_id)
        if guide is None:
            return ""
        return f"""
        <section>
        <h2>{html.escape(guide.title)}</h2>
        <p><b>Symptom:</b> {html.escape(guide.symptom)}</p>
        <p><b>Likely cause:</b> {html.escape(guide.likely_cause)}</p>
        <h3>Fix Steps</h3><ol>{_items(guide.fix_steps)}</ol>
        <h3>Verification Steps</h3><ol>{_items(guide.verification_steps)}</ol>
        </section>
        """

    def _about_metadata_html(self) -> str:
        try:
            identity = detect_build_identity()
        except Exception as exc:
            return f"<section><h2>Installed Build</h2><p>Build metadata unavailable: {html.escape(str(exc))}</p></section>"
        rows = [
            ("App name", identity.app_name),
            ("Version", identity.app_version),
            ("Build", identity.build_id or "not configured"),
            ("Package version", identity.package_version or "not installed as a package"),
            ("Install mode", identity.install_mode),
            ("Git commit", identity.git_commit or "not available"),
            ("License", "MIT"),
            ("Author/company", "Mac Audit Agent contributors"),
            ("Website", "https://github.com/fuzzlove/macOS-Security-Audit-Agent"),
            ("Executable", identity.executable_path),
            ("Runtime root", identity.runtime_root),
        ]
        rendered = "".join(f"<tr><th align='left'>{html.escape(label)}</th><td>{html.escape(str(value))}</td></tr>" for label, value in rows)
        return f"<section><h2>Installed Build</h2><table>{rendered}</table></section>"
