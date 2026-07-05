from __future__ import annotations

from functools import lru_cache

from mac_audit_agent.help.navigation_tree import HELP_CATEGORIES
from mac_audit_agent.help.topic_models import HelpTopic
from mac_audit_agent.help.troubleshooting_guides import TROUBLESHOOTING_GUIDES


def _topic(
    topic_id: str,
    title: str,
    category: str,
    summary: str,
    explanation: str,
    matters: list[str],
    actions: list[str],
    advanced: str,
    related: list[str],
    glossary: list[str],
    troubleshooting: list[str] | None = None,
    safety: list[str] | None = None,
) -> HelpTopic:
    return HelpTopic(
        topic_id=topic_id,
        title=title,
        category=category,
        short_summary=summary,
        user_friendly_explanation=explanation,
        when_this_matters=matters,
        what_you_should_do=actions,
        advanced_details=advanced,
        related_topics=related,
        glossary_terms=glossary,
        troubleshooting_steps=troubleshooting or [],
        safety_notes=safety or [],
    )


TOPICS: dict[str, HelpTopic] = {
    "help_center": _topic(
        "help_center",
        "MSAA Help Center",
        "Getting Started",
        "A structured guide to MSAA features, terms, troubleshooting, and next steps.",
        "The Help Center is the central knowledge base for MSAA. It groups product guidance by workflow so you can learn what a feature means, why it matters, and what to do next without reading developer notes or raw logs.",
        ["You are new to MSAA.", "You need one place to understand alerts, health, integrity, exposure, reports, and response workflows."],
        ["Start with Getting Started if you are new.", "Use search for specific terms such as integrity, KEV, baseline, or LaunchAgent.", "Open contextual Help from a screen when you need guidance for the thing you are viewing."],
        "Help topics are registered through HelpCenter and topic_registry. UI code should link to topic IDs instead of embedding scattered help text.",
        ["how_msaa_works", "alert_severity", "troubleshooting"],
        ["evidence snapshot", "alert severity levels"],
    ),
    "how_msaa_works": _topic(
        "how_msaa_works",
        "How MSAA Works",
        "Getting Started",
        "Plain-language explanation of scans, monitor events, alerts, findings, reports, and snapshots.",
        "MSAA collects local security information, normalizes it into findings and events, and helps you review risk. Scans show current state. Background monitoring shows change over time. Reports and snapshots preserve or share what was observed.",
        ["You need to know whether a result is a live alert, a scan finding, or preserved evidence.", "You are deciding whether to run a scan, export a report, or collect a snapshot."],
        ["Use scans for current state.", "Use monitor events for ongoing change.", "Use evidence snapshots before repair or cleanup when a finding may matter."],
        "MSAA stores findings, settings, events, and reports locally. Severity scoring and feature-specific models help group evidence without claiming a single signal proves compromise.",
        ["dashboard", "alert_severity", "reports_exports"],
        ["evidence snapshot", "baseline", "false positive"],
    ),
    "dashboard": _topic(
        "dashboard",
        "Dashboard",
        "Getting Started",
        "The dashboard is the starting view for scan state, security score, exposure, health, and integrity signals.",
        "The Dashboard gives a current orientation point. It summarizes important areas so you can decide what to review first.",
        ["You need a quick status check.", "You want to prioritize before opening detailed feature pages."],
        ["Run a safe scan on a new Mac.", "Review HIGH or CRITICAL indicators first.", "Open the feature page behind any card before changing settings."],
        "Dashboard cards combine scan results, health checks, exposure data, severity counts, and integrity status. They are triage summaries, not final determinations.",
        ["how_msaa_works", "alert_severity", "operational_health"],
        ["alert severity levels", "integrity", "evidence snapshot"],
    ),
    "alert_severity": _topic(
        "alert_severity",
        "Alert Severity Guide",
        "Alerts & Security Events",
        "Definitions for INFO, LOW, MEDIUM, HIGH, and CRITICAL alerts and how to respond.",
        "Alert severity tells you how quickly to review an event. INFO is informational, LOW is low-risk context, MEDIUM should be reviewed, HIGH needs prompt review, and CRITICAL needs immediate attention.",
        ["You see an alert and need to decide whether to pause, preserve evidence, or continue normal work.", "You are tuning alert thresholds."],
        ["Treat HIGH and CRITICAL as review prompts, not automatic proof.", "Lower thresholds only if you can tolerate more alerts.", "For unexplained high-risk alerts, preserve evidence before repair."],
        "Canonical severity names are INFO, LOW, MEDIUM, HIGH, and CRITICAL. Events may be logged without visible notification when below threshold, suppressed by policy, grouped, or useful only as evidence.",
        ["operational_health", "troubleshooting", "flight_recorder"],
        ["alert severity levels", "false positive", "evidence snapshot"],
        ["alerts_not_appearing"],
    ),
    "intrusion_detection": _topic(
        "intrusion_detection",
        "Intrusion Detection",
        "Alerts & Security Events",
        "How intrusion signals are grouped into reviewable security events.",
        "Intrusion Detection organizes suspicious local behaviors into findings that can be reviewed with context, confidence, severity, and recommended action.",
        ["You need to understand why a behavior was flagged.", "You are deciding whether to collect evidence or mark activity expected."],
        ["Read the explanation and evidence summary first.", "Check whether the activity matches known software or administration.", "Preserve evidence before changing files or services."],
        "Detection output should summarize evidence rather than dump raw logs. Technical evidence belongs in reports and evidence views with redaction where appropriate.",
        ["alert_severity", "live_response", "reports_exports"],
        ["false positive", "evidence snapshot", "MITRE ATT&CK"],
    ),
    "flight_recorder": _topic(
        "flight_recorder",
        "Flight Recorder",
        "Alerts & Security Events",
        "A timeline view for surrounding activity and correlated patterns.",
        "Flight Recorder helps you understand what happened around an event by showing nearby activity and related signals.",
        ["You need timeline context for an alert.", "You are checking whether several low-level signals form a pattern."],
        ["Review surrounding events before acting.", "Use snapshots or reports for high-risk timelines.", "Avoid assuming correlation means causation without evidence."],
        "Timeline views should present normalized event summaries and linked evidence, not raw debug streams.",
        ["alert_severity", "live_response", "reports_exports"],
        ["evidence snapshot", "false positive"],
    ),
    "operational_health": _topic(
        "operational_health",
        "Operational Health",
        "System Health",
        "How to interpret healthy, degraded, broken, and critical MSAA component states.",
        "Operational Health tells you whether MSAA itself can scan, monitor, alert, store data, keep settings consistent, and export reports.",
        ["A feature appears empty or unreliable.", "Alerts are missing.", "A daemon, notifier, storage, export, or settings check reports trouble."],
        ["Refresh health before an investigation.", "Repair MSAA components before changing unrelated macOS settings.", "If health is critical, fix monitoring or notifier delivery before relying on alert coverage."],
        "Health states are healthy, degraded, broken, and critical. They describe MSAA component reliability, not whether the Mac is compromised.",
        ["settings", "integrity_verification", "troubleshooting"],
        ["daemon", "notifier", "drift", "integrity"],
        ["daemon_not_running", "alerts_not_appearing"],
    ),
    "settings": _topic(
        "settings",
        "Settings",
        "System Health",
        "How monitor, notifier, event priority, health, and appearance settings affect MSAA.",
        "Settings control monitoring, notification thresholds, event priorities, appearance, and selected diagnostic behavior.",
        ["You are changing how much MSAA alerts.", "You are repairing monitor deployment or notification behavior."],
        ["Document threshold changes.", "Keep developer-mode controls disabled during normal use.", "Use Operational Health repair actions when component checks fail."],
        "Settings can affect visible alerts without deleting stored evidence. Developer synthetic events are for validation and should not be treated as real security findings.",
        ["operational_health", "alert_severity", "troubleshooting"],
        ["notifier", "daemon", "alert severity levels"],
        ["usb_bluetooth_not_detected", "daemon_not_running"],
    ),
    "integrity_verification": _topic(
        "integrity_verification",
        "Integrity Verification",
        "Integrity & Trust",
        "How trusted manifests and SHA-256 hashes detect modified, stale, unknown, verified, or draft installs.",
        "Integrity Verification compares protected MSAA files with a trusted manifest. It helps detect unexpected application changes while ignoring files expected to change, such as reports, logs, settings, caches, and databases.",
        ["MSAA reports modified, stale, unknown, draft, or verified state.", "You are checking whether the installed app still matches the trusted build."],
        ["Do not overwrite an unexplained mismatch.", "Export the integrity report and create an evidence snapshot.", "After a trusted update, use the matching trusted manifest."],
        "Integrity states are verified, modified, stale, unknown, and draft. SHA-256 hashes are used for file comparison. This check protects MSAA application trust, not every file on macOS.",
        ["operational_health", "live_response", "troubleshooting"],
        ["integrity", "trusted manifest", "evidence snapshot", "baseline"],
        ["integrity_warnings"],
        ["If integrity changed unexpectedly, preserve evidence before repair or reinstall."],
    ),
    "network_intelligence": _topic(
        "network_intelligence",
        "Network Intelligence",
        "Network Intelligence",
        "How MSAA reviews connections, listeners, DNS, gateway, VPN/proxy changes, baseline drift, and visibility mismatch.",
        "Network Intelligence summarizes local network posture. It helps you review listening services, current or recent connections, DNS and gateway settings, VPN or proxy changes, and drift from a known baseline.",
        ["You see unusual listeners or external connections.", "DNS, gateway, VPN, or proxy settings changed.", "Network data looks missing or inconsistent."],
        ["Review listeners and unusual external connections first.", "Check process path, user, signature, and expected business purpose.", "Verify network configuration drift before assuming compromise."],
        "A listener accepts incoming connections. A connection is active or recent communication. Visibility mismatch means collection sources disagree because of permissions, timing, or system limits.",
        ["live_response", "reports_exports", "troubleshooting"],
        ["baseline", "drift", "false positive"],
        ["network_data_missing"],
    ),
    "persistence_intelligence": _topic(
        "persistence_intelligence",
        "Persistence Intelligence",
        "Persistence Intelligence",
        "How MSAA reviews LaunchAgents, LaunchDaemons, login items, scheduled jobs, browser persistence, and baseline changes.",
        "Persistence Intelligence reviews mechanisms that can restart software after login, reboot, schedule, browser launch, or service reload. Legitimate management tools and unwanted software can both use persistence.",
        ["A new startup item appears.", "A persistence item has unusual owner, path, schedule, signature, or baseline status."],
        ["Review owner, path, signature, schedule, parent app, and purpose.", "Preserve evidence before deleting plists, scripts, or executables.", "Mark expected tools as reviewed instead of treating every new item as malicious."],
        "Persistence terms are standardized around persistence, daemon, LaunchAgent, LaunchDaemon, baseline, and drift. New since baseline means absent from the comparison snapshot.",
        ["integrity_verification", "live_response", "glossary"],
        ["persistence", "LaunchAgent", "LaunchDaemon", "baseline", "daemon"],
    ),
    "apple_exposure": _topic(
        "apple_exposure",
        "Apple Exposure Assessment",
        "Apple Exposure",
        "How MSAA reviews Apple security exposure, data freshness, CVEs, and CISA KEV indicators.",
        "Apple Exposure Assessment helps you decide whether this Mac may need Apple security updates based on local version context, checked-date freshness, CVEs, and KEV indicators.",
        ["You are planning updates.", "A CVE or KEV indicator appears.", "The assessment is stale or missing."],
        ["Refresh before relying on the assessment.", "Use System Settings or managed update tooling to patch.", "Verify the installed version after update and reboot if required."],
        "CVE entries identify disclosed vulnerabilities. KEV means known exploitation is documented in the CISA catalog. Applicability still depends on local product and version context.",
        ["reports_exports", "troubleshooting", "alert_severity"],
        ["CVE", "CISA KEV", "KEV", "false positive"],
        ["apple_exposure_not_updating"],
    ),
    "reports_exports": _topic(
        "reports_exports",
        "Reports and Exports",
        "Reports & Exports",
        "How HTML, JSON, Word, Excel, evidence bundles, and report detail levels should be used.",
        "Reports turn local findings into shareable summaries, analyst detail, or evidence packages. They should explain what was found and what to do without forcing users to read raw logs.",
        ["You need to share results.", "You need a durable record for review, remediation, or case tracking."],
        ["Choose executive reports for leadership and technical reports for analysts.", "Protect exports because they may contain sensitive local context.", "Open the reports folder to confirm where files were saved."],
        "Reports may include structured evidence tables and technical appendices, but Help pages should not render raw JSON, debug output, or system log dumps.",
        ["live_response", "how_msaa_works", "troubleshooting"],
        ["evidence snapshot", "false positive"],
        ["reports_not_generating"],
    ),
    "live_response": _topic(
        "live_response",
        "Live Response Collection",
        "Live Response",
        "How evidence snapshots collect read-only artifacts and export bundles without destructive actions.",
        "Live Response creates read-only snapshots of selected local artifacts so you or an analyst can review what existed at a point in time.",
        ["A high-risk or unexplained finding appears.", "You need before-and-after evidence around remediation."],
        ["Collect a snapshot before repair, reinstall, or cleanup.", "Export bundles only to trusted storage.", "Use snapshots to verify remediation."],
        "Collection can include system state, process and network details, persistence paths, logs, settings, hashes, and report metadata. The collection flow does not delete, quarantine, block, or wipe artifacts.",
        ["integrity_verification", "reports_exports", "network_intelligence"],
        ["evidence snapshot", "baseline", "integrity"],
        [],
        ["Evidence bundles may contain sensitive local paths and case context."],
    ),
    "family_safety": _topic(
        "family_safety",
        "Family & Safety Center",
        "Family & Safety Center",
        "How family, caregiver, school, and public-sector users can use safety categories and guidance.",
        "Family & Safety Center organizes local safety guidance into practical categories without hiding that restrictions can affect accessibility, education, support, and care workflows.",
        ["You are reviewing a shared, family, school, or public-sector Mac.", "You need practical guidance without advanced security jargon."],
        ["Read category explanations before applying restrictions.", "Use Apple-supported controls for Screen Time and privacy permissions.", "Balance lockdown with accessibility and support needs."],
        "Safety guidance maps configuration choices to user impact. It should not imply that one hardened profile is right for every household or organization.",
        ["reports_exports", "operational_health", "glossary"],
        ["false positive"],
    ),
    "troubleshooting": _topic(
        "troubleshooting",
        "Troubleshooting Hub",
        "Troubleshooting",
        "Actionable fixes for common MSAA visibility, health, alerting, integrity, exposure, network, device, and export issues.",
        "Troubleshooting is organized by symptom. Each guide explains the likely cause, fix steps, and verification steps without exposing raw debug logs in Help.",
        ["A feature does not behave as expected.", "You need a next step before changing settings or collecting support information."],
        ["Start with the symptom closest to what you see.", "Refresh Operational Health when the cause is unclear.", "Verify the fix using the steps listed in the guide."],
        "Detailed diagnostic data can be exported from feature views when needed, but Help content remains summarized and user-readable.",
        ["operational_health", "alert_severity", "integrity_verification"],
        ["daemon", "notifier", "integrity", "drift"],
        list(TROUBLESHOOTING_GUIDES),
    ),
    "glossary": _topic(
        "glossary",
        "Glossary",
        "Glossary",
        "Searchable definitions for common MSAA, macOS, and security terms.",
        "The glossary provides one consistent definition for terms used across MSAA so alerts, reports, and Help topics use the same language.",
        ["You see an unfamiliar term.", "A report or alert uses security vocabulary you want to verify."],
        ["Use simple definitions first.", "Open related topics for workflow guidance.", "Slow down before taking disruptive action when a term is unfamiliar."],
        "Glossary entries include simple definitions, technical definitions, examples, and related terms. Topic pages link to glossary entries by term.",
        ["help_center", "alert_severity", "persistence_intelligence"],
        ["alert severity levels", "integrity", "trusted manifest", "baseline", "persistence", "daemon", "LaunchAgent", "CVE", "KEV", "MITRE ATT&CK", "false positive", "evidence snapshot"],
    ),
    "about_msaa": _topic(
        "about_msaa",
        "About MSAA",
        "Glossary",
        "Product, version, license, privacy, local-first design, and disclaimer information.",
        "MSAA is the macOS Security Audit Agent. It is designed as a local-first defensive audit and investigation tool.",
        ["You need version, build, privacy, or license information.", "You are sharing a bug report or evaluation note."],
        ["Check installed version when reporting bugs.", "Review exported files before sharing.", "Use professional incident response support for high-risk or regulated incidents."],
        "MSAA does not replace professional incident response, legal advice, or vendor-supported remediation. Exported artifacts remain local unless the user shares them.",
        ["help_center", "reports_exports", "troubleshooting"],
        ["evidence snapshot", "false positive"],
    ),
    "pre_uat_audit": _topic(
        "pre_uat_audit",
        "Pre-UAT Audit",
        "Glossary",
        "How developers and release testers use the pre-user-acceptance audit.",
        "Pre-UAT Audit checks whether MSAA is ready for user acceptance testing by reviewing UI controls, settings, daemon and notifier behavior, alert pipeline, scans, exports, and release readiness.",
        ["You are validating a build before release.", "You need regression-oriented quality evidence."],
        ["Run the full audit before a release candidate.", "Fix blockers before handing the app to users.", "Export the audit report for regression tracking."],
        "Pre-UAT output is quality evidence for maintainers and testers. It should not be mixed into user Help pages as raw diagnostic output.",
        ["operational_health", "reports_exports", "troubleshooting"],
        ["notifier", "daemon", "alert severity levels"],
    ),
}


@lru_cache(maxsize=1)
def all_topics() -> dict[str, HelpTopic]:
    return dict(TOPICS)


def get_topic(topic_id: str) -> HelpTopic | None:
    return all_topics().get(topic_id)


def list_topics() -> list[HelpTopic]:
    topics = all_topics()
    ordered: list[HelpTopic] = []
    seen: set[str] = set()
    for topic_ids in HELP_CATEGORIES.values():
        for topic_id in topic_ids:
            topic = topics.get(topic_id)
            if topic is not None:
                ordered.append(topic)
                seen.add(topic_id)
    ordered.extend(topic for topic_id, topic in topics.items() if topic_id not in seen)
    return ordered


def search_topics(query: str) -> list[HelpTopic]:
    normalized = query.strip().lower()
    topics = list_topics()
    if not normalized:
        return topics
    results: list[tuple[int, HelpTopic]] = []
    for topic in topics:
        haystack_parts = [
            topic.title,
            topic.short_summary,
            topic.user_friendly_explanation,
            " ".join(topic.when_this_matters),
            " ".join(topic.what_you_should_do),
            topic.advanced_details,
            " ".join(topic.glossary_terms),
            " ".join(topic.related_topics),
            topic.category,
        ]
        haystack = "\n".join(haystack_parts).lower()
        if normalized in haystack:
            score = haystack.count(normalized)
            if normalized in topic.title.lower():
                score += 10
            if normalized in topic.short_summary.lower():
                score += 5
            if normalized in topic.category.lower():
                score += 3
            results.append((score, topic))
    return [topic for _score, topic in sorted(results, key=lambda item: (-item[0], item[1].title))]
