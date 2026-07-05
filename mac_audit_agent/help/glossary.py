from __future__ import annotations

from mac_audit_agent.help.topic_models import GlossaryTerm


GLOSSARY_TERMS: dict[str, GlossaryTerm] = {
    "alert severity levels": GlossaryTerm(
        "alert severity levels",
        "The priority labels MSAA uses to help you decide how quickly to review an event.",
        "MSAA uses INFO, LOW, MEDIUM, HIGH, and CRITICAL as canonical alert severity values. Severity is a triage signal, not proof of compromise.",
        "A HIGH persistence alert means review promptly and preserve evidence before making changes.",
        ["false positive", "evidence snapshot"],
    ),
    "baseline": GlossaryTerm(
        "baseline",
        "A trusted reference point used to notice what changed later.",
        "A saved state for files, persistence items, network posture, or settings that later scans can compare against for drift.",
        "A new LaunchAgent since baseline may be expected software or something that needs review.",
        ["drift", "persistence"],
    ),
    "CISA KEV": GlossaryTerm(
        "CISA KEV",
        "A public U.S. government list of vulnerabilities known to be exploited.",
        "The Cybersecurity and Infrastructure Security Agency Known Exploited Vulnerabilities catalog. MSAA surfaces KEV context for update prioritization.",
        "",
        ["CVE"],
    ),
    "CVE": GlossaryTerm(
        "CVE",
        "A public identifier for a known vulnerability.",
        "Common Vulnerabilities and Exposures identifiers name disclosed vulnerabilities so tools, vendors, and analysts can discuss the same issue.",
        "CVE-2026-12345 would identify one disclosed issue, not every affected Mac.",
        ["CISA KEV", "Apple Exposure"],
    ),
    "daemon": GlossaryTerm(
        "daemon",
        "A background service that runs without a normal app window.",
        "On macOS, daemon-style services are commonly managed by launchd and may run as system or user background processes.",
        "",
        ["LaunchAgent", "LaunchDaemon"],
    ),
    "drift": GlossaryTerm(
        "drift",
        "A meaningful difference from a baseline or expected state.",
        "Drift can describe changes in settings, persistence inventory, network posture, integrity state, or operational health.",
        "",
        ["baseline"],
    ),
    "evidence snapshot": GlossaryTerm(
        "evidence snapshot",
        "A read-only record of local facts saved for later review.",
        "An evidence snapshot preserves selected artifacts, metadata, hashes, and context from a point in time without deleting or quarantining anything.",
        "Create one before repairing an integrity mismatch.",
        ["integrity", "baseline"],
    ),
    "false positive": GlossaryTerm(
        "false positive",
        "A finding that looks suspicious but is explained by expected activity.",
        "A detection result that matches a rule or risk pattern but is authorized, benign, or not applicable after review.",
        "A device-management LaunchDaemon may look unusual but be approved by IT.",
        ["alert severity levels"],
    ),
    "integrity": GlossaryTerm(
        "integrity",
        "Confidence that something still matches its trusted state.",
        "MSAA integrity checks compare protected application files and trusted manifests to detect modified, stale, unknown, draft, or verified states.",
        "",
        ["trusted manifest", "evidence snapshot"],
    ),
    "trusted manifest": GlossaryTerm(
        "trusted manifest",
        "A trusted list of files and expected hashes.",
        "A controlled manifest records expected SHA-256 hashes for protected MSAA files so integrity checks can detect unexpected changes.",
        "",
        ["integrity", "baseline"],
    ),
    "persistence": GlossaryTerm(
        "persistence",
        "A way for software to start again automatically.",
        "Persistence mechanisms include LaunchAgents, LaunchDaemons, login items, scheduled jobs, browser extensions, and helper tools.",
        "",
        ["LaunchAgent", "daemon"],
    ),
    "LaunchAgent": GlossaryTerm(
        "LaunchAgent",
        "A per-user macOS background job definition.",
        "A launchd property list that usually runs in a user context after login or under user-level launchd management.",
        "",
        ["LaunchDaemon", "persistence"],
    ),
    "LaunchDaemon": GlossaryTerm(
        "LaunchDaemon",
        "A system-level macOS background job definition.",
        "A launchd property list that usually runs outside a normal user session and can start services at boot or service load.",
        "",
        ["LaunchAgent", "daemon"],
    ),
    "MITRE ATT&CK": GlossaryTerm(
        "MITRE ATT&CK",
        "A public knowledge base of attacker behaviors.",
        "A framework of tactics, techniques, and procedures used to map observed behavior to common adversary patterns.",
        "",
        ["persistence"],
    ),
    "KEV": GlossaryTerm(
        "KEV",
        "Short name for Known Exploited Vulnerabilities.",
        "MSAA uses KEV as shorthand for the CISA KEV catalog when prioritizing Apple Exposure items.",
        "",
        ["CISA KEV", "CVE"],
    ),
}

GLOSSARY: dict[str, str] = {term: entry.simple_definition for term, entry in GLOSSARY_TERMS.items()}
GLOSSARY["hash"] = "A fixed-length fingerprint used to detect whether data changed."
GLOSSARY["notifier"] = "The user-facing MSAA component that displays local alerts."
GLOSSARY["operational health"] = "The condition of MSAA components needed for scanning, monitoring, alerting, settings, storage, and exports."
GLOSSARY["alert pipeline"] = "The path from local event collection through severity scoring, storage, and user notification."


def get_glossary_entry(term: str) -> GlossaryTerm | None:
    normalized = term.strip().lower()
    for key, entry in GLOSSARY_TERMS.items():
        if key.lower() == normalized:
            return entry
    simple = GLOSSARY.get(term) or next((value for key, value in GLOSSARY.items() if key.lower() == normalized), None)
    if simple:
        return GlossaryTerm(term=term, simple_definition=simple, technical_definition=simple)
    return None


def get_glossary_term(term: str) -> str | None:
    entry = get_glossary_entry(term)
    return entry.simple_definition if entry else None


def search_glossary(query: str) -> list[GlossaryTerm]:
    normalized = query.strip().lower()
    entries = list(GLOSSARY_TERMS.values())
    if not normalized:
        return sorted(entries, key=lambda item: item.term.lower())
    return [
        entry
        for entry in sorted(entries, key=lambda item: item.term.lower())
        if normalized in " ".join(
            [entry.term, entry.simple_definition, entry.technical_definition, entry.example, " ".join(entry.related_terms)]
        ).lower()
    ]


def glossary_tooltip(term: str) -> str:
    entry = get_glossary_entry(term)
    if not entry:
        return "Open Help for more."
    return f"{entry.simple_definition}\nOpen Help for more."
