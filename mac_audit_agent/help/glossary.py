from __future__ import annotations

from mac_audit_agent.help.topic_models import GlossaryTerm

GLOSSARY_TERMS: dict[str, GlossaryTerm] = {
    "malware": GlossaryTerm("malware", "Software or code intended to harm, disrupt, spy on, or gain unauthorized control.", "Malware is an umbrella term whose classification depends on behavior and evidence, not merely an unfamiliar filename.", "Ransomware and spyware are malware categories.", ["ransomware", "virus", "worm"]),
    "virus": GlossaryTerm("virus", "Malware that attaches to other content and spreads when that host is run.", "A virus generally requires a host file or program and execution to replicate; it differs from a self-propagating worm.", "An infected document macro may spread when opened.", ["malware", "worm"]),
    "worm": GlossaryTerm("worm", "Self-propagating malware that can spread between systems.", "A worm automates propagation through reachable services, credentials, messaging, or removable media without needing to attach to a host file.", "A network worm may exploit an exposed service across many hosts.", ["malware", "virus"]),
    "Trojan horse": GlossaryTerm("Trojan horse", "Software presented as useful or legitimate while concealing harmful behavior.", "Trojan describes deceptive delivery or identity; it does not by itself specify persistence, payload, or propagation.", "A fake utility may install an unwanted backdoor.", ["malware"]),
    "rootkit": GlossaryTerm("rootkit", "Tools or modifications intended to conceal unauthorized control or artifacts.", "Rootkits may operate in user space, kernel space, firmware, or boot components; a heuristic indicator requires corroboration.", "Hidden process or module inconsistencies may require rootkit investigation.", ["malware"]),
    "ransomware": GlossaryTerm("ransomware", "Malware that denies access to data or systems and demands payment or leverage.", "Ransomware operations may combine encryption, deletion, exfiltration, credential abuse, and recovery impairment.", "Unexpected high-rate file changes can be a ransomware signal but are not proof alone.", ["malware"]),
    "supply-chain attack": GlossaryTerm("supply-chain attack", "Compromise introduced through a supplier, dependency, update, build process, or trusted service.", "Supply-chain risk crosses organizational trust boundaries and requires provenance, build, signing, dependency, and deployment evidence.", "A compromised signed update can distribute harmful code through a trusted channel.", ["integrity"]),
    "manifesto": GlossaryTerm("manifesto", "A public statement of ideas, principles, or intentions.", "A manifesto is historical or cultural source material, not technical evidence, authorization, or an ethical standard by itself.", "A historical computing essay may be studied for context.", []),
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
GLOSSARY["product licensing"] = "Signed authorization for commercial MSAA features; it does not grant authority to access or change a target system."
GLOSSARY["activation"] = "Verification and installation of a signed MSAA license, either from an offline document or a configured licensing service."
GLOSSARY["offline license"] = "An Ed25519-signed license document imported locally without requiring Stripe or an online activation request."
GLOSSARY["Stripe Checkout"] = "Stripe's hosted payment page; successful payment is confirmed to MSAA by a verified webhook before license fulfillment."
GLOSSARY["operational health"] = "The condition of MSAA components needed for scanning, monitoring, alerting, settings, storage, and exports."
GLOSSARY["typosquatting"] = "Use of a mistyped or confusingly similar name that may misdirect users; an existing similar name is not automatically malicious."
GLOSSARY["unicode confusable"] = "A character or string that can resemble another under some fonts or scripts; UTS #39 screening is an aid, not proof of intent."
GLOSSARY["rdap"] = "Registration Data Access Protocol, a structured protocol for domain registration data that does not guarantee purchase availability when no object is found."
GLOSSARY["package normalization"] = "Registry-defined transformation used before comparing package identifiers, such as PyPA collapsing runs of hyphens, underscores, and periods."
GLOSSARY["alert pipeline"] = "The path from local event collection through severity scoring, storage, and user notification."
GLOSSARY["egress filtering"] = "Monitoring or restricting traffic leaving a host or network according to an approved policy."
GLOSSARY["network segmentation"] = "Separating systems or trust zones and controlling traffic permitted between them or to external networks."
GLOSSARY["firewall policy"] = "Documented rules describing which network traffic is allowed, denied, logged, and reviewed."
GLOSSARY["ingress testing"] = "Authorized validation of traffic entering a defined host or network boundary from a stated source vantage."
GLOSSARY["cde segmentation"] = "Controls and evidence used to separate a PCI cardholder data environment from other systems; MSAA does not certify PCI compliance."
GLOSSARY["nmap xml"] = "Structured XML output produced by Nmap that records scan targets, ports, states, and supporting metadata for review."
GLOSSARY["cwe"] = "Common Weakness Enumeration, a MITRE-maintained vocabulary for software and hardware weakness types."


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
