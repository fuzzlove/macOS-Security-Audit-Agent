from __future__ import annotations

from collections import OrderedDict


HELP_CATEGORIES: "OrderedDict[str, list[str]]" = OrderedDict(
    [
        ("Getting Started", ["help_center", "how_msaa_works", "dashboard"]),
        ("Alerts & Security Events", ["alert_severity", "intrusion_detection", "flight_recorder"]),
        ("System Health", ["operational_health", "settings"]),
        ("Integrity & Trust", ["integrity_verification", "zero_trust_endpoint", "security_research_device", "not_signed"]),
        ("Network Intelligence", ["network_intelligence", "dns_assurance", "default_credential_scanner"]),
        ("Persistence Intelligence", ["persistence_intelligence"]),
        ("Keylogger Detection", ["keylogger_detection"]),
        ("Software Supply Chain", ["anti_typosquatting", "anti_typosquatting_domains", "anti_typosquatting_npm", "anti_typosquatting_pypi", "anti_typosquatting_rust", "anti_typosquatting_ruby", "anti_typosquatting_nuget", "anti_typosquatting_maven", "anti_typosquatting_go", "anti_typosquatting_composer", "anti_typosquatting_project_audit", "anti_typosquatting_investigations", "anti_typosquatting_scores", "anti_typosquatting_reporting", "anti_typosquatting_privacy", "anti_typosquatting_go_privacy", "anti_typosquatting_executive_reports"]),
        ("Apple Exposure", ["apple_exposure"]),
        ("Reports & Exports", ["reports_exports", "consultant_timesheet"]),
        ("Live Response", ["live_response"]),
        ("Family & Safety Center", ["family_safety"]),
        ("Troubleshooting", ["troubleshooting"]),
        ("Glossary", ["glossary", "about_msaa", "pre_uat_audit"]),
    ]
)


def categories() -> list[str]:
    return list(HELP_CATEGORIES.keys())


def topic_ids_for_category(category: str) -> list[str]:
    return list(HELP_CATEGORIES.get(category, []))
