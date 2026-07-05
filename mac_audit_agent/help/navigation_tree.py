from __future__ import annotations

from collections import OrderedDict


HELP_CATEGORIES: "OrderedDict[str, list[str]]" = OrderedDict(
    [
        ("Getting Started", ["help_center", "how_msaa_works", "dashboard"]),
        ("Alerts & Security Events", ["alert_severity", "intrusion_detection", "flight_recorder"]),
        ("System Health", ["operational_health", "settings"]),
        ("Integrity & Trust", ["integrity_verification"]),
        ("Network Intelligence", ["network_intelligence"]),
        ("Persistence Intelligence", ["persistence_intelligence"]),
        ("Apple Exposure", ["apple_exposure"]),
        ("Reports & Exports", ["reports_exports"]),
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
