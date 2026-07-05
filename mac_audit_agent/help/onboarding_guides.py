from __future__ import annotations


ONBOARDING_STEPS: list[dict[str, str]] = [
    {
        "title": "What MSAA does",
        "body": "MSAA reviews local macOS security posture, alerts, integrity, exposure, persistence, network posture, reports, and evidence snapshots without uploading telemetry by default.",
        "topic_id": "how_msaa_works",
    },
    {
        "title": "What alerts mean",
        "body": "Alerts are triage signals. Severity tells you how quickly to review an event, not whether compromise is proven.",
        "topic_id": "alert_severity",
    },
    {
        "title": "What integrity means",
        "body": "Integrity checks compare protected MSAA files with a trusted manifest so unexpected application changes are easier to notice.",
        "topic_id": "integrity_verification",
    },
    {
        "title": "What to do when alerts appear",
        "body": "Review the alert, preserve evidence for high-risk or unexplained activity, then follow feature-specific guidance before repairing or deleting anything.",
        "topic_id": "troubleshooting",
    },
]


def onboarding_html() -> str:
    steps = "".join(
        f"<li><b>{step['title']}</b><br>{step['body']}<br><a href=\"{step['topic_id']}\">Open guide</a></li>"
        for step in ONBOARDING_STEPS
    )
    return f"<h2>Welcome to MSAA Help</h2><ol>{steps}</ol><p>You can skip onboarding by opening any topic from the navigation tree.</p>"
