from __future__ import annotations


BUTTON_TEXT_REPLACEMENTS: dict[str, tuple[str, str]] = {
    "Refresh Network Intelligence": ("Refresh", "Refresh Network Intelligence."),
    "Local Network Discovery": ("Discover", "Run local network discovery."),
    "Network Settings": ("Settings", "Open Network Intelligence settings."),
    "Repair Operational Health": ("Repair Health", "Attempt safe repairs for broken MSAA operational components."),
    "Audit System Monitor Deployment": ("Audit Monitor", "Audit the system monitor deployment."),
    "Verify System Monitor Integrity": ("Verify Daemon", "Verify the deployed system monitor runtime and LaunchDaemon."),
    "Verify User Notifier Integrity": ("Verify Notifier", "Verify the user notifier runtime and LaunchAgent."),
    "Preserve Evidence Snapshot": ("Preserve Evidence", "Create an evidence snapshot before investigation or repair."),
    "Export Integrity Report": ("Export Report", "Export the current integrity verification report."),
    "Recalculate Manifest After Trusted Update": ("Rebaseline Manifest", "Recalculate trusted hashes after explicit trusted-update confirmation."),
    "Create Evidence Snapshot": ("Preserve Evidence", "Create an evidence snapshot."),
    "Export Case Package": ("Export Case", "Export an incident case package."),
    "Review High Priority Events": ("Review Priority", "Review high-priority events."),
    "Open Reports Folder": ("Open Reports", "Open the local reports folder."),
}


def normalize_button_text(text: str) -> tuple[str, str]:
    cleaned = " ".join(str(text or "").split())
    if cleaned in BUTTON_TEXT_REPLACEMENTS:
        return BUTTON_TEXT_REPLACEMENTS[cleaned]
    if len(cleaned) > 28:
        return cleaned[:25].rstrip() + "...", cleaned
    return cleaned, ""


__all__ = ["BUTTON_TEXT_REPLACEMENTS", "normalize_button_text"]
