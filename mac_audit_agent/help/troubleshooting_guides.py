from __future__ import annotations

from mac_audit_agent.help.topic_models import TroubleshootingGuide


TROUBLESHOOTING_GUIDES: dict[str, TroubleshootingGuide] = {
    "alerts_not_appearing": TroubleshootingGuide(
        "alerts_not_appearing",
        "Alerts Not Appearing",
        "Alerts not appearing",
        "Important events are recorded in MSAA but no visible notification appears.",
        "Notification permissions, notifier health, severity thresholds, incident mode, or event suppression may prevent visible alerts.",
        [
            "Open Operational Health and refresh component status.",
            "Verify the notifier is installed, healthy, and allowed to show macOS notifications.",
            "Check alert severity thresholds before lowering or raising them.",
            "Review Logs or Flight Recorder to confirm whether events are being recorded below alert threshold.",
        ],
        [
            "Generate or wait for a known test event when developer mode is enabled for testing.",
            "Confirm the event appears in logs and the notifier shows only events at or above threshold.",
        ],
        ["alert_severity", "operational_health"],
    ),
    "integrity_warnings": TroubleshootingGuide(
        "integrity_warnings",
        "Integrity Warnings",
        "Integrity warnings",
        "MSAA reports modified, stale, draft, or unknown integrity state.",
        "The installed files may differ from the trusted manifest, the manifest may belong to another build, or trust has not been established.",
        [
            "Do not overwrite the manifest until you understand why it changed.",
            "Export the integrity report and create an evidence snapshot.",
            "If the change is expected after a trusted update, select or create the matching trusted manifest.",
            "If the change is unexplained, preserve evidence before reinstalling or repairing.",
        ],
        [
            "Run the integrity check again after repair or reinstall.",
            "Confirm the status is verified or intentionally documented as draft during setup.",
        ],
        ["integrity_verification", "live_response"],
    ),
    "daemon_not_running": TroubleshootingGuide(
        "daemon_not_running",
        "Daemon Not Running",
        "Daemon not running",
        "Background monitoring is expected but the daemon is stopped, missing, or unhealthy.",
        "LaunchAgent or LaunchDaemon deployment may be missing, disabled by settings, blocked by permissions, or mismatched with the current build.",
        [
            "Open Operational Health and use the monitor repair or deployment action shown there.",
            "Confirm monitor settings have not disabled background monitoring.",
            "Repair the notifier separately if alerts are also missing.",
        ],
        [
            "Refresh Operational Health.",
            "Verify new monitor events appear after expected activity.",
        ],
        ["operational_health", "settings"],
    ),
    "network_data_missing": TroubleshootingGuide(
        "network_data_missing",
        "Network Data Missing",
        "Network data missing",
        "Network Intelligence shows empty or incomplete connections, listeners, DNS, gateway, VPN, or proxy data.",
        "Collection permissions, command availability, timing, privacy limits, or a quiet network state can reduce visibility.",
        [
            "Refresh Network Intelligence.",
            "Check Operational Health for collection or permission warnings.",
            "Review whether the Mac currently has active network activity.",
            "Use explicit local discovery or nmap actions only when authorized for that network.",
        ],
        [
            "Confirm DNS, gateway, and listener sections refresh without errors.",
            "Compare against a later scan before treating a quiet result as a failure.",
        ],
        ["network_intelligence", "operational_health"],
    ),
    "usb_bluetooth_not_detected": TroubleshootingGuide(
        "usb_bluetooth_not_detected",
        "USB/Bluetooth Not Detected",
        "USB or Bluetooth events are not appearing.",
        "The relevant monitor category may be disabled, permissions may limit visibility, or no qualifying change has occurred.",
        [
            "Open Settings and verify USB/Bluetooth monitoring categories are enabled.",
            "Refresh Operational Health.",
            "Reconnect a known authorized device for testing only when it is safe to do so.",
        ],
        [
            "Confirm the event appears in the monitor timeline or logs.",
            "Confirm alert policy allows that event type to notify if notification is expected.",
        ],
        ["operational_health", "settings"],
    ),
    "apple_exposure_not_updating": TroubleshootingGuide(
        "apple_exposure_not_updating",
        "Apple Exposure Not Updating",
        "Apple Exposure data is stale or does not refresh.",
        "The local cache may be stale, external sources may be unreachable, or the installed macOS version may not match available advisories.",
        [
            "Refresh Apple Exposure Assessment manually.",
            "Check the freshness label before making update decisions.",
            "Use Apple Software Update or managed update tooling as the source of action.",
        ],
        [
            "Confirm the checked date changed after refresh.",
            "Confirm installed macOS version after any update and reboot.",
        ],
        ["apple_exposure", "reports_exports"],
    ),
    "reports_not_generating": TroubleshootingGuide(
        "reports_not_generating",
        "Reports Not Generating",
        "A report or export action fails or produces no useful file.",
        "The report directory may be unavailable, disk space may be low, required scan data may be missing, or permissions may block file creation.",
        [
            "Run or refresh the feature scan before exporting.",
            "Open the reports folder to confirm the destination.",
            "Check disk space and folder permissions.",
            "Use a shorter report scope if a full technical report is not needed.",
        ],
        [
            "Open the generated report locally.",
            "Confirm the report contains summaries, recommended actions, and expected evidence sections.",
        ],
        ["reports_exports", "live_response"],
    ),
}


def get_troubleshooting_guide(guide_id: str) -> TroubleshootingGuide | None:
    return TROUBLESHOOTING_GUIDES.get(guide_id)


def list_troubleshooting_guides() -> list[TroubleshootingGuide]:
    return list(TROUBLESHOOTING_GUIDES.values())
