from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass
class RemediationAdvice:
    suggested_fix: str
    validation_step: str
    difficulty: str = "medium"
    expected_impact: str = "Improves local security posture and analyst confidence."
    rollback_note: str = "Document the change and keep enough evidence to reverse it if business impact is observed."
    user_friendly_explanation: str = "Review the evidence, confirm whether the activity is expected, and apply the fix only after validation."
    analyst_notes: str = "Preserve evidence for critical or high severity items before making changes."

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def _text(finding: Any) -> str:
    if isinstance(finding, dict):
        values = [
            finding.get("title", ""),
            finding.get("category", ""),
            finding.get("event_type", ""),
            finding.get("description", ""),
            finding.get("evidence", ""),
            finding.get("evidence_summary", ""),
            finding.get("rule_id", ""),
        ]
    else:
        values = [str(finding)]
    return " ".join(str(value).lower() for value in values if value)


def get_suggested_fix(finding: Any) -> RemediationAdvice:
    text = _text(finding)
    severity = str(finding.get("severity", "info") if isinstance(finding, dict) else "info").lower()
    preserve = " Preserve evidence before changing the system." if severity in {"critical", "high"} else ""

    if "launchdaemon" in text:
        return RemediationAdvice(
            "Review the LaunchDaemon plist, verify the target binary, confirm code signature, and remove or disable the item only if it is unauthorized." + preserve,
            "Re-run the persistence scan and confirm the LaunchDaemon is no longer present or is documented as approved.",
            "medium",
            "Reduces persistence risk while avoiding removal of legitimate management services.",
            "Keep a copy of the plist and binary path so the service can be restored if it is approved.",
        )
    if "launchagent" in text or "login item" in text or "persistence" in text:
        return RemediationAdvice(
            "Review the persistence item, verify its owner and target binary, confirm code signature, and disable it only if it is unauthorized." + preserve,
            "Re-run the persistence scan and confirm the item is removed, disabled, or marked approved.",
            "medium",
            "Reduces startup persistence risk and improves change accountability.",
            "Record the original path and plist contents before changing the item.",
        )
    if "usb" in text or "hid" in text or "physical device" in text:
        return RemediationAdvice(
            "Confirm whether the device was expected. If trusted, mark it trusted. If unknown, preserve evidence and review nearby session events before using the device." + preserve,
            "Open the Physical Device history and confirm the device trust status and recent timeline context.",
            "low",
            "Improves physical device accountability without blocking known business devices.",
            "If a device was incorrectly marked untrusted, update the trust decision and add an analyst note.",
        )
    if "bluetooth" in text:
        return RemediationAdvice(
            "Confirm the Bluetooth device identity with the user or asset owner. Mark trusted devices and investigate unknown or unexpected devices." + preserve,
            "Refresh device monitoring and verify the Bluetooth inventory reflects the expected device state.",
            "low",
            "Improves wireless device inventory confidence.",
            "Revert trust status if the device is later verified as unauthorized.",
        )
    if "network" in text or "listener" in text or "port" in text or "vpn" in text or "dns" in text or "gateway" in text:
        return RemediationAdvice(
            "Identify the owning process, verify code signature, confirm business need, and disable the service or connection path if unauthorized." + preserve,
            "Re-run network activity checks and confirm the listener, connection, DNS, gateway, or VPN state is expected.",
            "medium",
            "Reduces exposed service and suspicious network activity risk.",
            "Document the original service configuration before changing network or daemon settings.",
        )
    if "apple" in text or "cve" in text or "kev" in text or "exposure" in text:
        return RemediationAdvice(
            "Install the latest applicable Apple security update after confirming compatibility and backing up critical data.",
            "Refresh Apple Exposure Assessment and confirm update freshness and relevant CVE status.",
            "medium",
            "Reduces exposure to known Apple platform vulnerabilities.",
            "Use normal macOS update rollback or backup recovery procedures if compatibility issues occur.",
        )
    if "admin" in text or "sudoers" in text or "account" in text:
        return RemediationAdvice(
            "Verify the account or sudoers change was intentionally created. Remove unauthorized admin rights and review login/session history." + preserve,
            "Re-run admin and persistence checks and confirm account privileges match approved access.",
            "medium",
            "Reduces privilege abuse risk and improves access governance.",
            "Record prior group membership before changing account privileges.",
        )
    if "monitor" in text or "daemon" in text or "notifier" in text or "coverage" in text:
        return RemediationAdvice(
            "Restart the monitor, verify LaunchAgent/LaunchDaemon status, and confirm the notifier and database paths are healthy.",
            "Open Monitor Settings Diagnostics and confirm runtime, notifier, and installed settings agree.",
            "low",
            "Restores alert visibility and monitoring coverage.",
            "If restart changes behavior unexpectedly, review the install manifest and reinstall with current settings.",
        )
    return RemediationAdvice(
        "Review the finding evidence, confirm whether the behavior is expected, and document the decision before making changes." + preserve,
        "Refresh the assessment and confirm the finding is resolved, accepted, or documented as a false positive.",
        "medium",
        "Improves risk tracking and remediation accountability.",
        "Do not remove files, accounts, or services until ownership and business need are verified.",
    )
