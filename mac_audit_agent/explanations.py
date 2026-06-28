from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


HIGH_SEVERITIES = {"high", "critical"}


@dataclass
class FindingExplanation:
    technical_explanation: str
    plain_english_explanation: str
    analyst_next_step: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _title_category_text(finding: dict[str, Any]) -> str:
    return " ".join(
        [
            _text(finding.get("category")),
            _text(finding.get("title")),
            _text(finding.get("description")),
            _text(finding.get("evidence")),
            _text(finding.get("rule_id")),
        ]
    ).lower()


def _default_technical(finding: dict[str, Any]) -> str:
    title = _text(finding.get("title")) or "Security finding"
    evidence = _text(finding.get("evidence") or finding.get("evidence_summary"))
    source = _text(finding.get("command_or_source") or finding.get("command_used") or finding.get("trigger_source"))
    if evidence and source:
        return f"{title}: MSAA observed {evidence} from {source}."
    if evidence:
        return f"{title}: MSAA observed {evidence}."
    return f"{title}: MSAA recorded a high-priority condition that requires review."


def _default_plain(finding: dict[str, Any]) -> str:
    title = _text(finding.get("title")) or "This item"
    return (
        f"{title} may indicate a meaningful change or exposure on this Mac. "
        "It is not proof of malicious activity by itself, but it should be reviewed because it may affect security or visibility."
    )


def _default_next_step(finding: dict[str, Any]) -> str:
    next_step = _text(finding.get("recommended_next_steps") or finding.get("remediation_suggestion"))
    if next_step:
        return next_step
    verification = finding.get("recommended_verification_steps") or finding.get("verification_steps") or []
    if isinstance(verification, list) and verification:
        return _text(verification[0])
    return "Verify the evidence, confirm whether the activity is expected, and compare it against a trusted baseline before taking action."


def explain_finding(finding: dict[str, Any]) -> FindingExplanation:
    text = _title_category_text(finding)
    technical = _default_technical(finding)
    plain = _default_plain(finding)
    next_step = _default_next_step(finding)

    if "launchdaemon" in text or "launch daemon" in text:
        technical = _text(finding.get("technical_explanation")) or f"LaunchDaemon configuration observed: {_text(finding.get('evidence') or finding.get('related_path')) or 'a LaunchDaemon entry was recorded'}."
        plain = _text(finding.get("plain_english_explanation")) or "A program was configured to start automatically when the Mac boots. This can be normal software, but it can also be used to keep unwanted software running after restarts."
        next_step = _text(finding.get("analyst_next_step")) or "Verify the plist owner, file permissions, target program path, code signature, and whether the item is expected for this Mac."
    elif "launchagent" in text or "launch agent" in text or "login item" in text:
        plain = _text(finding.get("plain_english_explanation")) or "A program was configured to start automatically for a user session. This can be normal, but unexpected entries should be reviewed."
        next_step = _text(finding.get("analyst_next_step")) or "Verify the startup item, target program, user account, signature, and whether it appears in the trusted baseline."
    elif "port" in text or "listener" in text or "listening" in text or "nmap" in text:
        plain = _text(finding.get("plain_english_explanation")) or "The Mac appears to have a network service listening for connections. Some services are expected, but unexpected listeners can expose the Mac to other software or devices."
        next_step = _text(finding.get("analyst_next_step")) or "Identify the owning process, confirm whether the service is expected, and compare process ownership with port scan results."
    elif "admin" in text or "sudoers" in text or "user" in text:
        plain = _text(finding.get("plain_english_explanation")) or "An account or permission change may affect who can control the Mac. Admin-level access should be limited to trusted users."
        next_step = _text(finding.get("analyst_next_step")) or "Confirm the account owner, when the change occurred, and whether the admin or sudo permission is authorized."
    elif "filevault" in text or "firewall" in text or "remote login" in text or "ssh" in text:
        plain = _text(finding.get("plain_english_explanation")) or "An important security setting may not match the expected state. This can change how well the Mac protects data or limits access."
        next_step = _text(finding.get("analyst_next_step")) or "Confirm the setting in System Settings or with the recorded command output, then compare it to the local policy."
    elif "cve" in text or "kev" in text or "vulnerab" in text or "advisory" in text:
        plain = _text(finding.get("plain_english_explanation")) or "The Mac or installed software may be affected by a known security issue. Updates or mitigation may be needed after confirming applicability."
        next_step = _text(finding.get("analyst_next_step")) or "Verify the affected product and version, review vendor guidance, and prioritize updates for actively exploited or high-impact issues."

    return FindingExplanation(
        technical_explanation=_text(finding.get("technical_explanation")) or technical,
        plain_english_explanation=_text(finding.get("plain_english_explanation")) or plain,
        analyst_next_step=_text(finding.get("analyst_next_step")) or next_step,
    )


def ensure_finding_explanations(finding: dict[str, Any]) -> dict[str, Any]:
    enriched = dict(finding)
    severity = _text(enriched.get("severity")).lower()
    if severity not in HIGH_SEVERITIES:
        return enriched
    explanation = explain_finding(enriched)
    for key, value in explanation.to_dict().items():
        if not _text(enriched.get(key)):
            enriched[key] = value
    return enriched
