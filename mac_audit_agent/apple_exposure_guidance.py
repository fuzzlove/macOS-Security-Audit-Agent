from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any


FORECAST_LEVELS = {"clear", "watch", "elevated", "urgent", "critical"}
APPLICABILITY_VALUES = {"confirmed_applicable", "likely_applicable", "review_needed", "not_applicable", "unknown"}
CONFIDENCE_VALUES = {"low", "medium", "high", "very_high"}


def is_meaningful_value(value: Any, *, treat_unknown_as_empty: bool = False) -> bool:
    """
    Return True when a value should be retained during normalization.

    This intentionally avoids set-membership checks against arbitrary payload
    values because Apple Exposure cards commonly contain nested lists/dicts.
    """
    if value is None:
        return False
    if isinstance(value, bool):
        return True
    if isinstance(value, (int, float)):
        return True
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return False
        return not (treat_unknown_as_empty and text.lower() == "unknown")
    if isinstance(value, dict):
        return any(is_meaningful_value(item, treat_unknown_as_empty=treat_unknown_as_empty) for item in value.values())
    if isinstance(value, (list, tuple, set)):
        return any(is_meaningful_value(item, treat_unknown_as_empty=treat_unknown_as_empty) for item in value)
    return True


@dataclass
class AppleExposureUpdateGuide:
    guide_id: str
    source_card_id: str
    source_finding_id: str
    source_item_id: str
    title: str
    affected_product: str
    affected_component: str
    detected_version: str
    recommended_version: str
    forecast_level: str
    applicability: str
    confidence: str
    why_update_is_recommended: str
    urgency_explanation: str
    recommended_actions: list[str] = field(default_factory=list)
    step_by_step_update_instructions: list[str] = field(default_factory=list)
    verification_steps: list[str] = field(default_factory=list)
    pre_update_precautions: list[str] = field(default_factory=list)
    evidence_preservation_notes: list[str] = field(default_factory=list)
    post_update_checks: list[str] = field(default_factory=list)
    rollback_or_recovery_notes: list[str] = field(default_factory=list)
    official_references: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    generated_at: str = ""
    missing_fields: list[str] = field(default_factory=list)
    fallback_used: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_text(self) -> str:
        def section(title: str, items: list[str]) -> list[str]:
            clean = [str(item).strip() for item in items if str(item).strip()]
            if not clean:
                clean = ["None recorded."]
            return [title, "-" * len(title), *[f"- {item}" for item in clean], ""]

        lines = [
            self.title,
            "=" * len(self.title),
            f"Affected product: {self.affected_product}",
            f"Affected component: {self.affected_component}",
            f"Detected version: {self.detected_version or 'not detected'}",
            f"Recommended/fixed version: {self.recommended_version or 'not determined automatically'}",
            f"Forecast level: {self.forecast_level}",
            f"Applicability: {self.applicability}",
            f"Confidence: {self.confidence}",
            "",
            "Why This Matters",
            "----------------",
            self.why_update_is_recommended,
            "",
            "Urgency",
            "-------",
            self.urgency_explanation,
            "",
        ]
        lines.extend(section("Recommended Actions", self.recommended_actions))
        lines.extend(["Step-by-Step Update Instructions", "-" * 33])
        lines.extend(f"{index}. {item}" for index, item in enumerate(self.step_by_step_update_instructions, start=1))
        lines.append("")
        lines.extend(section("Verification Steps", self.verification_steps))
        evidence_notes = self.evidence_preservation_notes or self.pre_update_precautions
        lines.extend(section("Evidence Preservation", evidence_notes))
        lines.extend(section("Post-Update Checks", self.post_update_checks))
        lines.extend(section("Rollback or Recovery Notes", self.rollback_or_recovery_notes))
        lines.extend(section("References", self.official_references))
        lines.extend(section("Limitations", self.limitations))
        if self.missing_fields:
            lines.extend(section("Missing Data Diagnostics", self.missing_fields))
        return "\n".join(lines).strip() + "\n"


def _first(payload: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, list):
            value = ", ".join(str(item) for item in value if str(item).strip())
        if value not in {None, ""}:
            return str(value).strip()
    return ""


def _normalize_level(value: str) -> str:
    level = str(value or "").lower().strip()
    return level if level in FORECAST_LEVELS else "watch"


def _normalize_confidence(value: str) -> str:
    confidence = str(value or "").lower().strip().replace("-", "_")
    aliases = {"very high": "very_high", "confirmed": "very_high", "review": "medium"}
    confidence = aliases.get(confidence, confidence)
    return confidence if confidence in CONFIDENCE_VALUES else "medium"


def _normalize_applicability(payload: dict[str, Any]) -> str:
    raw = _first(payload, "applicability", "applicability_confidence", "confidence").lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "high": "likely_applicable",
        "very_high": "confirmed_applicable",
        "confirmed": "confirmed_applicable",
        "medium": "likely_applicable",
        "low": "review_needed",
        "review-needed": "review_needed",
    }
    value = aliases.get(raw, raw)
    return value if value in APPLICABILITY_VALUES else "unknown"


def normalize_apple_exposure_item(card_or_finding: Any) -> dict[str, Any]:
    if card_or_finding is None:
        return {}
    if hasattr(card_or_finding, "to_dict"):
        card_or_finding = card_or_finding.to_dict()
    elif hasattr(card_or_finding, "__dict__") and not isinstance(card_or_finding, dict):
        card_or_finding = dict(card_or_finding.__dict__)
    if not isinstance(card_or_finding, dict):
        return {}
    payload = dict(card_or_finding)
    alerts = payload.get("alerts")
    if isinstance(alerts, list) and alerts and isinstance(alerts[0], dict):
        merged = dict(alerts[0])
        for key, value in payload.items():
            if is_meaningful_value(value):
                merged[key] = value
        payload = merged
    cves = payload.get("cve_ids") or payload.get("cves") or payload.get("cve") or payload.get("cve_id") or []
    if isinstance(cves, str):
        cves = [cves]
    payload["normalized_cves"] = [str(item) for item in cves if str(item).strip()]
    payload["source_card_id"] = _first(payload, "card_id", "alert_id", "id")
    payload["source_finding_id"] = _first(payload, "finding_id", "id")
    payload["affected_product"] = _first(payload, "affected_local_product", "detected_product", "product", "affected_product", "title")
    payload["affected_component"] = _first(payload, "affected_component", "component", "package", "title")
    payload["detected_version"] = _first(payload, "detected_version", "current_version", "installed_version", "version")
    payload["recommended_version"] = _first(payload, "fixed_version", "recommended_version", "target_version", "available_version")
    payload["forecast_level"] = _normalize_level(_first(payload, "forecast_level", "level", "severity"))
    payload["confidence"] = _normalize_confidence(_first(payload, "confidence", "applicability_confidence"))
    payload["applicability"] = _normalize_applicability(payload)
    return payload


def _category(payload: dict[str, Any]) -> str:
    text = " ".join(
        [
            _first(payload, "affected_product"),
            _first(payload, "affected_component"),
            _first(payload, "title"),
            _first(payload, "description"),
        ]
    ).lower()
    if "kev" in text or payload.get("kev") or payload.get("kev_cves"):
        return "kev"
    if "xcode" in text or "command line tools" in text or "clt" in text:
        return "xcode"
    if "safari" in text or "webkit" in text:
        return "safari"
    if "rapid security response" in text or "rsr" in text:
        return "rapid_security_response"
    if "firmware" in text:
        return "firmware"
    if "review_needed" == payload.get("applicability"):
        return "review_needed"
    return "macos"


def _references(payload: dict[str, Any]) -> list[str]:
    refs = []
    for key in ("references", "official_references", "urls", "advisory_urls"):
        value = payload.get(key)
        if isinstance(value, list):
            refs.extend(str(item) for item in value if str(item).strip())
        elif isinstance(value, str) and value.strip():
            refs.append(value.strip())
    refs.append("https://support.apple.com/en-us/100100")
    if payload.get("kev") or payload.get("kev_cves"):
        refs.append("https://www.cisa.gov/known-exploited-vulnerabilities-catalog")
    for cve in payload.get("normalized_cves", [])[:5]:
        refs.append(f"https://nvd.nist.gov/vuln/detail/{cve}")
        refs.append(f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve}")
    unique = []
    for ref in refs:
        if ref and ref not in unique:
            unique.append(ref)
    return unique


def _freshness_limitations(freshness_metadata: dict[str, Any] | None) -> list[str]:
    if not isinstance(freshness_metadata, dict):
        return []
    limitations = []
    generated_at = _first(freshness_metadata, "generated_at", "timestamp", "last_update_time")
    if generated_at:
        limitations.append(f"This guidance is based on Apple Exposure data from {generated_at}. Refresh before taking action if possible.")
    if freshness_metadata.get("last_error") or freshness_metadata.get("source_update_failed"):
        limitations.append("Apple Exposure source update failed. The guidance is based on cached data.")
    if str(freshness_metadata.get("catalog_update_status", "")).lower() in {"stale", "cache", "offline-rules"}:
        limitations.append("Apple Exposure data may be cached or stale.")
    return limitations


def build_apple_exposure_update_guide(
    card_or_finding: Any,
    local_inventory: dict[str, Any] | None = None,
    freshness_metadata: dict[str, Any] | None = None,
) -> AppleExposureUpdateGuide:
    payload = normalize_apple_exposure_item(card_or_finding)
    generated_at = datetime.now().isoformat(timespec="seconds")
    if not payload:
        return AppleExposureUpdateGuide(
            guide_id=f"apple-guide-empty-{generated_at}",
            source_card_id="",
            source_finding_id="",
            source_item_id="",
            title="Apple Security Update Guidance",
            affected_product="No Apple Exposure item is selected",
            affected_component="No Apple Exposure item is selected",
            detected_version="",
            recommended_version="",
            forecast_level="watch",
            applicability="unknown",
            confidence="medium",
            why_update_is_recommended="No Apple Exposure item is selected. Select an Apple Exposure item for item-specific guidance. General Apple security update guidance is shown below.",
            urgency_explanation="General guidance cannot assign item-specific urgency. Check Software Update and review any Apple Exposure cards after refreshing the assessment.",
            recommended_actions=["Open Software Update and install available macOS or Safari security updates.", "Refresh Apple Exposure Assessment after updating.", "Select an Apple Exposure item for item-specific guidance."],
            step_by_step_update_instructions=["Open System Settings.", "Go to General -> Software Update.", "Install available macOS or Safari security updates.", "Restart if prompted.", "Reopen MSAA.", "Refresh Apple Exposure Assessment.", "Review whether the forecast level changed."],
            verification_steps=["Re-run Apple Exposure Assessment.", "Confirm Software Update reports no relevant updates.", "Review whether the forecast level changed."],
            pre_update_precautions=["If this Mac is under investigation, preserve evidence before updating.", "Updating may remove evidence from volatile state, but delaying updates may leave known vulnerabilities exposed."],
            evidence_preservation_notes=["If this Mac is under investigation, create an MSAA Evidence Snapshot before updating.", "Record current macOS/Safari/Xcode versions before making changes.", "Updating may remove evidence from volatile state, but delaying updates may leave known vulnerabilities exposed."],
            post_update_checks=["Re-run Apple Exposure Assessment after updates are installed.", "Review whether the forecast level changed."],
            rollback_or_recovery_notes=["Keep a backup available before making system changes."],
            official_references=["https://support.apple.com/en-us/100100"],
            limitations=["No selected card was provided to the guidance builder."],
            generated_at=generated_at,
            missing_fields=["selected_card"],
            fallback_used=True,
        )

    local_inventory = local_inventory or {}
    category = _category(payload)
    product = payload.get("affected_product") or _first(local_inventory, "macos_version", "safari_version", "xcode_version") or "Apple product information incomplete"
    component = payload.get("affected_component") or product
    detected = payload.get("detected_version") or ""
    recommended = payload.get("recommended_version") or ""
    level = payload.get("forecast_level", "watch")
    applicability = payload.get("applicability", "unknown")
    confidence = payload.get("confidence", "medium")
    missing = []
    if not payload.get("affected_product"):
        missing.append("affected_product")
    if not recommended:
        missing.append("recommended_version")
    if not detected:
        missing.append("detected_version")

    titles = {
        "macos": "macOS Security Update Guidance",
        "safari": "Safari / WebKit Security Update Guidance",
        "xcode": "Xcode / Command Line Tools Update Guidance",
        "kev": "Known Exploited Apple Vulnerability Guidance",
        "review_needed": "Apple Security Advisory Review Needed",
        "rapid_security_response": "Rapid Security Response Guidance",
        "firmware": "Apple Firmware / Security Update Guidance",
    }
    title = titles.get(category, titles["macos"])
    if applicability == "review_needed":
        title = titles["review_needed"]
        category = "review_needed"

    why = _first(payload, "why_update_is_recommended", "why_shown_to_you", "why_shown", "why_it_matters", "description")
    if not why:
        why = f"Apple security updates may address vulnerabilities affecting {component}. Review the advisory and Software Update before deciding."
    cves = payload.get("normalized_cves", [])
    if cves:
        why = f"{why} Associated CVE(s): {', '.join(cves)}."
    else:
        why = f"{why} No CVE was associated with this finding."
    urgency = {
        "critical": "Critical: install the relevant Apple update as soon as operationally safe, especially if exploitation is known or suspected.",
        "urgent": "Urgent: plan the update promptly and preserve evidence first if this Mac is part of an investigation.",
        "elevated": "Elevated: check Software Update today or during the next normal maintenance window.",
        "watch": "Watch: review applicability and install relevant updates when available.",
        "clear": "Clear: no immediate Apple update action is indicated by this card, but verify if local data is stale.",
    }.get(level, "Review the item and update if Apple Software Update offers a relevant fix.")

    common_precautions = [
        "Create a backup or confirm important data is backed up.",
        "If this system is under investigation, create an MSAA Evidence Snapshot before updating.",
        "Record current macOS/Safari/Xcode versions before making changes.",
    ]
    common_verification = [
        "Re-run Apple Exposure Assessment.",
        "Confirm Software Update reports no relevant updates.",
        "Confirm the detected product version/build in MSAA inventory changed or the item no longer appears.",
    ]
    if category == "safari":
        steps = [
            "Open System Settings -> General -> Software Update.",
            "Install available Safari or macOS updates.",
            "Restart Safari after updating.",
            "Restart the Mac if prompted.",
            "Re-run Apple Exposure Assessment.",
        ]
        actions = ["Install available Safari/WebKit or macOS updates.", "Treat WebKit fixes as browser-exposure hardening; they are often delivered through macOS or Safari updates."]
    elif category == "xcode":
        steps = [
            "Open App Store -> Updates for Xcode if Xcode was installed from the App Store.",
            "Open System Settings -> General -> Software Update for Command Line Tools updates.",
            "If installed from Apple Developer downloads, update from Apple Developer resources.",
            "Confirm Xcode or Command Line Tools version after updating.",
            "Re-run Apple Exposure Assessment.",
        ]
        actions = ["Update Xcode or Command Line Tools from the original Apple source.", "Confirm developer tools versions after updating."]
    elif category == "kev":
        steps = [
            "Preserve evidence if this system is under investigation.",
            "Create an MSAA Evidence Snapshot.",
            "Install the relevant Apple security update as soon as operationally safe.",
            "Review recent monitor events, persistence changes, admin changes, and network activity.",
            "Re-run Apple Exposure Assessment after updating.",
        ]
        actions = ["Prioritize the relevant Apple security update.", "Review local evidence for related suspicious changes without assuming compromise."]
        common_precautions.insert(0, "Known exploited status means urgency is higher, but it does not prove this Mac is compromised.")
    elif category == "review_needed":
        steps = [
            "Review the detected local version and product information.",
            "Open System Settings -> General -> Software Update.",
            "Check whether Apple offers a relevant update.",
            "Review attached Apple advisory references.",
            "Mark Reviewed or Snooze if the advisory is not applicable to this Mac.",
        ]
        actions = ["Verify applicability before acting.", "Refresh Apple Exposure Assessment if product or version data is incomplete."]
    else:
        steps = [
            "Create a backup or confirm important data is backed up.",
            "Open System Settings.",
            "Go to General -> Software Update.",
            "Install available macOS security updates.",
            "Restart if prompted.",
            "Reopen MSAA and refresh Apple Exposure Assessment.",
            "Confirm detected macOS version/build changed or the update no longer appears.",
        ]
        actions = ["Install available macOS security updates from Software Update.", "Restart if prompted and re-run Apple Exposure Assessment."]

    if cves:
        actions.insert(0, f"Review Apple/NVD context for: {', '.join(cves)}.")
        common_verification.append("Verify macOS/app version no longer matches affected version.")
    else:
        actions.insert(0, "No CVE was associated with this finding. Verify Apple update status and review vendor or Apple guidance.")
        common_verification.append("Confirm no CVE-specific action was inferred without source data.")

    limitations = _freshness_limitations(freshness_metadata)
    if missing:
        limitations.append("Some source data is incomplete. Review Apple Exposure Diagnostics and refresh the assessment.")
    if "recommended_version" in missing:
        limitations.append("Recommended/fixed version could not be determined automatically. Review Software Update and official Apple references.")
    if "affected_product" in missing:
        limitations.append("Product information is incomplete. Review Apple Exposure Diagnostics and refresh the assessment.")

    return AppleExposureUpdateGuide(
        guide_id=f"apple-guide-{payload.get('source_card_id') or payload.get('source_finding_id') or generated_at}",
        source_card_id=payload.get("source_card_id", ""),
        source_finding_id=payload.get("source_finding_id", ""),
        source_item_id=payload.get("source_card_id") or payload.get("source_finding_id", ""),
        title=title,
        affected_product=product,
        affected_component=component,
        detected_version=detected,
        recommended_version=recommended,
        forecast_level=level,
        applicability=applicability,
        confidence=confidence,
        why_update_is_recommended=why,
        urgency_explanation=urgency,
        recommended_actions=actions,
        step_by_step_update_instructions=steps,
        verification_steps=common_verification,
        pre_update_precautions=common_precautions,
        evidence_preservation_notes=common_precautions,
        post_update_checks=["Re-run Apple Exposure Assessment.", "Review whether the card is resolved, reviewed, or still applicable.", "Review related monitor events if the card was urgent or critical."],
        rollback_or_recovery_notes=["Keep backups available before updating.", "If an update causes operational impact, document the change and use normal Apple-supported recovery paths."],
        official_references=_references(payload),
        limitations=limitations or ["Guidance is based on local Apple Exposure data and official references attached to the item."],
        generated_at=generated_at,
        missing_fields=missing,
        fallback_used=bool(missing),
    )
