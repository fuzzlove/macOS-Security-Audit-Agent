from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import Enum
from importlib.resources import files
from typing import Any

from mac_audit_agent.help.topic_models import HelpTopic

DOCUMENTATION_BUNDLE_VERSION = "1.0"


@dataclass(frozen=True)
class DiagnosticTopic:
    code: str
    slug: str
    title: str
    summary: str
    resource: str
    module: str = "anti_ransomware"
    aliases: tuple[str, ...] = ()


@dataclass(frozen=True)
class HelpResolution:
    topic: HelpTopic | None
    requested_topic: str
    normalized_topic: str
    module: str
    reason: str = ""
    expected_resource: str = ""

    def failure_event(self, *, application_version: str = "unknown", build_id: str = "unknown") -> dict[str, str]:
        return {"event":"help_topic_resolution_failed", "requested_topic":self.requested_topic,
            "normalized_topic":self.normalized_topic, "module":self.module,
            "application_version":application_version, "build_id":build_id,
            "resource_bundle_version":DOCUMENTATION_BUNDLE_VERSION, "reason":self.reason,
            "expected_resource":self.expected_resource}


_DEFINITIONS = (
    ("AR001", "anti-ransomware-sensor-not-installed", "Anti-Ransomware Sensor Is Not Installed"),
    ("AR002", "anti-ransomware-sensor-not-loaded", "Anti-Ransomware Sensor Is Not Loaded"),
    ("AR003", "anti-ransomware-sensor-not-running", "Anti-Ransomware Sensor Is Not Running"),
    ("AR004", "anti-ransomware-entitlement-required", "Endpoint Security Entitlement Is Missing or Rejected"),
    ("AR005", "anti-ransomware-privacy-approval-required", "Anti-Ransomware Privacy Approval Is Required"),
    ("AR006", "anti-ransomware-connection-failed", "Endpoint Security Connection Is Unavailable"),
    ("AR014", "anti-ransomware-ipc-rejected", "Anti-Ransomware IPC Request Was Rejected"),
    ("AR016", "anti-ransomware-containment-unavailable", "Anti-Ransomware Containment Is Unavailable"),
    ("AR017", "anti-ransomware-containment-unverified", "Containment Action Could Not Be Verified"),
    ("AR018", "anti-ransomware-rule-invalid", "Anti-Ransomware Trust Rule Is Invalid"),
    ("AR022", "anti-ransomware-degraded-observation", "Anti-Ransomware Protection Is Running in Degraded Observation Mode"),
    ("AR024", "anti-ransomware-protocol-mismatch", "Anti-Ransomware Protocol Version Is Incompatible"),
    ("AR030", "anti-ransomware-safety-check-rejected", "Anti-Ransomware Safety Check Rejected the Operation"),
    ("AR031", "anti-ransomware-managed-approval-required", "Managed Anti-Ransomware Approval Is Required"),
    ("AR033", "anti-ransomware-critical-process-protected", "Critical Process Protection Blocked Containment"),
    ("AR034", "anti-ransomware-authorization-expired", "Containment Authorization Expired"),
)

DIAGNOSTIC_TOPICS: dict[str, DiagnosticTopic] = {
    code: DiagnosticTopic(code, slug, title, f"Actionable guidance for diagnostic {code}.", f"anti_ransomware/{code.lower()}.md", aliases=(f"anti_ransomware:{code}", f"anti-ransomware-{code.lower()}", slug))
    for code, slug, title in _DEFINITIONS
}
DIAGNOSTIC_TOPICS["AR022"] = DiagnosticTopic(**{**DIAGNOSTIC_TOPICS["AR022"].__dict__, "aliases": (*DIAGNOSTIC_TOPICS["AR022"].aliases, "anti_ransomware", "anti-ransomware")})
DIAGNOSTIC_TOPICS.update({
    "PY001": DiagnosticTopic("PY001", "python-runtime-unsupported", "Python Runtime Is Not Supported", "The detected Python runtime cannot start this MSAA mode.", "runtime/py001.md", "runtime", ("runtime:PY001",)),
    "DEP001": DiagnosticTopic("DEP001", "required-dependency-missing", "Required MSAA Dependency Is Missing", "A required runtime dependency is unavailable.", "runtime/dep001.md", "runtime", ("runtime:DEP001",)),
    "MON001": DiagnosticTopic("MON001", "system-monitor-not-installed", "MSAA System Monitor Is Not Installed", "The canonical system monitor service is not installed.", "runtime/mon001.md", "monitor", ("monitor:MON001",)),
    "STD004": DiagnosticTopic("STD004", "standards-source-unavailable", "Compliance Standards Source Is Unavailable", "A required standards source could not be validated.", "compliance/std004.md", "compliance", ("compliance:STD004",)),
})


def normalize_help_identifier(value: Any) -> str:
    if isinstance(value, Enum):
        value = value.value
    if isinstance(value, dict):
        for key in ("error_code", "help_topic", "topic_id", "finding_id", "alert_id", "code"):
            if value.get(key):
                return normalize_help_identifier(value[key])
        return ""
    if not isinstance(value, str):
        return ""
    text = value.strip()
    if text.startswith("{"):
        try:
            return normalize_help_identifier(json.loads(text))
        except (ValueError, TypeError):
            pass
    code = re.search(r"(?:^|[:/\-])\s*([A-Z]{2,12}\s*[-_]?\s*\d{3})$", text, re.IGNORECASE)
    if code:
        return re.sub(r"[^A-Z0-9]", "", code.group(1).upper())
    compact = re.sub(r"\s+", "", text).upper()
    if re.fullmatch(r"[A-Z]{2,12}\d{3}", compact):
        return compact
    return text.lower().replace("_", "-")


def _registration(identifier: Any) -> DiagnosticTopic | None:
    normalized = normalize_help_identifier(identifier)
    if normalized in DIAGNOSTIC_TOPICS:
        return DIAGNOSTIC_TOPICS[normalized]
    for registration in DIAGNOSTIC_TOPICS.values():
        if normalized in {normalize_help_identifier(registration.slug), *(normalize_help_identifier(alias) for alias in registration.aliases)}:
            return registration
    return None


def load_resource(resource: str) -> str:
    return files("mac_audit_agent.help.resources").joinpath(resource).read_text(encoding="utf-8")


def resolve_diagnostic_topic(identifier: Any) -> HelpTopic | None:
    registration = _registration(identifier)
    if registration is None:
        return None
    content = load_resource(registration.resource)
    return HelpTopic(topic_id=registration.slug, title=registration.title, category="Troubleshooting",
        short_summary=registration.summary, user_friendly_explanation=content,
        when_this_matters=[f"MSAA reports diagnostic {registration.code}."],
        what_you_should_do=["Follow the environment-specific steps in this guide and rerun the diagnostic check."],
        advanced_details=f"Stable diagnostic interface: {registration.code}.",
        related_topics=["operational_health", "troubleshooting"], resource=registration.resource,
        resource_content=content, diagnostic_codes=[registration.code], last_updated="2026-07-10")


def resolve_help_topic(identifier: Any) -> HelpResolution:
    requested = str(identifier)
    normalized = normalize_help_identifier(identifier)
    registration = _registration(identifier)
    if registration is None:
        return HelpResolution(None, requested, normalized, "unknown", "topic_not_registered")
    try:
        topic = resolve_diagnostic_topic(identifier)
    except (FileNotFoundError, ModuleNotFoundError, OSError):
        return HelpResolution(None, requested, normalized, registration.module, "resource_missing", registration.resource)
    except (UnicodeError, ValueError):
        return HelpResolution(None, requested, normalized, registration.module, "parse_failure", registration.resource)
    return HelpResolution(topic, requested, normalized, registration.module, expected_resource=registration.resource)


def validate_diagnostic_registry(emitted_codes: set[str] | None = None, registry: dict[str, DiagnosticTopic] | None = None) -> list[dict[str, str]]:
    failures: list[dict[str, str]] = []
    slugs: set[str] = set()
    aliases: dict[str, str] = {}
    selected = DIAGNOSTIC_TOPICS if registry is None else registry
    for code, registration in selected.items():
        if registration.slug in slugs:
            failures.append({"code": code, "reason": "duplicate_code_or_slug"})
        slugs.add(registration.slug)
        try:
            content = load_resource(registration.resource)
            if not content.strip() or not content.lstrip().startswith("# "):
                failures.append({"code": code, "reason": "parse_failure"})
        except (FileNotFoundError, ModuleNotFoundError, OSError):
            failures.append({"code": code, "reason": "resource_missing"})
        for alias in (registration.slug, *registration.aliases):
            normalized = normalize_help_identifier(alias)
            if normalized in aliases and aliases[normalized] != code:
                failures.append({"code": code, "reason": "alias_conflict"})
            aliases[normalized] = code
    for code in emitted_codes or set():
        if code not in selected:
            failures.append({"code": code, "reason": "topic_not_registered"})
    return failures
