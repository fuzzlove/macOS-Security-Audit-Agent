from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

FEATURE_ID = "MSAA_LOCKDOWN_PROFILE_V1"
PRODUCT_NAME = "MSAA Emergency Protection Mode"
APPLE_DISCLAIMER = "This is an MSAA-created security profile. It does not enable or claim to enforce Apple's Lockdown Mode."
PROFILE_DIR = Path(__file__).with_name("lockdown_profiles")
PROFILE_NAMES = frozenset({"emergency", "critical_zero_day", "ransomware_response", "investigation_mode"})


@dataclass(frozen=True)
class LockdownProfile:
    profile_id: str
    name: str
    purpose: str
    controls: tuple[dict[str, Any], ...]
    monitoring: tuple[str, ...]
    compliance: dict[str, tuple[str, ...]]
    network_mode: str
    score_adjustments: dict[str, int]
    sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {"feature_id": FEATURE_ID, "product_name": PRODUCT_NAME, "profile_id": self.profile_id, "name": self.name, "purpose": self.purpose, "controls": list(self.controls), "monitoring": list(self.monitoring), "compliance": {k: list(v) for k, v in self.compliance.items()}, "network_mode": self.network_mode, "score_adjustments": self.score_adjustments, "sha256": self.sha256, "apple_lockdown_mode": False, "disclaimer": APPLE_DISCLAIMER}


def load_profile(name: str, profile_dir: Path | None = None) -> LockdownProfile:
    normalized = str(name).strip().lower().removesuffix(".json")
    if normalized not in PROFILE_NAMES:
        raise ValueError(f"Unknown MSAA Emergency Protection profile: {name}")
    path = (profile_dir or PROFILE_DIR) / f"{normalized}.json"
    raw = path.read_bytes()
    payload = json.loads(raw)
    if payload.get("feature_id") != FEATURE_ID or payload.get("product_name") != PRODUCT_NAME:
        raise ValueError("Profile identity mismatch; refusing to load.")
    controls = payload.get("controls", [])
    if not isinstance(controls, list) or not controls:
        raise ValueError("Emergency profile contains no controls.")
    return LockdownProfile(normalized, str(payload["name"]), str(payload["purpose"]), tuple(dict(item) for item in controls), tuple(str(item) for item in payload.get("monitoring", [])), {str(k): tuple(str(v) for v in values) for k, values in payload.get("compliance", {}).items()}, str(payload.get("network_mode", "normal")), {str(k): int(v) for k, v in payload.get("score_adjustments", {}).items()}, hashlib.sha256(raw).hexdigest())


def profile_impact_summary(profile: LockdownProfile) -> dict[str, Any]:
    """Return operator-facing consequences derived from the enforceable profile."""
    control_ids = {str(control.get("id", "")) for control in profile.controls}
    changes: list[str] = []
    negative_impacts: list[str] = []
    if "remote_login" in control_ids:
        changes.append("Disables macOS Remote Login (SSH).")
        negative_impacts.append("Existing SSH sessions and SSH-based administration may be interrupted; new SSH connections will fail until rollback.")
    if "application_firewall" in control_ids:
        changes.append("Enables the macOS Application Firewall if it is currently off.")
        negative_impacts.append("Applications that accept inbound connections may prompt for permission or become unreachable until firewall rules are approved or the prior state is restored.")

    if profile.network_mode == "normal":
        network_effect = "No PF network isolation is requested or applied. Existing network connectivity remains in place."
    else:
        network_effect = (
            f"The profile requests '{profile.network_mode}' networking, but MSAA does not apply PF isolation without a separately reviewed incident allowlist. "
            "Activation therefore does not disconnect Wi-Fi/Ethernet, block outbound traffic, or guarantee host isolation."
        )

    return {
        "profile_id": profile.profile_id,
        "name": profile.name,
        "purpose": profile.purpose,
        "system_changes": changes,
        "negative_impacts": negative_impacts,
        "network_effect": network_effect,
        "monitoring_effect": (
            f"Records {len(profile.monitoring)} requested monitoring categories. Availability depends on installed, authorized, and healthy MSAA sensors; "
            "selecting the profile does not grant Full Disk Access, Accessibility, or Endpoint Security entitlements."
        ),
        "not_performed": [
            "Does not enable Apple's Lockdown Mode.",
            "Does not automatically terminate or quarantine processes or delete files.",
            "Does not disable Wi-Fi, Ethernet, Bluetooth, USB, sharing services, or user accounts.",
            "Does not guarantee containment of malware or ransomware.",
        ],
        "rollback": (
            "Before changing settings, MSAA records the observed Remote Login and firewall state. The prepared rollback command attempts to restore those values. "
            "Rollback can fail or require manual recovery if the machine loses power, state evidence is damaged, another administrator changes settings, or macOS rejects a command."
        ),
        "authorization": "Activation changes system settings, requires administrator authorization, and writes local authorization, inventory, result, and audit evidence.",
    }
