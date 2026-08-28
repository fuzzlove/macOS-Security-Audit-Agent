from __future__ import annotations

PROHIBITED_BY_DEFAULT = frozenset({
    "keystroke_logging", "continuous_screen_capture", "continuous_webcam_capture",
    "continuous_microphone_capture", "facial_recognition", "emotion_recognition",
    "disability_inference", "mental_health_inference", "disciplinary_threat_scoring",
    "targeted_advertising", "external_ai_training", "silent_location_tracking",
    "automatic_law_enforcement_referral",
})


def require_privacy_exception(capability: str, approvals: dict[str, bool]) -> None:
    if capability not in PROHIBITED_BY_DEFAULT:
        return
    required = {"legal_authority", "necessity", "less_invasive_alternatives", "retention_limit", "privacy_review", "civil_rights_review", "accessibility_review", "executive_approval"}
    missing = sorted(name for name in required if not approvals.get(name))
    if missing:
        raise PermissionError(
            f"[EDU-PRIV002] '{capability}' is prohibited by default; missing approvals={missing}. No collection or response was performed."
        )
