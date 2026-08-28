from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from mac_audit_agent.apple_exposure_guidance import is_meaningful_value


@dataclass
class AppleExposurePayloadValidationResult:
    valid: bool
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    normalized_fields: list[str] = field(default_factory=list)
    missing_recommended_fields: list[str] = field(default_factory=list)
    unsafe_types: list[str] = field(default_factory=list)
    empty_fields: list[str] = field(default_factory=list)
    extra_metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def validate_apple_exposure_payload(payload: Any) -> AppleExposurePayloadValidationResult:
    warnings: list[str] = []
    errors: list[str] = []
    normalized_fields: list[str] = []
    missing: list[str] = []
    unsafe: list[str] = []
    empty: list[str] = []
    extra: dict[str, Any] = {}

    if payload is None:
        return AppleExposurePayloadValidationResult(
            valid=True,
            warnings=["Payload is empty; fallback guidance will be used."],
            missing_recommended_fields=["title", "summary"],
        )
    if hasattr(payload, "to_dict"):
        payload = payload.to_dict()
    elif hasattr(payload, "__dict__") and not isinstance(payload, dict):
        payload = dict(payload.__dict__)
    if not isinstance(payload, dict):
        return AppleExposurePayloadValidationResult(valid=False, errors=[f"Unsupported payload type: {type(payload).__name__}"], unsafe_types=[type(payload).__name__])

    recognized = {
        "title",
        "summary",
        "description",
        "cve",
        "cve_id",
        "cve_ids",
        "cves",
        "kev",
        "kev_cves",
        "references",
        "official_references",
        "affected_product",
        "affected_component",
        "affected_local_product",
        "detected_version",
        "fixed_version",
        "recommended_version",
        "forecast_level",
        "applicability",
        "confidence",
        "alerts",
        "nvd",
        "apple",
    }
    for key, value in payload.items():
        if is_meaningful_value(value):
            normalized_fields.append(str(key))
        else:
            empty.append(str(key))
        if key not in recognized:
            extra[str(key)] = value
    for key in ("title", "summary"):
        if not is_meaningful_value(payload.get(key)):
            missing.append(key)
            warnings.append(f"Missing recommended field: {key}.")
    refs = payload.get("references") or payload.get("official_references")
    if refs is not None and not isinstance(refs, (str, list, tuple, set)):
        warnings.append("References field is malformed; it will be ignored by guidance rendering.")
        unsafe.append("references")
    elif isinstance(refs, (list, tuple, set)) and any(not isinstance(item, str) for item in refs if item is not None):
        warnings.append("References contains non-string entries; malformed entries will be ignored by guidance rendering.")
        unsafe.append("references")
    return AppleExposurePayloadValidationResult(
        valid=not errors,
        warnings=warnings,
        errors=errors,
        normalized_fields=normalized_fields,
        missing_recommended_fields=missing,
        unsafe_types=unsafe,
        empty_fields=empty,
        extra_metadata=extra,
    )
