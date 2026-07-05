from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any


SOLID_HEX_RE = re.compile(r"^#[0-9A-Fa-f]{6}$")


@dataclass(frozen=True)
class AlertSeverityStyle:
    severity: str
    background: str
    border: str
    title_text: str
    body_text: str
    badge_background: str
    badge_text: str
    icon: str
    default_duration_seconds: int
    persistent_by_default: bool
    primary_button_background: str = "#FFFFFF"
    primary_button_text: str = "#101828"
    secondary_button_background: str = "#1D2939"
    secondary_button_text: str = "#FFFFFF"
    focus_border: str = "#FFFFFF"
    opacity: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


ALERT_SEVERITY_STYLES: dict[str, AlertSeverityStyle] = {
    "critical": AlertSeverityStyle(
        severity="critical",
        background="#7A0000",
        border="#FFB4A8",
        title_text="#FFFFFF",
        body_text="#FFF5F5",
        badge_background="#FFB4A8",
        badge_text="#3B0000",
        icon="!",
        default_duration_seconds=0,
        persistent_by_default=True,
        primary_button_text="#7A0000",
    ),
    "high": AlertSeverityStyle(
        severity="high",
        background="#B42318",
        border="#FFCDCA",
        title_text="#FFFFFF",
        body_text="#FFF5F5",
        badge_background="#FFCDCA",
        badge_text="#4E1A14",
        icon="!",
        default_duration_seconds=20,
        persistent_by_default=False,
        primary_button_text="#B42318",
    ),
    "medium": AlertSeverityStyle(
        severity="medium",
        background="#B54708",
        border="#FEDF89",
        title_text="#FFFFFF",
        body_text="#FFF8EB",
        badge_background="#FEDF89",
        badge_text="#4E2A00",
        icon="!",
        default_duration_seconds=15,
        persistent_by_default=False,
        primary_button_text="#7A3A00",
    ),
    "low": AlertSeverityStyle(
        severity="low",
        background="#175CD3",
        border="#B2DDFF",
        title_text="#FFFFFF",
        body_text="#EFF8FF",
        badge_background="#B2DDFF",
        badge_text="#102A56",
        icon="i",
        default_duration_seconds=10,
        persistent_by_default=False,
        primary_button_text="#175CD3",
    ),
    "info": AlertSeverityStyle(
        severity="info",
        background="#344054",
        border="#D0D5DD",
        title_text="#FFFFFF",
        body_text="#F2F4F7",
        badge_background="#D0D5DD",
        badge_text="#101828",
        icon="i",
        default_duration_seconds=8,
        persistent_by_default=False,
    ),
    "success": AlertSeverityStyle(
        severity="success",
        background="#027A48",
        border="#A6F4C5",
        title_text="#FFFFFF",
        body_text="#ECFDF3",
        badge_background="#A6F4C5",
        badge_text="#054F31",
        icon="OK",
        default_duration_seconds=8,
        persistent_by_default=False,
        primary_button_text="#027A48",
    ),
}


STYLE_ALIAS_TO_SEVERITY = {
    "critical_red": "critical",
    "high_orange": "high",
    "medium_blue": "medium",
    "info_grey": "info",
    "neutral_grey": "info",
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "success": "success",
    "resolved": "success",
}


SEVERITY_STYLES: dict[str, dict[str, Any]] = {
    alias: ALERT_SEVERITY_STYLES[severity].to_dict()
    for alias, severity in STYLE_ALIAS_TO_SEVERITY.items()
}


def canonical_alert_severity(value: str | None) -> str:
    normalized = str(value or "info").strip().lower()
    return STYLE_ALIAS_TO_SEVERITY.get(normalized, normalized if normalized in ALERT_SEVERITY_STYLES else "info")


def get_alert_style(severity: str | None) -> AlertSeverityStyle:
    return ALERT_SEVERITY_STYLES[canonical_alert_severity(severity)]


def validate_alert_styles() -> list[str]:
    failures: list[str] = []
    required = {"critical", "high", "medium", "low", "info", "success"}
    missing = sorted(required - set(ALERT_SEVERITY_STYLES))
    if missing:
        failures.append(f"missing severity styles: {', '.join(missing)}")
    for severity, style in ALERT_SEVERITY_STYLES.items():
        payload = style.to_dict()
        for key in [
            "background",
            "border",
            "title_text",
            "body_text",
            "badge_background",
            "badge_text",
            "primary_button_background",
            "primary_button_text",
            "secondary_button_background",
            "secondary_button_text",
        ]:
            value = str(payload[key])
            if not SOLID_HEX_RE.match(value):
                failures.append(f"{severity}.{key} is not a solid #RRGGBB color: {value}")
            if "rgba" in value.lower() or "transparent" in value.lower():
                failures.append(f"{severity}.{key} uses transparency: {value}")
        if float(style.opacity) != 1.0:
            failures.append(f"{severity}.opacity must be 1.0")
    if ALERT_SEVERITY_STYLES["critical"].background == ALERT_SEVERITY_STYLES["high"].background:
        failures.append("critical and high backgrounds must be distinct")
    if ALERT_SEVERITY_STYLES["medium"].background == ALERT_SEVERITY_STYLES["info"].background:
        failures.append("medium and info backgrounds must be distinct")
    return failures


def apply_alert_style(widget: Any, severity: str | None) -> None:
    style = get_alert_style(severity)
    widget.setStyleSheet(
        f"background-color: {style.background};"
        f"color: {style.body_text};"
        f"border: 1px solid {style.border};"
    )
