from __future__ import annotations

import html
import re
from dataclasses import dataclass
from typing import Any

try:
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QBrush, QColor, QFont
except Exception:  # pragma: no cover - allows report/export imports without Qt
    Qt = None  # type: ignore[assignment]
    QBrush = QColor = QFont = None  # type: ignore[assignment]


SOLID_HEX_RE = re.compile(r"^#[0-9A-Fa-f]{6}$")


@dataclass(frozen=True)
class SeverityStyle:
    label: str
    background: str
    foreground: str
    border: str
    accent: str
    icon: str
    sort_rank: int
    cvss_min: float | None
    cvss_max: float | None
    description: str


SEVERITY_STYLES: dict[str, SeverityStyle] = {
    "none": SeverityStyle("NONE", "#475467", "#FFFFFF", "#D0D5DD", "#98A2B3", "-", 0, 0.0, 0.0, "No CVSS severity or no current security impact."),
    "info": SeverityStyle("INFO", "#344054", "#FFFFFF", "#D0D5DD", "#98A2B3", "i", 1, None, None, "Informational context, not necessarily a security issue."),
    "low": SeverityStyle("LOW", "#175CD3", "#FFFFFF", "#B2DDFF", "#53B1FD", "i", 2, 0.1, 3.9, "Low severity: informational or low-impact issue."),
    "medium": SeverityStyle("MEDIUM", "#B54708", "#FFFFFF", "#FEDF89", "#F79009", "!", 3, 4.0, 6.9, "Medium severity: review during normal security triage."),
    "high": SeverityStyle("HIGH", "#B42318", "#FFFFFF", "#FFCDCA", "#F04438", "!", 4, 7.0, 8.9, "High severity: review as soon as possible."),
    "critical": SeverityStyle("CRITICAL", "#7A0000", "#FFFFFF", "#FFB4A8", "#FF6B6B", "!", 5, 9.0, 10.0, "Critical severity: immediate review recommended."),
    "unknown": SeverityStyle("UNKNOWN", "#667085", "#FFFFFF", "#D0D5DD", "#98A2B3", "?", -1, None, None, "Unknown severity: review the source data before triage."),
    "success": SeverityStyle("HEALTHY", "#027A48", "#FFFFFF", "#A6F4C5", "#12B76A", "OK", 0, None, None, "Healthy or successful status."),
    "healthy": SeverityStyle("HEALTHY", "#027A48", "#FFFFFF", "#A6F4C5", "#12B76A", "OK", 0, None, None, "Healthy or successful status."),
}


SEVERITY_ALIASES = {
    "": "unknown",
    "informational": "info",
    "information": "info",
    "neutral": "info",
    "clear": "success",
    "ok": "success",
    "passed": "success",
    "pass": "success",
    "verified": "success",
    "resolved": "success",
    "reviewed": "success",
    "trusted": "success",
    "legitimate": "success",
    "likely_legitimate": "success",
    "known": "success",
    "unchanged": "success",
    "review": "unknown",
    "review_needed": "unknown",
    "needs_review": "unknown",
    "unavailable": "unknown",
    "unsupported": "unknown",
    "disabled": "unknown",
    "urgent": "critical",
    "high_risk": "critical",
    "suspicious": "high",
    "elevated": "high",
    "watch": "medium",
    "warning": "medium",
    "open": "medium",
    "partial": "medium",
    "stale": "medium",
    "degraded": "medium",
    "new": "medium",
    "changed": "medium",
    "modified": "critical",
    "hash_changed": "high",
    "failed": "critical",
    "failing": "critical",
    "broken": "critical",
    "criticality_critical": "critical",
}


def _clean(value: Any) -> str:
    return str(value or "").strip().lower().replace("-", "_").replace(" ", "_")


def _numeric_score(value: Any) -> float | None:
    if value in {None, ""}:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def normalize_severity(value: Any, score: Any = None, score_type: str | None = None) -> str:
    numeric = _numeric_score(score if score not in {None, ""} else value)
    normalized_type = _clean(score_type)

    if normalized_type in {"cvss", "cvss_score", "nvd", "vulnerability", "vulnerability_score"} and numeric is not None:
        if numeric == 0:
            return "none"
        if 0 < numeric <= 3.9:
            return "low"
        if numeric <= 6.9:
            return "medium"
        if numeric <= 8.9:
            return "high"
        if numeric <= 10:
            return "critical"
        return "unknown"

    if normalized_type in {"security_score", "safety_score", "health_score"} and numeric is not None:
        if numeric >= 90:
            return "success"
        if numeric >= 70:
            return "medium"
        if numeric >= 40:
            return "high"
        if numeric >= 0:
            return "critical"
        return "unknown"

    if normalized_type in {"risk_score", "risk", "risk_rating"} and numeric is not None:
        if numeric >= 90:
            return "critical"
        if numeric >= 70:
            return "high"
        if numeric >= 40:
            return "medium"
        if numeric >= 20:
            return "low"
        if numeric >= 0:
            return "info"
        return "unknown"

    raw = _clean(value)
    if raw in SEVERITY_STYLES:
        return raw
    if raw in SEVERITY_ALIASES:
        return SEVERITY_ALIASES[raw]
    if numeric is not None and raw == "":
        return normalize_severity("", numeric, "risk_score")
    return "unknown"


def display_severity_label(value: Any, score: Any = None, score_type: str | None = None) -> str:
    return get_severity_style(value, score, score_type).label


def get_severity_style(value: Any, score: Any = None, score_type: str | None = None) -> SeverityStyle:
    return SEVERITY_STYLES[normalize_severity(value, score, score_type)]


def severity_sort_rank(value: Any, score: Any = None, score_type: str | None = None) -> int:
    return get_severity_style(value, score, score_type).sort_rank


def make_severity_tooltip(value: Any, score: Any = None, score_type: str | None = None, reasons: list[str] | None = None) -> str:
    style = get_severity_style(value, score, score_type)
    parts = [style.description]
    if score not in {None, ""}:
        parts.append(f"Score: {score}.")
    if reasons:
        clean_reasons = [str(reason).strip() for reason in reasons if str(reason).strip()]
        if clean_reasons:
            parts.append("Reasons: " + "; ".join(clean_reasons))
    parts.append("NIST/NVD/CVSS-inspired severity palette.")
    return " ".join(parts)


def apply_severity_to_table_item(item, severity: Any, score: Any = None, score_type: str | None = None, *, reasons: list[str] | None = None, text: str | None = None) -> None:
    if item is None:
        return
    normalized = normalize_severity(severity, score, score_type)
    style = SEVERITY_STYLES[normalized]
    item.setText(text if text is not None else style.label)
    item.setToolTip(make_severity_tooltip(severity, score, score_type, reasons))
    if QColor is not None and QBrush is not None:
        item.setBackground(QBrush(QColor(style.background)))
        item.setForeground(QBrush(QColor(style.foreground)))
    if QFont is not None:
        font = item.font()
        font.setBold(True)
        item.setFont(font)
    if Qt is not None:
        item.setTextAlignment(Qt.AlignCenter)
        item.setData(Qt.UserRole, style.sort_rank)


def make_severity_badge(severity: Any, score: Any = None, score_type: str | None = None, *, css_class: str = "severity-badge") -> str:
    normalized = normalize_severity(severity, score, score_type)
    style = SEVERITY_STYLES[normalized]
    classes = f"{css_class} severity-{html.escape(normalized)}"
    return (
        f'<span class="{classes}" '
        f'style="background:{style.background};color:{style.foreground};border:1px solid {style.border};'
        'display:inline-block;border-radius:4px;padding:3px 8px;font-weight:700;">'
        f"{html.escape(style.label)}</span>"
    )


def validate_severity_styles() -> list[str]:
    failures: list[str] = []
    required = {"none", "info", "low", "medium", "high", "critical", "unknown", "success", "healthy"}
    missing = sorted(required - set(SEVERITY_STYLES))
    if missing:
        failures.append(f"missing severity styles: {', '.join(missing)}")
    for key, style in SEVERITY_STYLES.items():
        for field in ["background", "foreground", "border", "accent"]:
            value = getattr(style, field)
            if not SOLID_HEX_RE.match(value):
                failures.append(f"{key}.{field} is not a solid #RRGGBB color: {value}")
            if "rgba" in value.lower() or "transparent" in value.lower():
                failures.append(f"{key}.{field} uses transparency: {value}")
        if not style.label:
            failures.append(f"{key}.label is blank")
    return failures
