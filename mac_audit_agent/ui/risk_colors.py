from __future__ import annotations

import html
from dataclasses import dataclass
from typing import Any

from mac_audit_agent.ui.severity_styles import (
    SEVERITY_STYLES,
    apply_severity_to_table_item,
    normalize_severity,
    severity_sort_rank,
)


@dataclass(frozen=True)
class RiskColors:
    background: str
    text: str
    accent: str


RISK_TO_SEVERITY = {
    "critical": "critical",
    "high_risk": "critical",
    "high": "high",
    "suspicious": "high",
    "medium": "medium",
    "changed": "medium",
    "modified": "critical",
    "new": "medium",
    "low": "low",
    "info": "info",
    "none": "none",
    "unknown": "unknown",
    "review_needed": "unknown",
    "removed": "unknown",
    "disabled": "unknown",
    "unsupported": "unknown",
    "known": "success",
    "unchanged": "success",
    "trusted": "success",
    "legitimate": "success",
    "likely_legitimate": "success",
    "open": "medium",
    "reviewed": "success",
    "resolved": "success",
    "healthy": "success",
    "partial": "medium",
    "degraded": "medium",
    "failed": "critical",
}


def _risk_colors_for(severity: str) -> RiskColors:
    style = SEVERITY_STYLES[severity]
    return RiskColors(style.background, style.foreground, style.border)


RISK_COLOR_MAP: dict[str, RiskColors] = {label: _risk_colors_for(severity) for label, severity in RISK_TO_SEVERITY.items()}

RISK_SORT_RANK = {
    label: severity_sort_rank(severity)
    for label, severity in RISK_TO_SEVERITY.items()
}
RISK_SORT_RANK.update({"high_risk": 95, "suspicious": 85, "trusted": 10, "legitimate": 10, "likely_legitimate": 10})


def _clean(value: Any) -> str:
    return str(value or "").strip().lower().replace("-", "_").replace(" ", "_")


def normalize_risk_label(value: Any, score: Any = None) -> str:
    raw = _clean(value)
    if raw in {"", "none"} and score not in {None, ""}:
        return normalize_severity("", score, "risk_score")
    aliases = {
        "": "unknown",
        "none": "unknown",
        "review": "review_needed",
        "review_needed": "review_needed",
        "needs_review": "review_needed",
        "highrisk": "high_risk",
        "high_risk": "high_risk",
        "likely_trusted": "likely_legitimate",
        "success": "healthy",
    }
    normalized = aliases.get(raw, raw)
    if normalized in RISK_COLOR_MAP:
        return normalized
    return normalize_severity(value, score, "risk_score" if score not in {None, ""} else None)


def display_risk_label(label: Any, score: Any = None) -> str:
    normalized = normalize_risk_label(label, score)
    return normalized.replace("_", " ").upper()


def get_risk_colors(label: Any, score: Any = None) -> RiskColors:
    normalized = normalize_risk_label(label, score)
    return RISK_COLOR_MAP.get(normalized, _risk_colors_for(normalize_severity(normalized, score)))


def risk_sort_rank(label: Any, score: Any = None) -> int:
    normalized = normalize_risk_label(label, score)
    return RISK_SORT_RANK.get(normalized, severity_sort_rank(normalized, score))


def make_risk_tooltip(label: Any, score: Any = None, reasons: list[str] | None = None) -> str:
    normalized = display_risk_label(label, score)
    parts = [f"Risk rating: {normalized}."]
    if score not in {None, ""}:
        parts.append(f"Risk score: {score}/100.")
    if reasons:
        parts.append("Reasons: " + "; ".join(str(reason) for reason in reasons if str(reason).strip()))
    parts.append("NIST/NVD/CVSS-inspired severity palette.")
    return " ".join(parts)


def apply_risk_item_style(item, label: Any, score: Any = None, *, reasons: list[str] | None = None, text: str | None = None) -> None:
    normalized = normalize_risk_label(label, score)
    severity = RISK_TO_SEVERITY.get(normalized, normalize_severity(normalized, score, "risk_score" if score not in {None, ""} else None))
    apply_severity_to_table_item(
        item,
        severity,
        score,
        "risk_score" if score not in {None, ""} else None,
        reasons=reasons,
        text=text if text is not None else display_risk_label(normalized),
    )
    if item is not None:
        item.setToolTip(make_risk_tooltip(normalized, score, reasons))
        try:
            item.setData(256, risk_sort_rank(normalized, score))
        except Exception:
            pass


def risk_badge_html(label: Any, score: Any = None) -> str:
    normalized = normalize_risk_label(label, score)
    colors = get_risk_colors(normalized)
    text = html.escape(display_risk_label(normalized))
    return (
        f'<span class="risk-badge risk-{html.escape(normalized)} severity-{html.escape(RISK_TO_SEVERITY.get(normalized, normalized))}" '
        f'style="background:{colors.background};color:{colors.text};border:1px solid {colors.accent};'
        'display:inline-block;border-radius:4px;padding:3px 8px;font-weight:700;">'
        f"{text}</span>"
    )
