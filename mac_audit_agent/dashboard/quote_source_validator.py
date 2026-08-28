from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from mac_audit_agent.dashboard.security_quotes import SecurityQuote


MAX_QUOTE_TEXT_LENGTH = 240
KNOWN_BAD_ATTRIBUTION_MARKERS = [
    "einstein",
    "churchill",
    "fake nsa",
    "anonymous hacker",
]


@dataclass
class QuoteValidationResult:
    quote_id: str
    valid: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def validate_security_quote(quote: SecurityQuote) -> QuoteValidationResult:
    errors: list[str] = []
    warnings: list[str] = []
    if not quote.quote_id:
        errors.append("quote_id is required")
    if not quote.text.strip():
        errors.append("text is required")
    if len(quote.text) > MAX_QUOTE_TEXT_LENGTH:
        errors.append("quote text exceeds UI/copyright safety length")
    if not quote.author.strip() and quote.source_type not in {"proverb", "security_principle"}:
        errors.append("author is required unless quote is a proverb or security principle")
    if not quote.source_title.strip():
        errors.append("source_title is required")
    if not quote.source_reference.strip():
        errors.append("source_reference is required")
    if not quote.theme_tags:
        errors.append("at least one theme tag is required")
    if quote.copyright_status == "unknown_do_not_use":
        errors.append("unknown_do_not_use quotes cannot be displayed")
    if quote.attribution_confidence == "unknown":
        errors.append("unknown attribution cannot be displayed")
    if quote.attribution_confidence == "disputed" and quote.enabled:
        errors.append("disputed attribution must be disabled by default")
    if quote.source_type == "security_principle" and quote.author != "Security Principle":
        errors.append("paraphrased security principles must use author 'Security Principle'")
    if quote.source_type == "security_principle" and "derived" not in quote.source_reference.lower():
        warnings.append("security principle should identify derived-from source guidance")
    lowered = f"{quote.author} {quote.text} {quote.source_reference}".lower()
    if any(marker in lowered for marker in KNOWN_BAD_ATTRIBUTION_MARKERS):
        errors.append("known bad or high-risk attribution marker present")
    if "nsa" in lowered and quote.source_type != "security_principle":
        errors.append("NSA entries must be paraphrased security principles unless a direct public source is verified")
    if any(agency in lowered for agency in ["cisa", "nist", "dod", "nsa"]) and "endorsement" in lowered:
        errors.append("agency endorsement wording is forbidden")
    return QuoteValidationResult(quote.quote_id, not errors, errors, warnings)


def validate_quote_library(quotes: Iterable[SecurityQuote]) -> list[QuoteValidationResult]:
    return [validate_security_quote(quote) for quote in quotes]


def invalid_quote_results(quotes: Iterable[SecurityQuote]) -> list[QuoteValidationResult]:
    return [result for result in validate_quote_library(quotes) if not result.valid]
