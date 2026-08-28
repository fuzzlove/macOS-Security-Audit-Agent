from __future__ import annotations

import json
import random
from dataclasses import asdict, dataclass, field
from datetime import date
from pathlib import Path
from typing import Any, Literal


SourceType = Literal[
    "book",
    "speech",
    "proverb",
    "historical_text",
    "public_domain_translation",
    "modern_quote",
    "internal_msaa_original",
    "security_principle",
]
AttributionConfidence = Literal["verified", "likely", "disputed", "unknown"]
CopyrightStatus = Literal["public_domain", "short_quoted_excerpt", "licensed", "original_msaa", "unknown_do_not_use"]


@dataclass(frozen=True)
class SecurityQuote:
    quote_id: str
    text: str
    author: str
    source_title: str
    source_type: SourceType
    region: str
    culture_or_country: str
    era: str
    theme_tags: list[str] = field(default_factory=list)
    security_relevance: str = ""
    attribution_confidence: AttributionConfidence = "verified"
    copyright_status: CopyrightStatus = "public_domain"
    source_reference: str = ""
    translation_note: str = ""
    enabled: bool = True
    display_weight: int = 1

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def display_author(self) -> str:
        return self.author or ("Security Principle" if self.source_type == "security_principle" else "Proverb")

    @property
    def theme_label(self) -> str:
        return ", ".join(tag.replace("_", " ").title() for tag in self.theme_tags[:3])


@dataclass(frozen=True)
class SecurityWisdomSettings:
    enabled: bool = True
    rotation_mode: str = "daily"
    public_domain_only: bool = False
    include_modern: bool = True
    include_security_principles: bool = True
    include_disputed: bool = False
    theme_filter: list[str] = field(default_factory=list)
    hidden_quote_ids: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, payload: dict[str, Any] | None) -> "SecurityWisdomSettings":
        payload = payload or {}
        return cls(
            enabled=bool(payload.get("enabled", True)),
            rotation_mode=str(payload.get("rotation_mode", "daily") or "daily"),
            public_domain_only=bool(payload.get("public_domain_only", False)),
            include_modern=bool(payload.get("include_modern", True)),
            include_security_principles=bool(payload.get("include_security_principles", True)),
            include_disputed=bool(payload.get("include_disputed", False)),
            theme_filter=[str(item) for item in payload.get("theme_filter", []) if str(item).strip()],
            hidden_quote_ids=[str(item) for item in payload.get("hidden_quote_ids", []) if str(item).strip()],
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def default_quote_path() -> Path:
    return Path(__file__).resolve().parents[1] / "assets" / "security_quotes.json"


def load_security_quotes(path: Path | None = None) -> list[SecurityQuote]:
    quote_path = path or default_quote_path()
    payload = json.loads(quote_path.read_text(encoding="utf-8"))
    rows = payload.get("quotes", payload if isinstance(payload, list) else [])
    return [SecurityQuote(**row) for row in rows if isinstance(row, dict)]


def quote_is_displayable(quote: SecurityQuote, settings: SecurityWisdomSettings | None = None) -> bool:
    settings = settings or SecurityWisdomSettings()
    if not quote.enabled:
        return False
    if quote.quote_id in settings.hidden_quote_ids:
        return False
    if quote.copyright_status == "unknown_do_not_use":
        return False
    if quote.attribution_confidence == "unknown":
        return False
    if quote.attribution_confidence == "disputed" and not settings.include_disputed:
        return False
    if settings.public_domain_only and quote.copyright_status != "public_domain":
        return False
    if quote.source_type == "modern_quote" and not settings.include_modern:
        return False
    if quote.source_type == "security_principle" and not settings.include_security_principles:
        return False
    if settings.theme_filter and not set(settings.theme_filter).intersection(quote.theme_tags):
        return False
    return True


def displayable_security_quotes(settings: SecurityWisdomSettings | None = None, path: Path | None = None) -> list[SecurityQuote]:
    settings = settings or SecurityWisdomSettings()
    return [quote for quote in load_security_quotes(path) if quote_is_displayable(quote, settings)]


def format_security_quote(quote: SecurityQuote) -> str:
    return f"{quote.text}\n- {quote.display_author}, {quote.source_title}"


def legacy_strategy_quotes() -> list[dict[str, str]]:
    return [{"source": quote.display_author, "text": quote.text} for quote in load_security_quotes() if quote.enabled]


def select_security_quote(
    *,
    previous_quote_id: str = "",
    settings: SecurityWisdomSettings | None = None,
    rng: random.Random | None = None,
    today: date | None = None,
    path: Path | None = None,
) -> SecurityQuote:
    settings = settings or SecurityWisdomSettings()
    quotes = displayable_security_quotes(settings, path)
    if not quotes:
        quotes = [quote for quote in load_security_quotes(path) if quote.enabled]
    if not quotes:
        raise ValueError("Security quote library is empty.")
    mode = settings.rotation_mode
    if mode == "daily":
        day = today or date.today()
        return quotes[day.toordinal() % len(quotes)]
    chooser = rng or random.SystemRandom()
    if mode in {"random", "per_launch"}:
        weighted = []
        for quote in quotes:
            if quote.quote_id != previous_quote_id:
                weighted.extend([quote] * max(1, int(quote.display_weight)))
        return chooser.choice(weighted or quotes)
    if previous_quote_id:
        for quote in quotes:
            if quote.quote_id == previous_quote_id:
                return quote
    return quotes[0]


def next_quote(current_quote_id: str, *, settings: SecurityWisdomSettings | None = None, path: Path | None = None) -> SecurityQuote:
    quotes = displayable_security_quotes(settings, path)
    if not quotes:
        quotes = load_security_quotes(path)
    ids = [quote.quote_id for quote in quotes]
    if current_quote_id not in ids:
        return quotes[0]
    return quotes[(ids.index(current_quote_id) + 1) % len(quotes)]


def previous_quote(current_quote_id: str, *, settings: SecurityWisdomSettings | None = None, path: Path | None = None) -> SecurityQuote:
    quotes = displayable_security_quotes(settings, path)
    if not quotes:
        quotes = load_security_quotes(path)
    ids = [quote.quote_id for quote in quotes]
    if current_quote_id not in ids:
        return quotes[0]
    return quotes[(ids.index(current_quote_id) - 1) % len(quotes)]
