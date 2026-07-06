from __future__ import annotations

SUPPORT_LINKS = {
    "developer": "Liquidsky Network Security",
    "github": "https://github.com/fuzzlove",
    "website": "https://liquidskysecurity.com",
    "patreon": "https://patreon.com/fuzzlove",
    "buy_me_a_coffee": "https://buymeacoffee.com/fuzzlove",
}


def canonical_support_url(key: str = "patreon") -> str:
    return SUPPORT_LINKS[key]


__all__ = ["SUPPORT_LINKS", "canonical_support_url"]
