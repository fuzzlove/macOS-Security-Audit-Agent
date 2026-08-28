from __future__ import annotations

from datetime import datetime, timezone, tzinfo

UTC: tzinfo = timezone.utc


def utc_now() -> datetime:
    """Return a timezone-aware current UTC datetime."""
    return datetime.now(UTC)


__all__ = ["UTC", "utc_now"]
