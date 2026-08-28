from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import TypeVar


T = TypeVar("T")


def pre_uat_requested(argv: Sequence[str]) -> bool:
    """Return true only for the explicit, standalone release-testing flag."""
    return "--pre-uat" in argv


def filter_pre_uat_navigation(items: Iterable[T], *, enabled: bool) -> list[T]:
    output = list(items)
    if enabled:
        return output
    return [item for item in output if getattr(item, "id", "") != "pre_uat_audit"]


__all__ = ["filter_pre_uat_navigation", "pre_uat_requested"]
