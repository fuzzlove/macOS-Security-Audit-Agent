from __future__ import annotations

from typing import Any


def remediation_summary(remediation: dict[str, Any]) -> str:
    immediate = "; ".join(remediation.get("immediate", ()))
    long_term = "; ".join(remediation.get("long_term", ()))
    return f"Immediate: {immediate}\nLong-term: {long_term}".strip()


__all__ = ["remediation_summary"]
