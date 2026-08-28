"""Bounded entropy comparison; never reads complete user files by default."""

from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    size = len(data)
    return -sum((count / size) * math.log2(count / size) for count in Counter(data).values())


def entropy_delta(before: bytes, after: bytes, *, sample_limit: int = 65536) -> dict[str, float | int]:
    old, new = before[:sample_limit], after[:sample_limit]
    old_entropy, new_entropy = shannon_entropy(old), shannon_entropy(new)
    return {"before": old_entropy, "after": new_entropy, "delta": new_entropy - old_entropy,
            "bytes_sampled_before": len(old), "bytes_sampled_after": len(new)}


__all__ = ["entropy_delta", "shannon_entropy"]
