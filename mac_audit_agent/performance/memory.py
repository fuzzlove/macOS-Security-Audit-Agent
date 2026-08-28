from __future__ import annotations

import gc
import json
import os
import resource
from collections.abc import Iterable, Iterator
from typing import Any


def get_process_memory_mb() -> float:
    usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if os.uname().sysname == "Darwin":
        return usage / (1024 * 1024)
    return usage / 1024


def memory_budget_exceeded(soft_mb: int, hard_mb: int | None = None) -> bool:
    current = get_process_memory_mb()
    return current >= float(hard_mb or soft_mb)


def maybe_gc_after_heavy_task(threshold_mb: int = 1024) -> bool:
    if get_process_memory_mb() >= threshold_mb:
        gc.collect()
        return True
    return False


def cap_text_output(text: str | bytes, max_bytes: int = 1_000_000) -> str:
    data = text.encode("utf-8", errors="replace") if isinstance(text, str) else bytes(text)
    if len(data) <= max_bytes:
        return data.decode("utf-8", errors="replace")
    suffix = f"\n...[truncated to {max_bytes} bytes by MSAA resource budget]..."
    return data[: max(0, max_bytes - len(suffix))].decode("utf-8", errors="replace") + suffix


def stream_json_items(path, *, key: str | None = None) -> Iterator[Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    items = payload.get(key, []) if key and isinstance(payload, dict) else payload
    if isinstance(items, list):
        yield from items
    else:
        yield items


def summarize_large_collection(items: Iterable[Any], *, limit: int = 100) -> dict[str, Any]:
    preview = []
    total = 0
    for total, item in enumerate(items, start=1):
        if len(preview) < limit:
            preview.append(item)
    return {"count": total, "preview": preview, "truncated": total > limit}
