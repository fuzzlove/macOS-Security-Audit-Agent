"""Rate-aware update scheduling with bounded jitter and source isolation."""

from __future__ import annotations

import hashlib
import random
from datetime import datetime, timedelta
from typing import Any

from .manager import ThreatIntelligenceManager, _time
from .models import utc_now
from .signing import ManifestSigner


class DefinitionUpdateScheduler:
    def __init__(self, manager: ThreatIntelligenceManager, *, jitter_fraction: float = 0.1, random_source: random.Random | None = None) -> None:
        self.manager = manager
        self.jitter_fraction = max(0.0, min(float(jitter_fraction), 0.5))
        self.random = random_source

    def next_update(self, source_id: str) -> datetime:
        adapter = self.manager.registry.get(source_id)
        source = next((item for item in self.manager.source_statuses() if item["source_id"] == source_id), {})
        baseline = _time(source.get("last_attempt")) or utc_now()
        interval = adapter.policy.minimum_interval_seconds
        maximum_jitter = min(interval * self.jitter_fraction, float(self.manager.policy.jitter_seconds))
        if self.random is not None:
            unit = self.random.uniform(-1, 1)
        else:
            material = f"{source_id}\0{baseline.isoformat()}".encode()
            unit = (int.from_bytes(hashlib.sha256(material).digest()[:8], "big") / (2**64 - 1)) * 2 - 1
        jitter = maximum_jitter * unit
        return baseline + timedelta(seconds=max(60, interval + jitter))

    def run_due(self, *, signer: ManifestSigner | None = None, activate: bool = False, now: datetime | None = None) -> dict[str, Any]:
        moment = now or utc_now()
        due_sources: set[str] = set()
        not_due: dict[str, Any] = {}
        for adapter in self.manager.registry.all():
            if not adapter.policy.enabled:
                continue
            status = next((item for item in self.manager.source_statuses() if item["source_id"] == adapter.source_id), {})
            last = _time(status.get("last_attempt"))
            if last is None or moment >= self.next_update(adapter.source_id):
                due_sources.add(adapter.source_id)
            else:
                not_due[adapter.source_id] = {"status": "NOT_DUE", "next_update": self.next_update(adapter.source_id).isoformat()}
        if not due_sources:
            return not_due
        results = self.manager.update_enabled(
            signer=signer, activate=activate, allow_early_update=True,
            source_ids=due_sources,
        )
        for source_id, payload in not_due.items():
            results.setdefault(source_id, payload)
        return results


__all__ = ["DefinitionUpdateScheduler"]
