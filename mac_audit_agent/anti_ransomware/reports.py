"""Shared report payload builder."""

from __future__ import annotations

from .mitre_mapping import map_behaviors
from .standards_mapping import map_readiness
from .guidance_engine import GuidanceEngine


def build_report(*, assessment: dict, behaviors: list[str], evidence: dict | None = None) -> dict:
    guidance = [GuidanceEngine().resolve({"detection_type": behavior, **assessment}).to_dict() for behavior in behaviors]
    return {"detected_facts": assessment, "analyst_hypotheses": [],
            "mitre_attack": [item.to_dict() for item in map_behaviors(behaviors, evidence)],
            "government_guidance": guidance,
            "standards_readiness": [item.to_dict() for item in map_readiness(audit_logging=True, recovery_ready=False, containment_policy=False)],
            "disclaimer": "Evidence and readiness support only; not certification or guaranteed protection."}


__all__ = ["build_report"]
