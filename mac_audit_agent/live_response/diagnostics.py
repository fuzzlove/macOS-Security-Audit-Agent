from __future__ import annotations

from typing import Any


def build_live_response_diagnostics(snapshot=None, *, last_error: str = "") -> dict[str, Any]:
    if snapshot is None:
        return {
            "module_loaded": True,
            "collector_overlap_detected": True,
            "msaa_subsystem_reuse_rate": 0,
            "fallback_collectors_used": [],
            "snapshot_success": False,
            "last_error": last_error or "Live Response Collection has not run yet.",
            "hash_verification_status": "unknown",
        }
    diagnostics = dict(getattr(snapshot, "diagnostics", {}) or {})
    diagnostics.setdefault("module_loaded", True)
    diagnostics.setdefault("collector_overlap_detected", True)
    diagnostics.setdefault("msaa_subsystem_reuse_rate", 1)
    diagnostics.setdefault("fallback_collectors_used", [])
    diagnostics.setdefault("snapshot_success", True)
    diagnostics.setdefault("artifact_counts", snapshot.artifact_counts())
    diagnostics["hash_verification_status"] = "verified" if getattr(snapshot, "evidence_hash", "") else "missing"
    diagnostics["integrity_status"] = getattr(snapshot, "integrity_status", "unknown")
    return diagnostics
