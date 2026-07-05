from __future__ import annotations

from typing import Any


def build_live_response_report(snapshot) -> dict[str, Any]:
    if snapshot is None:
        return {
            "section": "Live Response Collection",
            "summary": {"status": "not_collected", "snapshot_id": "", "evidence_hash": "", "integrity_status": "unknown"},
            "artifact_counts": {},
            "collectors_used": [],
            "diagnostics": {"last_error": "Live Response Collection has not run yet."},
        }
    payload = snapshot.to_dict() if hasattr(snapshot, "to_dict") else dict(snapshot)
    return {
        "section": "Live Response Collection",
        "summary": {
            "status": "ok" if not payload.get("diagnostics", {}).get("errors") else "degraded",
            "snapshot_id": payload.get("snapshot_id", ""),
            "timestamp": payload.get("timestamp", ""),
            "scope": payload.get("collection_scope", ""),
            "evidence_hash": payload.get("evidence_hash", ""),
            "integrity_status": payload.get("integrity_status", ""),
            "linked_case_id": payload.get("linked_case_id", ""),
        },
        "artifact_counts": payload.get("artifact_counts", {}),
        "collectors_used": payload.get("collectors_used", []),
        "overlap_warnings": payload.get("diagnostics", {}).get("overlap_warnings", []),
        "fallback_collectors_used": payload.get("diagnostics", {}).get("fallback_collectors_used", []),
        "diagnostics": payload.get("diagnostics", {}),
        "process_artifacts": payload.get("process_artifacts", []),
        "network_artifacts": payload.get("network_artifacts", []),
        "file_system_artifacts": payload.get("file_system_artifacts", []),
        "persistence_artifacts": payload.get("persistence_artifacts", []),
        "user_session_artifacts": payload.get("user_session_artifacts", []),
        "security_artifacts": payload.get("security_artifacts", []),
        "recommended_analysis_steps": [
            "Review high-risk process, network, and persistence artifacts first.",
            "Verify the evidence hash before transferring the snapshot.",
            "Correlate this snapshot with Security Timeline events and linked case notes.",
        ],
    }
