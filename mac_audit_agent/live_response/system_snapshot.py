from __future__ import annotations

from typing import Any

from mac_audit_agent.collectors import CollectorSuite
from mac_audit_agent.config import AuditConfig
from mac_audit_agent.live_response.artifact_collectors import collect_gap_file_metadata, overlap_warnings, safety_policy
from mac_audit_agent.live_response.evidence_mapper import (
    file_artifacts_from_scan,
    network_artifacts_from_network_intelligence,
    network_artifacts_from_scan,
    persistence_artifacts_from_report,
    persistence_artifacts_from_scan,
    process_artifacts_from_scan,
    security_artifacts_from_scan,
    user_session_artifacts_from_scan,
)
from mac_audit_agent.live_response.models import LiveResponseSnapshot
from mac_audit_agent.network_intelligence import NetworkIntelligenceCollector
from mac_audit_agent.network_intelligence.baseline import snapshot_from_dict
from mac_audit_agent.persistence_intelligence.scanner import PersistenceIntelligenceEngine, ScanContext
from mac_audit_agent.runner import RunnerConfig, SafeCommandRunner


def create_live_response_snapshot(
    db,
    *,
    scope: str = "quick",
    linked_case_id: str = "",
    scan_result=None,
    run_scan_if_missing: bool = True,
    include_gap_file_metadata: bool | None = None,
) -> LiveResponseSnapshot:
    diagnostics: dict[str, Any] = {
        "module_loaded": True,
        "collector_overlap_detected": True,
        "overlap_warnings": overlap_warnings(),
        "fallback_collectors_used": [],
        "missing_permissions": [],
        "errors": [],
        "safety": safety_policy(),
    }
    collectors_used: list[str] = []
    if scan_result is None:
        scan_result = db.latest_scan_result()
    if scan_result is None and run_scan_if_missing:
        try:
            runner = SafeCommandRunner(RunnerConfig(dry_run=False))
            scan_result = CollectorSuite(runner, AuditConfig(logs_dir=db.logs_dir)).run_safe_scan()
            collectors_used.append("msaa_safe_scan")
        except Exception as exc:
            diagnostics["errors"].append(f"MSAA safe scan unavailable: {type(exc).__name__}: {exc}")
    elif scan_result is not None:
        collectors_used.append("msaa_latest_scan")

    latest_network_payload = None
    try:
        previous_network = db.latest_network_intelligence_snapshot()
        baseline = snapshot_from_dict(previous_network) if previous_network else None
        network_snapshot = NetworkIntelligenceCollector().collect(baseline=baseline, settings={"network_activity_monitoring_enabled": True})
        db.record_network_intelligence_snapshot(network_snapshot)
        latest_network_payload = network_snapshot.to_dict()
        collectors_used.append("msaa_network_intelligence")
    except Exception as exc:
        diagnostics["errors"].append(f"Network Intelligence unavailable: {type(exc).__name__}: {exc}")
        latest_network_payload = db.latest_network_intelligence_snapshot()
        if latest_network_payload:
            collectors_used.append("msaa_network_intelligence_cached")

    persistence_report = None
    try:
        persistence_report = PersistenceIntelligenceEngine(ScanContext()).scan()
        collectors_used.append("msaa_persistence_intelligence")
    except Exception as exc:
        diagnostics["errors"].append(f"Persistence Intelligence unavailable: {type(exc).__name__}: {exc}")

    process_artifacts = process_artifacts_from_scan(scan_result)
    network_artifacts = network_artifacts_from_network_intelligence(latest_network_payload) or network_artifacts_from_scan(scan_result)
    file_artifacts = file_artifacts_from_scan(scan_result)
    persistence_artifacts = persistence_artifacts_from_report(persistence_report) if persistence_report else persistence_artifacts_from_scan(scan_result)
    user_session_artifacts = user_session_artifacts_from_scan(scan_result)
    security_artifacts = security_artifacts_from_scan(scan_result)

    should_collect_gap_metadata = include_gap_file_metadata if include_gap_file_metadata is not None else scope in {"standard", "full", "custom"}
    if should_collect_gap_metadata:
        gap_files, warnings = collect_gap_file_metadata(scope)
        file_artifacts.extend(gap_files)
        diagnostics["fallback_collectors_used"].append("mlrc_gap_file_metadata")
        diagnostics["missing_permissions"].extend([warning for warning in warnings if "permission" in warning.lower()])
        diagnostics.setdefault("warnings", []).extend(warnings)

    snapshot = LiveResponseSnapshot(
        collection_scope=scope,
        collectors_used=collectors_used,
        process_artifacts=process_artifacts,
        network_artifacts=network_artifacts,
        file_system_artifacts=file_artifacts,
        persistence_artifacts=persistence_artifacts,
        user_session_artifacts=user_session_artifacts,
        security_artifacts=security_artifacts,
        diagnostics=diagnostics,
        linked_case_id=linked_case_id,
    )
    total_sources = len(collectors_used) + len(diagnostics["fallback_collectors_used"])
    diagnostics["msaa_subsystem_reuse_rate"] = round(len(collectors_used) / total_sources, 3) if total_sources else 0
    diagnostics["artifact_counts"] = snapshot.artifact_counts()
    diagnostics["snapshot_success"] = True
    snapshot.compute_evidence_hash()
    if hasattr(db, "record_live_response_snapshot"):
        db.record_live_response_snapshot(snapshot)
    return snapshot
