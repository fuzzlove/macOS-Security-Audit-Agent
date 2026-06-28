from __future__ import annotations

import json
from pathlib import Path

from mac_audit_agent.evidence_graph import EvidenceGraphBuilder, export_graph_json
from mac_audit_agent.models import Finding, PortSnapshot, ProcessSnapshot, ScanResult
from mac_audit_agent.reporting import export_scan_result_json


def _finding() -> Finding:
    return Finding(
        id="finding-launchdaemon",
        category="Persistence",
        title="New LaunchDaemon",
        severity="high",
        description="New LaunchDaemon points to an unsigned process.",
        evidence="/Library/LaunchDaemons/com.test.plist -> /tmp/.worker",
        command_used="launchctl print",
        remediation_suggestion="Verify the LaunchDaemon target and signature.",
        warning="Review before removal.",
        related_path="/tmp/.worker",
    )


def _scan_result() -> ScanResult:
    return ScanResult(
        scan_id="scan-graph",
        timestamp="2026-06-27T12:00:00+00:00",
        hostname="mac.local",
        current_user="m",
        findings=[_finding()],
        collected_artifacts={
            "processes": {
                "all": [
                    ProcessSnapshot(
                        pid=4242,
                        ppid=1,
                        user="m",
                        command_path="/tmp/.worker",
                        process_name=".worker",
                        signed_status="unsigned",
                        trust_level="untrusted",
                    )
                ],
                "suspicious": [],
                "errors": [],
            },
            "ports": {
                "listening": [
                    PortSnapshot(".worker", 4242, "127.0.0.1:7000", 7000, "tcp", "LISTEN")
                ],
                "active_connections": [],
                "suspicious_review_needed": [],
                "errors": [],
            },
            "launch_snapshots": [
                {
                    "path": "/Library/LaunchDaemons/com.test.plist",
                    "label": "com.test",
                    "program": "/tmp/.worker",
                    "suspicious": True,
                }
            ],
            "users": [{"username": "m", "admin": True}],
            "localhost_scan": {},
        },
    )


def test_graph_builds_from_finding() -> None:
    graph = EvidenceGraphBuilder().build_from_scan_result(_scan_result())
    node_ids = {node.node_id for node in graph.nodes}
    edge_types = {edge.edge_type for edge in graph.edges}

    assert "finding:finding-launchdaemon" in node_ids
    assert "process:4242" in node_ids
    assert "launch_item:/Library/LaunchDaemons/com.test.plist" in node_ids
    assert {"started", "connected_to", "related_to"} <= edge_types
    chain = graph.evidence_chain("finding:finding-launchdaemon")
    assert any(item["to"] == "process:4242" for item in chain)


def test_related_events_linked() -> None:
    event = {
        "event_id": "event-1",
        "timestamp": "2026-06-27T12:01:00+00:00",
        "event_type": "launchdaemon_added",
        "related_path": "/tmp/.worker",
        "related_pid": 4242,
        "related_user": "m",
        "evidence": "LaunchDaemon observed.",
    }
    graph = EvidenceGraphBuilder().build_from_scan_result(_scan_result(), monitor_events=[event])

    assert "event:event-1" in {node.node_id for node in graph.nodes}
    assert any(edge.source_id == "event:event-1" and edge.target_id == "process:4242" for edge in graph.edges)
    assert any(edge.source_id == "event:event-1" and edge.target_id == "user:m" for edge in graph.edges)


def test_export_works(tmp_path: Path) -> None:
    graph = EvidenceGraphBuilder().build_from_scan_result(_scan_result())
    output = export_graph_json(graph, tmp_path / "graph.json")
    payload = json.loads(output.read_text(encoding="utf-8"))

    assert payload["node_count"] >= 4
    assert payload["edge_count"] >= 3
    assert any(node["node_type"] == "finding" for node in payload["nodes"])


def test_report_export_includes_evidence_graph(tmp_path: Path) -> None:
    scan_result = _scan_result()
    path = export_scan_result_json(scan_result, tmp_path / "report.json")
    payload = json.loads(path.read_text(encoding="utf-8"))

    assert payload["evidence_graph"]["node_count"] >= 4
    assert payload["report_summary"]["evidence_graph"]["edge_count"] >= 3
