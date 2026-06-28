from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from mac_audit_agent.models import ScanResult, utc_now_iso
from mac_audit_agent.storage import json_safe


NODE_TYPES = {"process", "user", "file", "launch_item", "network_endpoint", "device", "finding", "event", "snapshot"}
EDGE_TYPES = {"started", "connected_to", "created", "modified", "owned_by", "observed_with", "related_to", "first_seen_after"}


@dataclass
class EvidenceNode:
    node_id: str
    node_type: str
    label: str
    summary: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["evidence"] = json_safe(payload["evidence"])
        return payload


@dataclass
class EvidenceEdge:
    source_id: str
    target_id: str
    edge_type: str
    evidence: str = ""
    confidence: str = "medium"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class EvidenceGraph:
    generated_at: str
    nodes: list[EvidenceNode] = field(default_factory=list)
    edges: list[EvidenceEdge] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "nodes": [node.to_dict() for node in self.nodes],
            "edges": [edge.to_dict() for edge in self.edges],
        }

    def related_nodes(self, node_id: str) -> list[EvidenceNode]:
        related_ids = {
            edge.target_id for edge in self.edges if edge.source_id == node_id
        } | {
            edge.source_id for edge in self.edges if edge.target_id == node_id
        } | {node_id}
        return [node for node in self.nodes if node.node_id in related_ids]

    def evidence_chain(self, node_id: str, *, max_depth: int = 4) -> list[dict[str, Any]]:
        node_lookup = {node.node_id: node for node in self.nodes}
        chain: list[dict[str, Any]] = []
        seen = {node_id}
        frontier = [(node_id, 0)]
        while frontier:
            current, depth = frontier.pop(0)
            if depth >= max_depth:
                continue
            for edge in self.edges:
                if edge.source_id == current and edge.target_id not in seen:
                    seen.add(edge.target_id)
                    target = node_lookup.get(edge.target_id)
                    chain.append({"depth": depth + 1, "from": current, "edge_type": edge.edge_type, "to": edge.target_id, "label": target.label if target else "", "evidence": edge.evidence})
                    frontier.append((edge.target_id, depth + 1))
                elif edge.target_id == current and edge.source_id not in seen:
                    seen.add(edge.source_id)
                    source = node_lookup.get(edge.source_id)
                    chain.append({"depth": depth + 1, "from": edge.source_id, "edge_type": edge.edge_type, "to": current, "label": source.label if source else "", "evidence": edge.evidence})
                    frontier.append((edge.source_id, depth + 1))
        return chain


def export_graph_json(graph: EvidenceGraph | dict[str, Any], output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = graph.to_dict() if hasattr(graph, "to_dict") else graph
    output_path.write_text(json.dumps(json_safe(payload), indent=2, sort_keys=True), encoding="utf-8")
    return output_path


class EvidenceGraphBuilder:
    def build_from_scan_result(self, scan_result: ScanResult, *, monitor_events: list[dict[str, Any]] | None = None) -> EvidenceGraph:
        artifacts = dict(scan_result.collected_artifacts)
        artifacts["findings"] = [finding.to_dict() if hasattr(finding, "to_dict") else dict(finding) for finding in scan_result.findings]
        artifacts.setdefault("scan_id", scan_result.scan_id)
        artifacts.setdefault("timestamp", scan_result.timestamp)
        return self.build(artifacts, monitor_events=monitor_events)

    def build(self, artifacts: dict[str, Any], *, monitor_events: list[dict[str, Any]] | None = None) -> EvidenceGraph:
        nodes: dict[str, EvidenceNode] = {}
        edges: dict[tuple[str, str, str], EvidenceEdge] = {}

        def add_node(node: EvidenceNode) -> None:
            if node.node_type not in NODE_TYPES:
                return
            existing = nodes.get(node.node_id)
            if existing is None:
                nodes[node.node_id] = node
            else:
                existing.evidence.update(node.evidence)
                if node.summary and node.summary not in existing.summary:
                    existing.summary = "; ".join(part for part in [existing.summary, node.summary] if part)

        def add_edge(edge: EvidenceEdge) -> None:
            if edge.edge_type not in EDGE_TYPES or edge.source_id == edge.target_id:
                return
            key = (edge.source_id, edge.target_id, edge.edge_type)
            edges.setdefault(key, edge)

        findings = [self._as_dict(item) for item in artifacts.get("findings", [])]
        processes = [self._as_dict(item) for item in (artifacts.get("processes", {}) or {}).get("all", [])] if isinstance(artifacts.get("processes", {}), dict) else []
        ports = [self._as_dict(item) for item in (artifacts.get("ports", {}) or {}).get("listening", [])] if isinstance(artifacts.get("ports", {}), dict) else []
        active_connections = [self._as_dict(item) for item in (artifacts.get("ports", {}) or {}).get("active_connections", [])] if isinstance(artifacts.get("ports", {}), dict) else []
        launch_items = [self._as_dict(item) for item in artifacts.get("launch_snapshots", [])]
        users = [self._as_dict(item) for item in artifacts.get("users", [])]
        files = [self._as_dict(item) for item in artifacts.get("file_issues", [])]
        network_discovery = artifacts.get("network_discovery", {}) if isinstance(artifacts.get("network_discovery", {}), dict) else {}
        devices = [self._as_dict(item) for item in network_discovery.get("hosts", network_discovery.get("devices", []))]
        snapshots = [self._as_dict(item) for item in artifacts.get("packet_captures", [])]
        events = [self._as_dict(item) for item in (monitor_events or [])]
        timeline = artifacts.get("security_timeline", {}) if isinstance(artifacts.get("security_timeline", {}), dict) else {}
        events.extend(self._as_dict(item) for item in timeline.get("events", []))

        process_by_pid: dict[str, str] = {}
        process_by_path: dict[str, str] = {}
        for process in processes:
            pid = str(process.get("pid", ""))
            path = str(process.get("command_path", ""))
            label = str(process.get("process_name") or Path(path).name or pid)
            node_id = self._node_id("process", pid or path)
            add_node(EvidenceNode(node_id, "process", label, f"pid={pid} path={path}", process))
            if pid:
                process_by_pid[pid] = node_id
            if path:
                process_by_path[path] = node_id
            user = str(process.get("user", ""))
            if user:
                user_id = self._node_id("user", user)
                add_node(EvidenceNode(user_id, "user", user, "Process owner", {"username": user}))
                add_edge(EvidenceEdge(node_id, user_id, "owned_by", f"{label} runs as {user}", "high"))
            if path:
                file_id = self._node_id("file", path)
                add_node(EvidenceNode(file_id, "file", path, "Process executable", {"path": path, "signed_status": process.get("signed_status", "")}))
                add_edge(EvidenceEdge(node_id, file_id, "started", "Process executable path", "medium"))

        for user in users:
            username = str(user.get("username") or user.get("user") or user.get("name") or "")
            if username:
                add_node(EvidenceNode(self._node_id("user", username), "user", username, "Local user", user))

        for file_item in files:
            path = str(file_item.get("path", ""))
            if path:
                add_node(EvidenceNode(self._node_id("file", path), "file", path, str(file_item.get("issue_type", "File evidence")), file_item))

        for launch in launch_items:
            path = str(launch.get("path") or launch.get("label") or "")
            program = str(launch.get("program") or "")
            label = str(launch.get("label") or path)
            launch_id = self._node_id("launch_item", path or label)
            add_node(EvidenceNode(launch_id, "launch_item", label, f"{path} -> {program}", launch))
            if program:
                file_id = self._node_id("file", program)
                add_node(EvidenceNode(file_id, "file", program, "Launch item target binary", {"path": program}))
                add_edge(EvidenceEdge(launch_id, file_id, "started", "Launch item target", "medium"))
                if program in process_by_path:
                    add_edge(EvidenceEdge(launch_id, process_by_path[program], "started", "Launch item target matches running process", "high"))

        for port in [*ports, *active_connections]:
            endpoint = self._endpoint_label(port)
            if not endpoint:
                continue
            endpoint_id = self._node_id("network_endpoint", endpoint)
            add_node(EvidenceNode(endpoint_id, "network_endpoint", endpoint, str(port.get("state", "Network endpoint")), port))
            pid = str(port.get("pid", ""))
            if pid and pid in process_by_pid:
                add_edge(EvidenceEdge(process_by_pid[pid], endpoint_id, "connected_to", f"pid={pid} endpoint={endpoint}", "high"))

        for device in devices:
            key = str(device.get("ip_address") or device.get("mac_address") or device.get("hostname") or device.get("likely_hostname") or "")
            if not key:
                continue
            label = str(device.get("likely_hostname") or device.get("hostname") or key)
            add_node(EvidenceNode(self._node_id("device", key), "device", label, "Network device", device))

        for snapshot in snapshots:
            key = str(snapshot.get("capture_id") or snapshot.get("snapshot_id") or snapshot.get("pcap_path") or snapshot.get("snapshot_path") or "")
            if key:
                add_node(EvidenceNode(self._node_id("snapshot", key), "snapshot", key, "Evidence snapshot", snapshot))

        for event in events:
            key = str(event.get("event_id") or event.get("trace_id") or event.get("timestamp") or event.get("title") or "")
            if not key:
                continue
            event_id = self._node_id("event", key)
            add_node(EvidenceNode(event_id, "event", str(event.get("event_type") or event.get("title") or key), str(event.get("summary") or event.get("evidence") or ""), event))
            self._link_event(event_id, event, add_edge, process_by_pid, process_by_path, add_node)

        for finding in findings:
            finding_key = str(finding.get("id") or finding.get("title") or finding.get("evidence") or "")
            if not finding_key:
                continue
            finding_id = self._node_id("finding", finding_key)
            add_node(EvidenceNode(finding_id, "finding", str(finding.get("title") or finding_key), str(finding.get("description") or finding.get("evidence") or ""), finding))
            self._link_finding(finding_id, finding, add_edge, process_by_pid, process_by_path, add_node)

        graph = EvidenceGraph(generated_at=utc_now_iso(), nodes=sorted(nodes.values(), key=lambda item: (item.node_type, item.label, item.node_id)), edges=sorted(edges.values(), key=lambda item: (item.source_id, item.edge_type, item.target_id)))
        return graph

    def _link_finding(self, finding_id: str, finding: dict[str, Any], add_edge, process_by_pid: dict[str, str], process_by_path: dict[str, str], add_node) -> None:
        related_pid = str(finding.get("related_pid") or "")
        if related_pid and related_pid in process_by_pid:
            add_edge(EvidenceEdge(finding_id, process_by_pid[related_pid], "related_to", "Finding related_pid matched process.", "high"))
        related_path = str(finding.get("related_path") or "")
        if related_path:
            file_id = self._node_id("file", related_path)
            add_node(EvidenceNode(file_id, "file", related_path, "Finding related path", {"path": related_path}))
            add_edge(EvidenceEdge(finding_id, file_id, "related_to", "Finding related_path.", "high"))
            if related_path in process_by_path:
                add_edge(EvidenceEdge(finding_id, process_by_path[related_path], "related_to", "Finding related_path matched process.", "high"))
        related_user = str(finding.get("related_user") or "")
        if related_user:
            user_id = self._node_id("user", related_user)
            add_node(EvidenceNode(user_id, "user", related_user, "Finding related user", {"username": related_user}))
            add_edge(EvidenceEdge(finding_id, user_id, "related_to", "Finding related_user.", "medium"))
        endpoint = str(finding.get("related_network_endpoint") or "")
        if endpoint:
            endpoint_id = self._node_id("network_endpoint", endpoint)
            add_node(EvidenceNode(endpoint_id, "network_endpoint", endpoint, "Finding related endpoint", {"endpoint": endpoint}))
            add_edge(EvidenceEdge(finding_id, endpoint_id, "connected_to", "Finding related_network_endpoint.", "medium"))
        event_id = str(finding.get("event_id") or "")
        if event_id:
            add_edge(EvidenceEdge(finding_id, self._node_id("event", event_id), "observed_with", "Finding event_id.", "medium"))
        evidence_text = " ".join(str(finding.get(key, "")) for key in ("evidence", "description", "title"))
        for path, process_id in process_by_path.items():
            if path and path in evidence_text:
                add_edge(EvidenceEdge(finding_id, process_id, "related_to", "Finding evidence mentions process path.", "medium"))

    def _link_event(self, event_id: str, event: dict[str, Any], add_edge, process_by_pid: dict[str, str], process_by_path: dict[str, str], add_node) -> None:
        related_pid = str(event.get("related_pid") or event.get("pid") or "")
        if related_pid and related_pid in process_by_pid:
            add_edge(EvidenceEdge(event_id, process_by_pid[related_pid], "observed_with", "Event PID matched process.", "high"))
        related_path = str(event.get("related_path") or "")
        if related_path:
            file_id = self._node_id("file", related_path)
            add_node(EvidenceNode(file_id, "file", related_path, "Event related path", {"path": related_path}))
            add_edge(EvidenceEdge(event_id, file_id, "related_to", "Event related_path.", "medium"))
            if related_path in process_by_path:
                add_edge(EvidenceEdge(event_id, process_by_path[related_path], "observed_with", "Event related_path matched process.", "high"))
        related_user = str(event.get("related_user") or "")
        if related_user:
            user_id = self._node_id("user", related_user)
            add_node(EvidenceNode(user_id, "user", related_user, "Event related user", {"username": related_user}))
            add_edge(EvidenceEdge(event_id, user_id, "related_to", "Event related_user.", "medium"))
        endpoint = str(event.get("related_network_endpoint") or "")
        if endpoint:
            endpoint_id = self._node_id("network_endpoint", endpoint)
            add_node(EvidenceNode(endpoint_id, "network_endpoint", endpoint, "Event related endpoint", {"endpoint": endpoint}))
            add_edge(EvidenceEdge(event_id, endpoint_id, "connected_to", "Event related_network_endpoint.", "medium"))

    def _node_id(self, node_type: str, key: Any) -> str:
        safe = str(key).strip().replace("\n", " ")[:240]
        return f"{node_type}:{safe}"

    def _endpoint_label(self, payload: dict[str, Any]) -> str:
        if payload.get("remote_address"):
            return str(payload.get("remote_address"))
        if payload.get("local_address"):
            return str(payload.get("local_address"))
        if payload.get("host") and payload.get("port"):
            return f"{payload.get('host')}:{payload.get('port')}"
        if payload.get("port"):
            return f"{str(payload.get('protocol', 'tcp')).lower()}:{payload.get('port')}"
        return ""

    def _as_dict(self, value: Any) -> dict[str, Any]:
        if isinstance(value, dict):
            return value
        if hasattr(value, "to_dict"):
            return value.to_dict()
        if hasattr(value, "__dict__"):
            return dict(value.__dict__)
        return {"value": json_safe(value)}
