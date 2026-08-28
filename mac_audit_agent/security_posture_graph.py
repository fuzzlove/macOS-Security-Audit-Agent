"""Evidence-bound temporal and risk analysis over MSAA's EvidenceGraph.

Relationships are created from explicit identifiers and evidence references.
Text similarity, severity, or ATT&CK mappings alone never create an attack path.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping
from uuid import uuid4

from mac_audit_agent.evidence_graph import EvidenceEdge, EvidenceGraph, EvidenceNode

ENTITY_TYPES = {"device", "user", "process", "application", "file", "network_endpoint", "vulnerability", "event"}
RELATIONSHIP_TYPES = {"affected_by", "connected_to", "created", "executed", "installed_by", "opened", "observed_with", "precedes", "related_to"}
CONFIDENCE = {"low": 0.35, "medium": 0.6, "high": 0.85}
SEVERITY = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SENSITIVE_KEYS = {"password", "password_value", "token", "access_token", "secret", "private_key", "credential", "cookie", "authorization"}


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _hash(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _parse_time(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


@dataclass(frozen=True)
class GraphRelationship:
    relationship_id: str
    source_entity: str
    target_entity: str
    relationship_type: str
    confidence: str
    timestamp: str
    evidence_reference: tuple[str, ...]
    explanation: str
    observed: bool

    def to_dict(self) -> dict[str, Any]: return asdict(self)


@dataclass(frozen=True)
class GraphEvent:
    event_id: str
    timestamp: str
    related_entities: tuple[str, ...]
    severity: str
    mitre_mapping: tuple[str, ...]
    evidence_reference: tuple[str, ...]
    source_module: str
    event_type: str

    def to_dict(self) -> dict[str, Any]: return asdict(self)


@dataclass(frozen=True)
class RiskPath:
    path_id: str
    event_ids: tuple[str, ...]
    entity_ids: tuple[str, ...]
    start_time: str
    end_time: str
    confidence: str
    risk_level: str
    mitre_mapping: tuple[str, ...]
    evidence_reference: tuple[str, ...]
    observed_facts: tuple[str, ...]
    analyst_interpretation: str
    limitations: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]: return asdict(self)


@dataclass(frozen=True)
class SecurityPostureGraph:
    graph_id: str
    generated_at: str
    evidence_graph: EvidenceGraph
    relationships: tuple[GraphRelationship, ...]
    events: tuple[GraphEvent, ...]
    risk_paths: tuple[RiskPath, ...]
    posture_score_before: int
    posture_score_after: int
    score_explanation: tuple[str, ...]
    integrity_hash: str = ""
    qualification: str = "Observed relationships and analyst interpretations are separate. A risk path is not proof of compromise or attacker attribution."

    def to_dict(self) -> dict[str, Any]:
        return {
            **asdict(self), "evidence_graph": self.evidence_graph.to_dict(),
            "relationships": [item.to_dict() for item in self.relationships],
            "events": [item.to_dict() for item in self.events], "risk_paths": [item.to_dict() for item in self.risk_paths],
        }


class SecurityPostureGraphEngine:
    def __init__(self, *, temporal_window_seconds: int = 1800) -> None:
        if not 60 <= temporal_window_seconds <= 86400: raise ValueError("Temporal correlation window must be between 60 seconds and 24 hours.")
        self.temporal_window_seconds = temporal_window_seconds

    def build(self, raw_events: Iterable[Mapping[str, Any]], *, context: Mapping[str, Any] | None = None) -> SecurityPostureGraph:
        context = context or {}
        nodes: dict[str, EvidenceNode] = {}
        edges: dict[tuple[str, str, str], EvidenceEdge] = {}
        relationships: list[GraphRelationship] = []
        events: list[GraphEvent] = []
        event_entities: dict[str, set[str]] = {}
        raw_lookup: dict[str, dict[str, Any]] = {}

        for raw in raw_events:
            normalized = self._normalize_event(raw)
            if normalized is None: continue
            event, entities, explicit_relationships = normalized
            events.append(event); raw_lookup[event.event_id] = dict(raw)
            event_node_id = f"event:{event.event_id}"
            nodes[event_node_id] = EvidenceNode(event_node_id, "event", event.event_type, f"{event.source_module} · {event.severity}", {"timestamp": event.timestamp, "severity": event.severity, "source_module": event.source_module, "mitre_mapping": list(event.mitre_mapping), "evidence_reference": list(event.evidence_reference)})
            event_entities[event.event_id] = set()
            for entity in entities:
                entity_id = entity["entity_id"]
                node_id = f"{entity['entity_type']}:{entity_id}"
                nodes.setdefault(node_id, EvidenceNode(node_id, entity["entity_type"], entity["name"], "Observed security entity", entity["attributes"]))
                event_entities[event.event_id].add(node_id)
                relationship = self._relationship(event_node_id, node_id, "observed_with", "high", event.timestamp, event.evidence_reference, "The event explicitly identified this entity.", True)
                self._add_relationship(relationship, relationships, edges)
            for item in explicit_relationships:
                source = self._resolve_ref(item.get("source_entity"), nodes)
                target = self._resolve_ref(item.get("target_entity"), nodes)
                relation_type = str(item.get("relationship_type", ""))
                refs = self._refs(item.get("evidence_reference", []))
                confidence = str(item.get("confidence", "medium")).lower()
                if source and target and source != target and relation_type in RELATIONSHIP_TYPES and refs and confidence in CONFIDENCE:
                    relationship = self._relationship(source, target, relation_type, confidence, event.timestamp, refs, str(item.get("explanation") or "The source event explicitly supplied this relationship."), True)
                    self._add_relationship(relationship, relationships, edges)

        ordered = sorted(events, key=lambda item: (_parse_time(item.timestamp) or datetime.min.replace(tzinfo=timezone.utc), item.event_id))
        for index, earlier in enumerate(ordered):
            for later in ordered[index + 1:]:
                delta = self._delta(earlier.timestamp, later.timestamp)
                if delta is None or delta > self.temporal_window_seconds: break
                shared = event_entities.get(earlier.event_id, set()) & event_entities.get(later.event_id, set())
                if not shared: continue
                confidence = "high" if earlier.source_module != later.source_module and delta <= 900 else "medium"
                refs = tuple(sorted(set(earlier.evidence_reference) | set(later.evidence_reference)))
                relation = self._relationship(f"event:{earlier.event_id}", f"event:{later.event_id}", "precedes", confidence, later.timestamp, refs, f"Events share explicit entity identifiers and occurred {delta} seconds apart.", False)
                self._add_relationship(relation, relationships, edges)

        paths = self._risk_paths(ordered, event_entities, relationships)
        before = max(0, min(100, int(context.get("security_score", 100))))
        penalty, explanation = self._score(paths, events, context)
        graph = EvidenceGraph(str(context.get("generated_at") or (ordered[-1].timestamp if ordered else datetime.now(timezone.utc).isoformat())), sorted(nodes.values(), key=lambda item: item.node_id), sorted(edges.values(), key=lambda item: (item.source_id, item.edge_type, item.target_id)))
        base = SecurityPostureGraph(f"posture-graph-{uuid4().hex}", graph.generated_at, graph, tuple(relationships), tuple(ordered), tuple(paths), before, max(0, before - penalty), tuple(explanation))
        digest = _hash(base.to_dict())
        return SecurityPostureGraph(**{**base.to_dict(), "evidence_graph": graph, "relationships": tuple(relationships), "events": tuple(ordered), "risk_paths": tuple(paths), "score_explanation": tuple(explanation), "integrity_hash": digest})

    def related_to(self, graph: SecurityPostureGraph, node_id: str) -> dict[str, Any]:
        nodes = graph.evidence_graph.related_nodes(node_id)
        relations = [item.to_dict() for item in graph.relationships if node_id in {item.source_entity, item.target_entity}]
        return {"query": "what_connects_to_node", "node_id": node_id, "nodes": [item.to_dict() for item in nodes], "relationships": relations}

    def before_event(self, graph: SecurityPostureGraph, event_id: str, *, limit: int = 20) -> list[dict[str, Any]]:
        target = next((item for item in graph.events if item.event_id == event_id), None)
        if not target: return []
        target_time = _parse_time(target.timestamp)
        return [item.to_dict() for item in graph.events if target_time and _parse_time(item.timestamp) and _parse_time(item.timestamp) < target_time][-max(1, min(limit, 100)):]

    def changed_recently(self, graph: SecurityPostureGraph, *, since: str) -> list[dict[str, Any]]:
        boundary = _parse_time(since)
        return [item.to_dict() for item in graph.events if boundary and _parse_time(item.timestamp) and _parse_time(item.timestamp) >= boundary]

    def dashboard(self, graph: SecurityPostureGraph) -> dict[str, Any]:
        return {"category": "Security Posture Graph", "security_graph": graph.evidence_graph.to_dict(), "attack_paths": [item.to_dict() for item in graph.risk_paths], "risk_relationships": [item.to_dict() for item in graph.relationships], "timeline": [item.to_dict() for item in graph.events], "affected_assets": [item.to_dict() for item in graph.evidence_graph.nodes if item.node_type in {"device", "application", "file", "user"}], "posture_score_before": graph.posture_score_before, "posture_score_after": graph.posture_score_after, "actions": ["investigate_node", "view_evidence", "expand_relationship", "generate_incident_report", "export_graph"]}

    def analyst_context(self, graph: SecurityPostureGraph, path_id: str) -> dict[str, Any]:
        path = next((item for item in graph.risk_paths if item.path_id == path_id), None)
        if not path: return {"observed_facts": [], "interpretation": "No matching evidence-backed path exists.", "confidence": "none", "guardrail": graph.qualification}
        return {"observed_facts": list(path.observed_facts), "evidence_reference": list(path.evidence_reference), "interpretation": path.analyst_interpretation, "confidence": path.confidence, "uncertainty": list(path.limitations), "guardrail": "Do not claim compromise, attribution, or causation from graph proximity alone."}

    def incident_context(self, graph: SecurityPostureGraph, path_id: str) -> dict[str, Any]:
        path = next((item for item in graph.risk_paths if item.path_id == path_id), None)
        eligible = bool(path and path.confidence == "high" and path.risk_level in {"high", "critical"})
        return {"eligible": eligible, "automatic_action": False, "authorization_required": True, "evidence_reference": list(path.evidence_reference) if path else [], "recommended_action": "preserve_graph_and_request_incident_creation" if eligible else "continue_analyst_review"}

    @staticmethod
    def verify_integrity(graph: SecurityPostureGraph) -> bool:
        payload = graph.to_dict(); expected = str(payload.pop("integrity_hash", "")); payload["integrity_hash"] = ""
        return bool(expected) and _hash(payload) == expected

    def _normalize_event(self, raw: Mapping[str, Any]) -> tuple[GraphEvent, list[dict[str, Any]], list[dict[str, Any]]] | None:
        event_id = str(raw.get("event_id", "")).strip(); timestamp = str(raw.get("timestamp", "")).strip()
        source = str(raw.get("source_module", raw.get("source", ""))).strip(); refs = self._refs(raw.get("evidence_reference", raw.get("evidence", [])))
        if not event_id or not source or not refs or _parse_time(timestamp) is None: return None
        severity = str(raw.get("severity", "info")).lower(); severity = severity if severity in SEVERITY else "info"
        mitre = raw.get("mitre_mapping", raw.get("mitre_attack", [])); mitre = [mitre] if isinstance(mitre, str) else mitre
        entities: list[dict[str, Any]] = []
        for item in raw.get("entities", []):
            if not isinstance(item, Mapping): continue
            entity_type = str(item.get("entity_type", "")); identity = str(item.get("entity_id", item.get("name", ""))).strip()
            if entity_type not in ENTITY_TYPES - {"event"} or not identity: continue
            attributes = self._sanitize(item.get("attributes", {}))
            entities.append({"entity_type": entity_type, "entity_id": identity, "name": str(item.get("name", identity)), "attributes": attributes})
        event = GraphEvent(event_id, timestamp, tuple(f"{item['entity_type']}:{item['entity_id']}" for item in entities), severity, tuple(str(value).split()[0] for value in mitre if value), refs, source, str(raw.get("event_type", "security_event")))
        relations = [dict(item) for item in raw.get("relationships", []) if isinstance(item, Mapping)]
        return event, entities, relations

    @staticmethod
    def _sanitize(attributes: Any) -> dict[str, Any]:
        if not isinstance(attributes, Mapping): return {}
        return {str(key): value for key, value in attributes.items() if str(key).lower() not in SENSITIVE_KEYS and not any(term in str(key).lower() for term in ("password", "secret", "private_key", "token"))}

    @staticmethod
    def _refs(value: Any) -> tuple[str, ...]:
        if isinstance(value, str): value = [value]
        return tuple(sorted({str(item) for item in (value or []) if str(item).strip()}))

    @staticmethod
    def _resolve_ref(value: Any, nodes: Mapping[str, EvidenceNode]) -> str:
        text = str(value or "")
        if text in nodes: return text
        matches = [key for key in nodes if key.endswith(f":{text}")]
        return matches[0] if len(matches) == 1 else ""

    def _relationship(self, source: str, target: str, kind: str, confidence: str, timestamp: str, refs: tuple[str, ...], explanation: str, observed: bool) -> GraphRelationship:
        identifier = "relationship-" + hashlib.sha256(f"{source}|{kind}|{target}|{timestamp}".encode()).hexdigest()[:24]
        return GraphRelationship(identifier, source, target, kind, confidence, timestamp, refs, explanation, observed)

    @staticmethod
    def _add_relationship(item: GraphRelationship, relationships: list[GraphRelationship], edges: dict[tuple[str, str, str], EvidenceEdge]) -> None:
        key = (item.source_entity, item.target_entity, item.relationship_type)
        if key in edges: return
        relationships.append(item); edges[key] = EvidenceEdge(item.source_entity, item.target_entity, item.relationship_type if item.relationship_type in {"connected_to", "created", "observed_with", "related_to"} else "related_to", item.explanation + " Evidence: " + ", ".join(item.evidence_reference), item.confidence)

    @staticmethod
    def _delta(first: str, second: str) -> int | None:
        a, b = _parse_time(first), _parse_time(second)
        return max(0, round((b - a).total_seconds())) if a and b else None

    def _risk_paths(self, events: list[GraphEvent], entities: dict[str, set[str]], relationships: list[GraphRelationship]) -> list[RiskPath]:
        temporal = {(item.source_entity.removeprefix("event:"), item.target_entity.removeprefix("event:")): item for item in relationships if item.relationship_type == "precedes"}
        paths: list[RiskPath] = []
        for start in range(len(events)):
            chain = [events[start]]
            for candidate in events[start + 1:]:
                if (chain[-1].event_id, candidate.event_id) in temporal:
                    chain.append(candidate)
                if len(chain) >= 5: break
            sources = {item.source_module for item in chain}
            if len(chain) < 3 or len(sources) < 2: continue
            confidence = "high" if all(temporal[(chain[i].event_id, chain[i + 1].event_id)].confidence == "high" for i in range(len(chain) - 1)) else "medium"
            refs = tuple(sorted({ref for item in chain for ref in item.evidence_reference}))
            entity_ids = tuple(sorted({entity for item in chain for entity in entities.get(item.event_id, set())}))
            techniques = tuple(sorted({technique for item in chain for technique in item.mitre_mapping}))
            max_severity = max(SEVERITY[item.severity] for item in chain); risk = "critical" if max_severity == 4 and confidence == "high" else "high" if max_severity >= 3 else "medium"
            facts = tuple(f"{item.timestamp}: {item.event_type} from {item.source_module} ({item.severity})" for item in chain)
            paths.append(RiskPath(f"risk-path-{uuid4().hex}", tuple(item.event_id for item in chain), entity_ids, chain[0].timestamp, chain[-1].timestamp, confidence, risk, techniques, refs, facts, "Multiple evidence-backed events share explicit entities within the configured temporal window and may warrant investigation.", ("Temporal proximity and shared entities do not prove causation.", "The graph does not identify an attacker or establish compromise.")))
        unique: dict[tuple[str, ...], RiskPath] = {item.event_ids: item for item in paths}
        return list(unique.values())

    @staticmethod
    def _score(paths: list[RiskPath], events: list[GraphEvent], context: Mapping[str, Any]) -> tuple[int, list[str]]:
        if not paths: return 0, ["No qualified multi-event risk path was produced; graph correlation did not change the posture score."]
        penalty = 0; reasons = []
        for path in paths:
            path_penalty = 8 + 2 * max(0, len(path.event_ids) - 3) + (5 if path.confidence == "high" else 0) + (5 if path.risk_level == "critical" else 2 if path.risk_level == "high" else 0)
            penalty += min(path_penalty, 20); reasons.append(f"{path.path_id}: -{min(path_penalty, 20)} for {len(path.event_ids)} connected events, {path.confidence} confidence, {path.risk_level} contextual risk.")
        privileged = bool(context.get("privileged_user_involved", False)); intel = bool(context.get("threat_intelligence_match", False))
        context_refs = SecurityPostureGraphEngine._refs(context.get("evidence_reference", []))
        if (privileged or intel) and not context_refs: reasons.append("Privilege or threat-intelligence context was ignored because it lacked evidence references.")
        else:
            if privileged: penalty += 4; reasons.append("-4: evidence-backed privileged-user context.")
            if intel: penalty += 6; reasons.append("-6: evidence-backed threat-intelligence match.")
        return min(penalty, 45), reasons


class SecurityPostureGraphRepository:
    def __init__(self, database: sqlite3.Connection | Path | str) -> None:
        self._owns = not isinstance(database, sqlite3.Connection); self.conn = sqlite3.connect(str(database)) if self._owns else database; self.conn.row_factory = sqlite3.Row
        self.conn.executescript("""
        CREATE TABLE IF NOT EXISTS graph_entities (entity_id TEXT PRIMARY KEY, entity_type TEXT NOT NULL, name TEXT NOT NULL, attributes TEXT NOT NULL, created_timestamp TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS graph_relationships (relationship_id TEXT PRIMARY KEY, source_entity TEXT NOT NULL, target_entity TEXT NOT NULL, relationship_type TEXT NOT NULL, confidence TEXT NOT NULL, timestamp TEXT NOT NULL, evidence_json TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS graph_events (event_id TEXT PRIMARY KEY, related_entities TEXT NOT NULL, severity TEXT NOT NULL, mitre_mapping TEXT NOT NULL, evidence_reference TEXT NOT NULL, payload_json TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS posture_graphs (graph_id TEXT PRIMARY KEY, generated_at TEXT NOT NULL, integrity_hash TEXT NOT NULL, payload_json TEXT NOT NULL);
        """); self.conn.commit()

    def close(self) -> None:
        if self._owns: self.conn.close()

    def save(self, graph: SecurityPostureGraph) -> None:
        if not SecurityPostureGraphEngine.verify_integrity(graph): raise ValueError("Refusing to store a graph with invalid integrity metadata.")
        with self.conn:
            for node in graph.evidence_graph.nodes:
                self.conn.execute("INSERT OR REPLACE INTO graph_entities VALUES (?,?,?,?,?)", (node.node_id, node.node_type, node.label, _canonical(node.evidence), graph.generated_at))
            for item in graph.relationships:
                self.conn.execute("INSERT OR REPLACE INTO graph_relationships VALUES (?,?,?,?,?,?,?)", (item.relationship_id, item.source_entity, item.target_entity, item.relationship_type, item.confidence, item.timestamp, _canonical(item.evidence_reference)))
            for item in graph.events:
                self.conn.execute("INSERT OR REPLACE INTO graph_events VALUES (?,?,?,?,?,?)", (item.event_id, _canonical(item.related_entities), item.severity, _canonical(item.mitre_mapping), _canonical(item.evidence_reference), _canonical(item.to_dict())))
            self.conn.execute("INSERT INTO posture_graphs VALUES (?,?,?,?)", (graph.graph_id, graph.generated_at, graph.integrity_hash, _canonical(graph.to_dict())))

    def latest_payload(self) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT payload_json FROM posture_graphs ORDER BY generated_at DESC LIMIT 1").fetchone()
        if not row: return None
        payload = json.loads(row["payload_json"]); expected = payload.get("integrity_hash", ""); candidate = dict(payload); candidate["integrity_hash"] = ""
        if not expected or _hash(candidate) != expected: raise ValueError("Security posture graph integrity verification failed.")
        return payload


__all__ = ["GraphEvent", "GraphRelationship", "RiskPath", "SecurityPostureGraph", "SecurityPostureGraphEngine", "SecurityPostureGraphRepository"]
