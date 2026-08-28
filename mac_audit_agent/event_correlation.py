from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from typing import Any


def _as_mapping(event: Any) -> dict[str, Any]:
    if isinstance(event, dict):
        return dict(event)
    if is_dataclass(event):
        return asdict(event)
    if hasattr(event, "to_dict"):
        try:
            payload = event.to_dict()
            if isinstance(payload, dict):
                return dict(payload)
        except Exception:
            pass
    return {}


def _json_mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return dict(value)
    if not value:
        return {}
    try:
        parsed = json.loads(str(value))
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    return dict(parsed) if isinstance(parsed, dict) else {}


def correlation_id_for_event(event: Any) -> str:
    payload = _as_mapping(event)
    for key in ("correlation_id", "source_trace"):
        value = str(payload.get(key) or "").strip()
        if value:
            return value
    for container_key in ("provenance_json", "metadata_json", "provenance", "metadata"):
        container = _json_mapping(payload.get(container_key))
        value = str(container.get("correlation_id") or "").strip()
        if value:
            return value
    try:
        from mac_audit_agent.rules import correlation_id_for

        return correlation_id_for(
            payload.get("event_type", ""),
            payload.get("source", ""),
            payload.get("process_name", ""),
            payload.get("trigger_rule_id", ""),
            payload.get("duplicate_group_key", ""),
            payload.get("evidence", payload.get("summary", "")),
            timestamp=str(payload.get("timestamp") or ""),
        )
    except Exception:
        seed = "|".join(
            str(payload.get(key, ""))
            for key in ("event_type", "source", "process_name", "timestamp", "event_id", "evidence")
        )
        if not seed.strip("|"):
            return ""
        import hashlib

        return f"corr-{hashlib.sha256(seed.encode('utf-8')).hexdigest()[:16]}"
