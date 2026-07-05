from __future__ import annotations

import html
import json
from pathlib import Path

from mac_audit_agent.models import utc_now_iso
from mac_audit_agent.persistence_intelligence.models import PersistenceItem
from mac_audit_agent.ui.risk_colors import risk_badge_html


def build_timeline(items: list[PersistenceItem], baseline_comparison: dict | None = None) -> list[dict]:
    events: list[dict] = []
    for item in items:
        status = item.baseline_status if item.baseline_status != "unknown" else "observed"
        events.append({
            "timestamp": item.last_seen or utc_now_iso(),
            "event": status,
            "severity": item.risk_level,
            "mechanism": item.mechanism,
            "item_id": item.item_id,
            "label": item.label or item.name,
            "mitre": item.mitre_techniques,
        })
    if baseline_comparison:
        for key in ["added", "removed", "modified", "hash_changed", "signature_changed", "permission_changed", "owner_changed"]:
            for entry in baseline_comparison.get(key, []) or []:
                item = entry.get("after", entry) if isinstance(entry, dict) else {}
                events.append({
                    "timestamp": utc_now_iso(),
                    "event": key,
                    "severity": item.get("risk_level", "INFO") if isinstance(item, dict) else "INFO",
                    "mechanism": item.get("mechanism", "") if isinstance(item, dict) else "",
                    "item_id": item.get("item_id", "") if isinstance(item, dict) else "",
                    "label": item.get("label", "") if isinstance(item, dict) else "",
                    "mitre": item.get("mitre_techniques", []) if isinstance(item, dict) else [],
                })
    return sorted(events, key=lambda item: item.get("timestamp", ""))


def export_timeline(events: list[dict], path: Path, fmt: str = "json") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "html":
        rows = "\n".join(
            f"<tr><td>{html.escape(str(e.get('timestamp', '')))}</td><td>{html.escape(str(e.get('event', '')))}</td><td>{risk_badge_html(e.get('severity', 'unknown'))}</td><td>{html.escape(str(e.get('mechanism', '')))}</td><td>{html.escape(str(e.get('label', '')))}</td></tr>"
            for e in events
        )
        path.write_text(f"<html><body><h1>Persistence Timeline</h1><table><tr><th>Time</th><th>Event</th><th>Severity</th><th>Mechanism</th><th>Label</th></tr>{rows}</table></body></html>", encoding="utf-8")
    elif fmt in {"md", "markdown"}:
        lines = ["# Persistence Timeline", "", "| Time | Event | Severity | Mechanism | Label |", "|---|---|---|---|---|"]
        lines.extend(f"| {e.get('timestamp','')} | {e.get('event','')} | {e.get('severity','')} | {e.get('mechanism','')} | {e.get('label','')} |" for e in events)
        path.write_text("\n".join(lines), encoding="utf-8")
    else:
        path.write_text(json.dumps(events, indent=2, sort_keys=True), encoding="utf-8")
    return path
