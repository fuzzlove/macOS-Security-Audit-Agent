from __future__ import annotations

from typing import Any


DB_INDEXES = [
    ("idx_background_monitor_events_timestamp", "background_monitor_events", "timestamp"),
    ("idx_background_monitor_events_type", "background_monitor_events", "event_type"),
    ("idx_background_monitor_events_severity", "background_monitor_events", "severity"),
    ("idx_event_alert_traces_event_id", "event_alert_traces", "event_id"),
    ("idx_event_alert_traces_created_at", "event_alert_traces", "created_at"),
    ("idx_findings_finding_id", "findings", "finding_id"),
    ("idx_findings_severity", "findings", "severity"),
    ("idx_findings_category", "findings", "category"),
]


def ensure_performance_indexes(db: Any) -> list[str]:
    created = []
    for name, table, columns in DB_INDEXES:
        try:
            db.conn.execute(f"CREATE INDEX IF NOT EXISTS {name} ON {table} ({columns})")
            created.append(name)
        except Exception:
            continue
    db.conn.commit()
    return created


def database_diagnostics(db: Any) -> dict[str, Any]:
    path = getattr(db, "path", None)
    size = path.stat().st_size if path and path.exists() else 0
    return {"path": str(path or ""), "size_bytes": size, "indexes": ensure_performance_indexes(db)}
