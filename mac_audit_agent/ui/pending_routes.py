from __future__ import annotations

import json
from typing import Any

from mac_audit_agent.models import utc_now_iso
from mac_audit_agent.ui.routes import Route


def ensure_pending_routes_schema(db: Any) -> None:
    db.conn.execute(
        """
        CREATE TABLE IF NOT EXISTS pending_ui_routes (
            route_id TEXT PRIMARY KEY,
            view TEXT NOT NULL,
            params_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            source_action_id TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'pending',
            consumed_at TEXT NOT NULL DEFAULT '',
            error TEXT NOT NULL DEFAULT ''
        )
        """
    )
    db.conn.commit()


def enqueue_pending_route(db: Any, route: Route) -> Route:
    ensure_pending_routes_schema(db)
    db.conn.execute(
        """
        INSERT OR REPLACE INTO pending_ui_routes
        (route_id, view, params_json, created_at, source_action_id, status, consumed_at, error)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (route.route_id, route.view, json.dumps(route.params, sort_keys=True), route.created_at, route.source_action_id, route.status, "", route.error),
    )
    db.conn.commit()
    return route


def get_pending_routes(db: Any) -> list[Route]:
    ensure_pending_routes_schema(db)
    rows = db.conn.execute("SELECT * FROM pending_ui_routes WHERE status = 'pending' ORDER BY created_at ASC").fetchall()
    routes: list[Route] = []
    for row in rows:
        try:
            params = json.loads(str(row["params_json"] or "{}"))
        except json.JSONDecodeError:
            params = {}
        routes.append(
            Route(
                route_id=str(row["route_id"]),
                view=str(row["view"]),
                params=params if isinstance(params, dict) else {},
                created_at=str(row["created_at"]),
                source_action_id=str(row["source_action_id"] or ""),
                status=str(row["status"] or "pending"),
                error=str(row["error"] or ""),
            )
        )
    return routes


def consume_pending_route(db: Any, route_id: str) -> None:
    ensure_pending_routes_schema(db)
    db.conn.execute("UPDATE pending_ui_routes SET status = 'consumed', consumed_at = ? WHERE route_id = ?", (utc_now_iso(), route_id))
    db.conn.commit()


def mark_route_failed(db: Any, route_id: str, reason: str) -> None:
    ensure_pending_routes_schema(db)
    db.conn.execute("UPDATE pending_ui_routes SET status = 'failed', error = ? WHERE route_id = ?", (reason, route_id))
    db.conn.commit()
