"""Sanitized multi-format definition health and source policy report."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from mac_audit_agent.professional_report import structured_payload_report

from .manager import ThreatIntelligenceManager


def diagnostics_payload(manager: ThreatIntelligenceManager) -> dict[str, Any]:
    status = manager.status()
    return {
        "schema_version": "1.0",
        "report_type": "msaa_threat_definition_health",
        "definition_health": {key: value for key, value in status.items() if key != "sources"},
        "sources": status.get("sources", []),
        "recent_history": manager.store.history(),
        "privacy": "Definition diagnostics exclude provider credentials, private keys, authorization tokens, and arbitrary endpoint event contents.",
    }


def export_diagnostics(manager: ThreatIntelligenceManager, destination: Path) -> Path:
    destination = Path(destination)
    payload = diagnostics_payload(manager)
    if destination.suffix.lower() == ".json":
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
        temporary.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
        return destination
    if destination.suffix.lower() not in {".html", ".docx", ".xlsx"}:
        raise ValueError("Definition diagnostics support .html, .docx, .xlsx, or .json")
    return structured_payload_report(
        destination, title="MSAA Threat Intelligence & Definition Health",
        payload=payload,
        qualification="Feed indicators are defensive intelligence, not proof of compromise. Blocking requires prevention-policy approval; source licensing and attribution obligations remain applicable.",
    )


__all__ = ["diagnostics_payload", "export_diagnostics"]
