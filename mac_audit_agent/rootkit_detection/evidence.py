from __future__ import annotations

import hashlib
import json
from pathlib import Path

from mac_audit_agent.models import utc_now_iso
from mac_audit_agent.rootkit_detection.models import RootkitScanResult


def export_evidence_package(result: RootkitScanResult, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "package_type": "rootkit_advanced_persistence_evidence",
        "created_at": utc_now_iso(),
        "privacy_review_required": True,
        "destructive_actions_performed": False,
        "scan_result": result.to_dict(),
        "limitations": result.limitations,
    }
    package_path = output_dir / f"rootkit_suspect_evidence_{result.scan_id}.json"
    package_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    digest = hashlib.sha256(package_path.read_bytes()).hexdigest()
    manifest_path = output_dir / f"rootkit_suspect_evidence_{result.scan_id}.manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "created_at": utc_now_iso(),
                "package_path": str(package_path),
                "sha256": digest,
                "privacy_review_required": True,
                "chain_of_custody_note": "Generated locally by MSAA. Review before sharing.",
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return manifest_path
