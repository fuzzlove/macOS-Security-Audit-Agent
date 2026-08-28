from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mac_audit_agent.models import utc_now_iso
from mac_audit_agent.persistence_intelligence.models import PersistenceItem, PersistenceScanReport


RISK_ACCEPTANCE_PHRASE = "I AGREE"
INSECURE_BASELINE_DISCLAIMER = (
    "MSAA STRONGLY ADVISES AGAINST CREATING A TRUSTED BASELINE FROM THIS SYSTEM. "
    "The current evidence indicates serious findings, incomplete protection coverage, or failed security protections. "
    "A trusted baseline can cause insecure or malicious persistence to be treated as expected in future comparisons. "
    "Contact your local IT department or authorized security team before accepting this risk. "
    "By typing I AGREE, you accept full responsibility for baselining this insecure system and acknowledge that doing so "
    "may violate MSAA or organizational policies and may lead to disciplinary action, including termination, where applicable. "
    "MSAA does not recommend or approve this action."
)


def insecure_baseline_reasons(report: PersistenceScanReport, rootkit_result: Any = None) -> list[str]:
    reasons = []
    severe = [finding for finding in report.findings if str(finding.severity).upper() in {"CRITICAL", "HIGH"}]
    if severe:
        reasons.append(f"{len(severe)} critical/high persistence finding(s) remain unresolved")
    degraded = [row for row in report.coverage if str(row.get("coverage_status", "")).lower() in {"failed", "partial", "degraded", "unknown"}]
    if degraded:
        reasons.append("scanner coverage is not passing: " + ", ".join(str(row.get("scanner_id", "unknown")) for row in degraded))
    if report.errors:
        reasons.append(f"the persistence scan reported {len(report.errors)} error(s)")
    if int(report.posture_score) < 70:
        reasons.append(f"persistence posture score is {report.posture_score}/100")
    posture = getattr(rootkit_result, "posture", None)
    if posture is not None:
        failed = []
        for label, value in (
            ("SIP", posture.sip_status), ("Authenticated Root", posture.authenticated_root_status),
            ("Signed System Volume", posture.ssv_status), ("Gatekeeper", posture.gatekeeper_status),
            ("FileVault", posture.filevault_status), ("Secure Boot", posture.secure_boot_status),
        ):
            if str(value or "unknown").lower() not in {"enabled", "active", "enforced", "on", "full", "full security", "sealed", "verified"}:
                failed.append(f"{label}={value or 'unknown'}")
        if failed:
            reasons.append("platform protections are not verified passing: " + ", ".join(failed))
    return reasons


class PersistenceBaselineManager:
    def __init__(self, baseline_dir: Path | None = None) -> None:
        self.baseline_dir = baseline_dir or (Path.home() / "Library" / "Application Support" / "MacAuditAgent" / "persistence_baselines")
        try:
            self.baseline_dir.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            self.baseline_dir = Path.cwd() / ".mac_audit_agent" / "persistence_baselines"
            self.baseline_dir.mkdir(parents=True, exist_ok=True)

    def _path(self, name: str) -> Path:
        safe = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in name.strip()) or "default"
        return self.baseline_dir / f"{safe}.json"

    def create_baseline(
        self, name: str, items: list[PersistenceItem], *, risk_reasons: list[str] | None = None,
        acknowledgement: str = "", acknowledged_by: str = "",
    ) -> Path:
        reasons = list(risk_reasons or [])
        if reasons and acknowledgement != RISK_ACCEPTANCE_PHRASE:
            raise PermissionError("INSECURE_BASELINE_REFUSED: exact acknowledgement 'I AGREE' is required.")
        payload = {
            "name": name,
            "created_at": utc_now_iso(),
            "items": {item.item_id: {"fingerprint": item.fingerprint(), "item": item.to_dict()} for item in items},
            "risk_acceptance": {
                "required": bool(reasons), "accepted": bool(reasons), "reasons": reasons,
                "acknowledgement": acknowledgement if reasons else "not_required",
                "acknowledged_by": acknowledged_by if reasons else "",
                "disclaimer": INSECURE_BASELINE_DISCLAIMER if reasons else "",
            },
        }
        path = self._path(name)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        temporary.replace(path)
        return path

    def list_baselines(self) -> list[str]:
        return sorted(path.stem for path in self.baseline_dir.glob("*.json"))

    def delete_baseline(self, name: str) -> bool:
        path = self._path(name)
        if path.exists():
            path.unlink()
            return True
        return False

    def export_baseline(self, name: str) -> dict[str, Any]:
        return json.loads(self._path(name).read_text(encoding="utf-8"))

    def import_baseline(self, file: Path) -> Path:
        payload = json.loads(file.read_text(encoding="utf-8"))
        path = self._path(str(payload.get("name") or file.stem))
        path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        return path

    def compare_baseline(self, name: str, items: list[PersistenceItem]) -> dict[str, Any]:
        path = self._path(name)
        if not path.exists():
            return {
                "baseline": name,
                "status": "missing",
                "added": [],
                "removed": [],
                "modified": [],
                "hash_changed": [],
                "permission_changed": [],
                "owner_changed": [],
                "signature_changed": [],
                "loaded_state_changed": [],
                "disabled_state_changed": [],
            }
        baseline = json.loads(path.read_text(encoding="utf-8"))
        previous = baseline.get("items", {})
        current = {item.item_id: item for item in items}
        added = [item.to_dict() for item_id, item in current.items() if item_id not in previous]
        removed = [payload.get("item", {}) for item_id, payload in previous.items() if item_id not in current]
        modified: list[dict[str, Any]] = []
        hash_changed: list[dict[str, Any]] = []
        permission_changed: list[dict[str, Any]] = []
        owner_changed: list[dict[str, Any]] = []
        signature_changed: list[dict[str, Any]] = []
        loaded_state_changed: list[dict[str, Any]] = []
        disabled_state_changed: list[dict[str, Any]] = []
        for item_id, item in current.items():
            old_payload = previous.get(item_id)
            if not old_payload:
                item.baseline_status = "new"
                continue
            old_item = old_payload.get("item", {})
            item.first_seen = str(old_item.get("first_seen") or item.first_seen)
            item.last_seen = utc_now_iso()
            if old_payload.get("fingerprint") != item.fingerprint():
                item.baseline_status = "changed"
                modified.append({"before": old_item, "after": item.to_dict()})
            else:
                item.baseline_status = "known"
            if old_item.get("target_hash_sha256") != item.target_hash_sha256:
                hash_changed.append(item.to_dict())
            if old_item.get("permissions") != item.permissions:
                permission_changed.append(item.to_dict())
            if old_item.get("owner") != item.owner:
                owner_changed.append(item.to_dict())
            if old_item.get("signed_status") != item.signed_status:
                signature_changed.append(item.to_dict())
            if bool(old_item.get("loaded", False)) != bool(item.loaded):
                loaded_state_changed.append(item.to_dict())
            if bool(old_item.get("disabled", False)) != bool(item.disabled):
                disabled_state_changed.append(item.to_dict())
        return {
            "baseline": name,
            "status": "compared",
            "added": added,
            "removed": removed,
            "modified": modified,
            "hash_changed": hash_changed,
            "permission_changed": permission_changed,
            "owner_changed": owner_changed,
            "signature_changed": signature_changed,
            "loaded_state_changed": loaded_state_changed,
            "disabled_state_changed": disabled_state_changed,
        }
