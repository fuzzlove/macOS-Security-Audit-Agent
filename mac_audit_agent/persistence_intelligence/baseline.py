from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mac_audit_agent.models import utc_now_iso
from mac_audit_agent.persistence_intelligence.models import PersistenceItem


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

    def create_baseline(self, name: str, items: list[PersistenceItem]) -> Path:
        payload = {
            "name": name,
            "created_at": utc_now_iso(),
            "items": {item.item_id: {"fingerprint": item.fingerprint(), "item": item.to_dict()} for item in items},
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
