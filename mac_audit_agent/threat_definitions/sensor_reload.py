"""Controlled definition reload requests and sensor load acknowledgements."""

from __future__ import annotations

import fcntl
import json
import os
import time
from pathlib import Path
from typing import Any

from .models import utc_now
from .store import DefinitionStore


class DefinitionSensorReloadCoordinator:
    def __init__(self, store: DefinitionStore) -> None:
        self.store = store
        self.request_path = self.store.metadata_dir / "sensor-reload-request.json"
        self.receipt_path = self.store.metadata_dir / "sensor-load-receipts.json"

    def validate_and_request(self, release_path: Path) -> bool:
        """Prove the activated data is loadable and publish a daemon reload request."""
        started = time.monotonic()
        try:
            manifest = self.store.verify_bundle(release_path)
            release_id = str(manifest["bundle_version"])
            from mac_audit_agent.anti_ransomware.definition_database import (
                ActiveMacOSMalwareDatabase,
            )
            from mac_audit_agent.anti_ransomware.yara_backend import YaraBackend

            snapshot = ActiveMacOSMalwareDatabase(store=self.store).load()
            if snapshot.version != release_id:
                return False
            if snapshot.yara_sources:
                backend = YaraBackend()
                compiled = backend.compile(snapshot.yara_sources)
                compiled.match(data=b"MSAA harmless post-activation load fixture", timeout=2)
            duration = time.monotonic() - started
            request = {
                "schema_version": 1,
                "requested_at": utc_now().isoformat(),
                "release_id": release_id,
                "manifest_sha256": snapshot.manifest_sha256,
            }
            self.store._atomic_json(self.request_path, request)
            self.acknowledge(
                "definition_loader_validation", release_id,
                loaded_yara_rules=int(snapshot.counts.get("YARA_RULE", len(snapshot.yara_sources))),
                loaded_hash_entries=snapshot.hash_backend.indicator_count,
                load_duration=duration,
                status="ACCEPTED",
            )
            return True
        except Exception:  # noqa: BLE001 - any load failure must force atomic rollback
            return False

    def acknowledge(
        self,
        sensor_id: str,
        release_id: str,
        *,
        loaded_yara_rules: int,
        loaded_hash_entries: int,
        load_duration: float,
        status: str,
    ) -> None:
        self.store.metadata_dir.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(self.store.metadata_dir / "sensor-receipts.lock", os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            document = self.receipts()
            receipts = document.setdefault("receipts", {})
            receipts[str(sensor_id)[:128]] = {
                "loaded_release_id": str(release_id)[:128],
                "loaded_yara_rules": max(0, int(loaded_yara_rules)),
                "loaded_hash_entries": max(0, int(loaded_hash_entries)),
                "load_duration": max(0.0, float(load_duration)),
                "status": str(status)[:64],
                "acknowledged_at": utc_now().isoformat(),
            }
            document.update({"schema_version": 1, "updated_at": utc_now().isoformat()})
            self.store._atomic_json(self.receipt_path, document)
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def receipts(self) -> dict[str, Any]:
        try:
            if self.receipt_path.is_symlink() or not self.receipt_path.is_file() or self.receipt_path.stat().st_size > 1024 * 1024:
                return {"schema_version": 1, "receipts": {}}
            document = json.loads(self.receipt_path.read_text(encoding="utf-8"))
            return document if isinstance(document, dict) and isinstance(document.get("receipts"), dict) else {"schema_version": 1, "receipts": {}}
        except (OSError, json.JSONDecodeError):
            return {"schema_version": 1, "receipts": {}}

    def desynchronized_sensors(self, active_release: str) -> list[str]:
        return sorted(
            sensor_id
            for sensor_id, receipt in self.receipts().get("receipts", {}).items()
            if sensor_id != "definition_loader_validation"
            and isinstance(receipt, dict)
            and receipt.get("status") == "ACCEPTED"
            and receipt.get("loaded_release_id") != active_release
        )


__all__ = ["DefinitionSensorReloadCoordinator"]
