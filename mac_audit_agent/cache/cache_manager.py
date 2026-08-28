from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from mac_audit_agent.models import utc_now_iso


@dataclass
class CacheReadResult:
    key: str
    hit: bool
    payload: Any = None
    stale: bool = False
    corrupted: bool = False
    error: str = ""
    path: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class CacheManager:
    def __init__(self, cache_dir: Path | None = None, *, max_cache_size_mb: int = 512) -> None:
        self.cache_dir = cache_dir or Path.home() / ".mac_audit_agent" / "cache"
        self.max_cache_size_mb = max_cache_size_mb
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _path_for_key(self, key: str) -> Path:
        safe = "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in key)
        return self.cache_dir / f"{safe}.json"

    def read_json(self, key: str, *, ttl_seconds: int = 86_400) -> CacheReadResult:
        path = self._path_for_key(key)
        if not path.exists():
            return CacheReadResult(key, False, path=str(path))
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            return CacheReadResult(key, False, corrupted=True, error=str(exc), path=str(path))
        stored_at = str(payload.get("_cache_metadata", {}).get("stored_at", "")) if isinstance(payload, dict) else ""
        stale = True
        if stored_at:
            try:
                parsed = datetime.fromisoformat(stored_at)
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                stale = datetime.now(timezone.utc) - parsed > timedelta(seconds=ttl_seconds)
            except ValueError:
                stale = True
        return CacheReadResult(key, True, payload.get("payload", payload) if isinstance(payload, dict) else payload, stale=stale, path=str(path))

    def write_json(self, key: str, payload: Any, *, source: str = "") -> Path:
        path = self._path_for_key(key)
        wrapped = {"_cache_metadata": {"stored_at": utc_now_iso(), "source": source}, "payload": payload}
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(wrapped, sort_keys=True, default=str), encoding="utf-8")
        tmp.replace(path)
        return path

    def clear_expired(self, *, ttl_seconds: int = 86_400) -> int:
        removed = 0
        for path in self.cache_dir.glob("*.json"):
            result = self.read_json(path.stem, ttl_seconds=ttl_seconds)
            if result.stale or result.corrupted:
                try:
                    path.unlink()
                    removed += 1
                except OSError:
                    pass
        return removed

    def size_bytes(self) -> int:
        total = 0
        for root, _dirs, files in os.walk(self.cache_dir):
            for filename in files:
                try:
                    total += (Path(root) / filename).stat().st_size
                except OSError:
                    pass
        return total

    def diagnostics(self) -> dict[str, Any]:
        files = sorted(
            (
                {"path": str(path), "size": path.stat().st_size, "modified": datetime.fromtimestamp(path.stat().st_mtime).isoformat()}
                for path in self.cache_dir.glob("*")
                if path.is_file()
            ),
            key=lambda item: int(item["size"]),
            reverse=True,
        )
        return {"cache_dir": str(self.cache_dir), "size_bytes": self.size_bytes(), "largest_files": files[:20], "max_cache_size_mb": self.max_cache_size_mb}
