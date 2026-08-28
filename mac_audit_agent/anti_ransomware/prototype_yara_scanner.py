from __future__ import annotations

import threading
from pathlib import Path
from queue import Empty, Full, Queue
from typing import Callable

from .definition_database import (
    ActiveMacOSMalwareDatabase,
    MacOSMalwareDefinitionSnapshot,
)
from .hash_indicators import HashIndicator, HashIndicatorBackend
from .yara_rule_manager import YaraRuleManager


class PrototypeYaraScanner:
    """One-worker, bounded on-change scanner for the pre-certificate observer."""
    def __init__(
        self,
        manager: YaraRuleManager,
        callback: Callable[[Path, tuple[str, ...]], None],
        *,
        definition_database: ActiveMacOSMalwareDatabase | None = None,
        hash_callback: Callable[[Path, tuple[HashIndicator, ...]], None] | None = None,
        queue_size: int = 128,
        reload_interval_seconds: float = 60.0,
    ):
        self.manager = manager; self.callback = callback; self.definition_database = definition_database
        self.hash_callback = hash_callback; self.queue: Queue[Path] = Queue(maxsize=queue_size)
        self.stop_event = threading.Event(); self.thread = None; self.compiled = None; self.dropped = 0
        self.reload_interval_seconds = max(0.05, float(reload_interval_seconds)); self.definition_snapshot = MacOSMalwareDefinitionSnapshot("", "", {}, HashIndicatorBackend(), {})
        self.hash_cache = None
        if definition_database is not None and hasattr(definition_database, "store"):
            try:
                from mac_audit_agent.threat_definitions.intelligence import (
                    FileHashCache,
                )
                self.hash_cache = FileHashCache(definition_database.store.cache_dir / "file_hashes.sqlite3")
            except (OSError, RuntimeError, ValueError):
                self.hash_cache = None
    @property
    def active(self): return bool(self.thread and self.thread.is_alive())
    def start(self):
        self._reload_definitions(force=True)
        if self.compiled is None and not self.definition_snapshot.hash_backend.indicator_count and self.definition_database is None: return False
        self.stop_event.clear(); self.thread = threading.Thread(target=self._run, name="MSAAPrototypeYara", daemon=True); self.thread.start(); return True
    def submit(self, path: Path):
        if not self.active: return
        try: self.queue.put_nowait(Path(path))
        except Full: self.dropped += 1
    def _run(self):
        last_reload = 0.0
        while not self.stop_event.wait(0.05):
            import time
            if time.monotonic() - last_reload >= self.reload_interval_seconds:
                self._reload_definitions()
                last_reload = time.monotonic()
            try: path = self.queue.get_nowait()
            except Empty: continue
            try:
                # Exact SHA-256 intelligence is canonical and evaluated before
                # pattern matching. Legacy digests share the same bounded read.
                if self.definition_snapshot.hash_backend.indicator_count and self.hash_cache is not None:
                    _digests = self.hash_cache.digest(
                        path, include_legacy=any(name in {"md5", "sha1"} for name in self.definition_snapshot.hash_backend.algorithms),
                    )
                    hash_matches = tuple(
                        match for algorithm, digest in _digests.items()
                        if (match := self.definition_snapshot.hash_backend.match_digest(algorithm, digest)) is not None
                    )
                elif self.definition_snapshot.hash_backend.indicator_count:
                    hash_matches, _digests = self.definition_snapshot.hash_backend.match_file_all(path)
                else:
                    hash_matches = ()
                if hash_matches and self.hash_callback is not None:
                    self.hash_callback(path, hash_matches)
                if self.compiled is not None:
                    matches = self.manager.backend.scan(self.compiled, path)
                    names = tuple(str(getattr(match, "rule", match)) for match in matches)
                    if names: self.callback(path, names)
            except (OSError, ValueError, TimeoutError, RuntimeError): pass
            finally: self.queue.task_done()
    def _reload_definitions(self, *, force: bool = False):
        import time
        started = time.monotonic()
        try:
            snapshot = self.definition_database.load() if self.definition_database is not None else MacOSMalwareDefinitionSnapshot("", "", {}, self.definition_snapshot.hash_backend.__class__(), {})
            if not force and snapshot.generation == self.definition_snapshot.generation:
                return
            sources = self.manager.active_sources()
            sources.update(snapshot.yara_sources)
            try:
                compiled = self.manager.backend.compile(sources) if sources else None
            except RuntimeError:
                compiled = None
            self.compiled = compiled
            self.definition_snapshot = snapshot
            if snapshot.version and self.definition_database is not None and hasattr(self.definition_database, "store"):
                from mac_audit_agent.threat_definitions.sensor_reload import (
                    DefinitionSensorReloadCoordinator,
                )
                try:
                    DefinitionSensorReloadCoordinator(self.definition_database.store).acknowledge(
                        "anti_ransomware_prototype", snapshot.version,
                        loaded_yara_rules=int(snapshot.counts.get("YARA_RULE", len(snapshot.yara_sources))),
                        loaded_hash_entries=snapshot.hash_backend.indicator_count,
                        load_duration=time.monotonic() - started,
                        status="ACCEPTED",
                    )
                except OSError:
                    # A receipt failure degrades health visibility but must not
                    # discard an already validated definition snapshot.
                    pass
        except Exception:  # noqa: BLE001 - keep the last verified generation on any backend failure
            # Keep the last verified generation active when a replacement fails.
            return
    def stop(self, timeout=2.0):
        self.stop_event.set()
        if self.thread: self.thread.join(timeout)
        self.thread = None
