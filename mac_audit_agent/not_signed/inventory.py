from __future__ import annotations

import hashlib
from collections import defaultdict
from pathlib import Path
from threading import Event
from typing import Callable, Iterable

from .discovery import DEFAULT_ROOTS, bundle_metadata, discover_applications, discover_persistence, discover_processes
from .models import AssociatedFileRecord, InstalledSoftwareItem, ProcessRecord
from .protected_items import protected_path
from .risk_engine import score
from .signing_assessor import SigningAssessor


class SoftwareInventoryService:
    def __init__(self, *, assessor: SigningAssessor | None = None, roots: Iterable[Path] = DEFAULT_ROOTS, max_items: int = 2000):
        self.assessor, self.roots, self.max_items = assessor or SigningAssessor(), tuple(roots), max_items

    def scan(self, *, cancel: Event | None = None, on_item: Callable[[InstalledSoftwareItem], None] | None = None, on_phase: Callable[[str], None] | None = None) -> tuple[InstalledSoftwareItem, ...]:
        phase = on_phase or (lambda _value: None); emit = on_item or (lambda _value: None)
        phase("Enumerating running processes")
        processes = discover_processes(); persistence = discover_persistence()
        by_bundle: dict[Path, list[ProcessRecord]] = defaultdict(list); standalone: dict[Path, list[ProcessRecord]] = defaultdict(list)
        for process in processes:
            bundle = next((parent for parent in (process.executable_path, *process.executable_path.parents) if parent.suffix == ".app"), None)
            (by_bundle[bundle] if bundle else standalone[process.executable_path]).append(process)
        phase("Discovering applications")
        bundles = list(discover_applications(self.roots, limit=self.max_items, cancel=cancel))
        for bundle in by_bundle:
            if bundle not in bundles: bundles.append(bundle)
        items: list[InstalledSoftwareItem] = []
        phase("Verifying signatures and provenance")
        for bundle in bundles[:self.max_items]:
            if cancel and cancel.is_set(): break
            metadata = bundle_metadata(bundle); executable = Path(metadata["executable"])
            item = self._item(executable, bundle, metadata, tuple(by_bundle.get(bundle, ())), persistence)
            items.append(item); emit(item)
        phase("Assessing standalone running executables")
        for executable, running in list(standalone.items())[:500]:
            if cancel and cancel.is_set(): break
            item = self._item(executable, None, {"name": executable.name, "bundle_id": None, "version": None, "icon": None}, tuple(running), persistence)
            items.append(item); emit(item)
        phase("Complete")
        return tuple(items)

    def _item(self, executable: Path, bundle: Path | None, metadata: dict[str, object], running: tuple[ProcessRecord, ...], persistence_all):
        assessment_target = bundle or executable
        signing = self.assessor.assess(assessment_target)
        matching = tuple(item for item in persistence_all if item.executable_path and (item.executable_path == executable or (bundle and bundle in item.executable_path.parents)))
        severity, reasons = score(signing.classification, executable, running, bool(matching))
        protected, protection_reason = protected_path(bundle or executable)
        associated = tuple(AssociatedFileRecord(item.path, "LaunchAgents/LaunchDaemons", "Confirmed", "Launch item explicitly references this executable.", True) for item in matching)
        try: stat = assessment_target.stat(); modified = str(stat.st_mtime); size = stat.st_size
        except OSError: modified, size = "", 0
        identity = hashlib.sha256(str((bundle or executable).resolve(strict=False)).encode()).hexdigest()[:24]
        source = "system" if str(executable).startswith("/System/") else ("homebrew" if str(executable).startswith(("/opt/homebrew/", "/usr/local/Cellar/")) else "installed")
        return InstalledSoftwareItem(identity, str(metadata["name"]), executable, bundle, metadata.get("bundle_id"), metadata.get("version"), metadata.get("icon"), signing, running, matching, associated, severity, reasons, source, size, modified, protected, protection_reason)
