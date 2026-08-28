"""Verified active malware definitions consumed by macOS host sensors."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from mac_audit_agent.threat_definitions.models import (
    DefinitionAction,
    DefinitionLifecycle,
    DefinitionType,
)
from mac_audit_agent.threat_definitions.store import (
    DEFAULT_DEFINITION_ROOT,
    DefinitionStore,
)

from .hash_indicators import HashIndicatorBackend

_INACTIVE = {
    DefinitionLifecycle.EXPIRED,
    DefinitionLifecycle.REVOKED,
    DefinitionLifecycle.FALSE_POSITIVE,
    DefinitionLifecycle.DISABLED,
    DefinitionLifecycle.SUPERSEDED,
}


@dataclass(frozen=True)
class MacOSMalwareDefinitionSnapshot:
    version: str
    manifest_sha256: str
    yara_sources: dict[str, str]
    hash_backend: HashIndicatorBackend
    counts: dict[str, int]

    @property
    def generation(self) -> str:
        return f"{self.version}:{self.manifest_sha256}"


class ActiveMacOSMalwareDatabase:
    """Read only from the signed, atomically activated definition database.

    MD5 and SHA-1 remain lookup/correlation formats only. The database never
    turns a legacy digest match into automatic deletion or containment.
    """

    def __init__(self, root: Path = DEFAULT_DEFINITION_ROOT, *, store: DefinitionStore | None = None) -> None:
        self.store = store or DefinitionStore(Path(root))

    def load(self) -> MacOSMalwareDefinitionSnapshot:
        active = self.store.active_bundle_path()
        if active is None:
            return MacOSMalwareDefinitionSnapshot("", "", {}, HashIndicatorBackend(), {})
        manifest = self.store.verify_bundle(active)
        definitions = [
            item for item in self.store.definitions()
            if item.lifecycle not in _INACTIVE and item.action != DefinitionAction.DISABLED
        ]
        yara_sources = {
            item.definition_id: item.value
            for item in definitions
            if item.definition_type == DefinitionType.YARA_RULE
        }
        # Administrator-owned custom rules live outside immutable releases and
        # are validated independently so one broken rule cannot block core data.
        try:
            from .yara_backend import YaraBackend
            backend = YaraBackend()
            for path in sorted(self.store.custom_dir.glob("*.yar"))[:500]:
                try:
                    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
                        continue
                    source = path.read_text(encoding="utf-8")
                    backend.compile({f"custom_{path.stem}": source})
                    yara_sources[f"custom_{path.stem}"] = source
                except (OSError, UnicodeDecodeError, RuntimeError, ValueError):
                    continue
        except (ImportError, OSError):
            pass
        counts = {
            kind.value: sum(item.definition_type == kind for item in definitions)
            for kind in (DefinitionType.YARA_RULE, DefinitionType.MD5, DefinitionType.SHA1, DefinitionType.SHA256)
        }
        custom_count = max(0, len(yara_sources) - sum(item.definition_type == DefinitionType.YARA_RULE for item in definitions))
        counts[DefinitionType.YARA_RULE.value] = int(manifest.get("yara_rule_count", counts[DefinitionType.YARA_RULE.value])) + custom_count
        pointer = self.store._pointer(self.store.active_dir)
        return MacOSMalwareDefinitionSnapshot(
            str(manifest.get("bundle_version", active.name)),
            str(pointer.get("manifest_sha256", "")),
            yara_sources,
            HashIndicatorBackend.from_threat_definitions(definitions),
            counts,
        )


__all__ = ["ActiveMacOSMalwareDatabase", "MacOSMalwareDefinitionSnapshot"]
