from __future__ import annotations

import plistlib
import platform
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class InventoryItem:
    product: str
    version: str
    source: str
    path: str = ""
    package_revision: str = ""
    backport_fixed: bool = False
    mitigated: bool = False


class MacOSInventory:
    """Bounded read-only application/runtime inventory; no active probing."""
    def __init__(self, application_roots: tuple[Path,...] = (Path("/Applications"), Path("/System/Applications")), max_apps: int = 2000) -> None:
        self.application_roots=application_roots; self.max_apps=max(1,min(max_apps,10_000))

    def collect(self)->list[InventoryItem]:
        items=[InventoryItem("macOS",platform.mac_ver()[0],"platform")]
        for root in self.application_roots:
            if not root.is_dir(): continue
            for app in sorted(root.glob("*.app")):
                if len(items)>=self.max_apps: return items
                info=app/"Contents"/"Info.plist"
                try:
                    if info.stat().st_size>2*1024*1024: continue
                    payload=plistlib.loads(info.read_bytes())
                except (OSError,plistlib.InvalidFileException): continue
                name=str(payload.get("CFBundleDisplayName") or payload.get("CFBundleName") or app.stem)
                version=str(payload.get("CFBundleShortVersionString") or payload.get("CFBundleVersion") or "")
                items.append(InventoryItem(name,version,"application_bundle",str(app)))
        return items
