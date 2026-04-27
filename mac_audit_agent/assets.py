from __future__ import annotations

import base64
import mimetypes
import sys
from pathlib import Path


def _asset_roots() -> list[Path]:
    package_root = Path(__file__).resolve().parent
    roots: list[Path] = []
    bundle_root = getattr(sys, "_MEIPASS", None)
    if bundle_root:
        roots.append(Path(bundle_root) / "mac_audit_agent" / "assets")
    roots.append(package_root / "assets")
    return roots


def get_asset_path(name: str) -> Path:
    for root in _asset_roots():
        candidate = root / name
        if candidate.exists():
            return candidate
    return _asset_roots()[-1] / name


def get_asset_data_uri(name: str) -> str | None:
    path = get_asset_path(name)
    if not path.exists():
        return None
    try:
        data = path.read_bytes()
    except OSError:
        return None
    mime_type, _ = mimetypes.guess_type(path.name)
    encoded = base64.b64encode(data).decode("ascii")
    return f"data:{mime_type or 'application/octet-stream'};base64,{encoded}"
