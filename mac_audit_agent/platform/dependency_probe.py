from __future__ import annotations

import importlib.metadata
import importlib.util
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class DependencyProbe:
    distribution: str; module: str; available: bool; version: str; category: str; native: bool; evidence: dict[str, object]
    def to_dict(self) -> dict[str, object]: return asdict(self)


def probe_dependency(distribution: str, module: str, *, category: str = "optional") -> DependencyProbe:
    spec = importlib.util.find_spec(module)
    try: version = importlib.metadata.version(distribution)
    except importlib.metadata.PackageNotFoundError: version = "missing"
    origin = str(getattr(spec, "origin", "") or "") if spec else ""
    native = origin.endswith((".so", ".dylib"))
    return DependencyProbe(distribution, module, spec is not None, version, category, native, {"origin": origin, "architecture_validation_required": native})


__all__ = ["DependencyProbe", "probe_dependency"]
