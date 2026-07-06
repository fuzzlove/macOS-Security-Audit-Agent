from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_legacy_path = Path(__file__).resolve().parent.parent / "frameworks.py"
_spec = importlib.util.spec_from_file_location("mac_audit_agent._frameworks_legacy", _legacy_path)
if _spec is None or _spec.loader is None:  # pragma: no cover
    raise ImportError(f"Unable to load legacy framework module: {_legacy_path}")
_legacy = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _legacy
_spec.loader.exec_module(_legacy)

for _name in dir(_legacy):
    if not _name.startswith("_"):
        globals()[_name] = getattr(_legacy, _name)

try:
    from mac_audit_agent.frameworks.cmmc import CMMC_DISCLAIMER, build_cmmc_readiness
    from mac_audit_agent.frameworks.cmmc_crosswalk import cmmc_mappings_for_finding, cmmc_mappings_for_msaa_check
except Exception:  # pragma: no cover - keep legacy framework imports resilient
    CMMC_DISCLAIMER = (
        "MSAA provides CMMC/NIST readiness mapping and evidence support. This output is not a CMMC "
        "certification, C3PAO assessment, DoD authorization, NIST compliance attestation, or legal determination."
    )

__all__ = [name for name in globals() if not name.startswith("_")]
