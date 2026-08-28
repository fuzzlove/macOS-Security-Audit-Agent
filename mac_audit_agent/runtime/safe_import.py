from __future__ import annotations

import importlib
from dataclasses import dataclass
from typing import Any, Callable, Union


class DependencyUnavailable(ImportError): pass
class CapabilityUnavailable(RuntimeError): pass
class RequiredDependencyMissing(DependencyUnavailable): pass


@dataclass(frozen=True)
class SafeImportResult:
    module: Any = None; available: bool = False; error: str = ""; fallback_used: bool = False; user_message: str = ""


def safe_import(module_name: str, *, capability_id: str, fallback: Union[Callable[[], Any], Any] = None, required: bool = False) -> SafeImportResult:
    try:
        return SafeImportResult(importlib.import_module(module_name), True, "", False, "Available.")
    except (ImportError, OSError) as exc:
        message = f"{capability_id} is unavailable because optional module {module_name} could not be loaded. Other MSAA features remain available."
        if fallback is not None:
            value = fallback() if callable(fallback) else fallback
            return SafeImportResult(value, False, f"{type(exc).__name__}: {exc}", True, message + " A reduced fallback is active.")
        if required:
            raise RequiredDependencyMissing(message) from exc
        return SafeImportResult(None, False, f"{type(exc).__name__}: {exc}", False, message)


__all__ = ["CapabilityUnavailable", "DependencyUnavailable", "RequiredDependencyMissing", "SafeImportResult", "safe_import"]
