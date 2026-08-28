"""Runtime-safe typing exports for every MSAA diagnostic runtime."""

from __future__ import annotations

import typing as _typing

Any = _typing.Any
Callable = _typing.Callable
Iterable = _typing.Iterable
Mapping = _typing.Mapping
MutableMapping = _typing.MutableMapping
Sequence = _typing.Sequence
Optional = _typing.Optional
Union = _typing.Union
TYPE_CHECKING = _typing.TYPE_CHECKING
Literal = _typing.Literal
Protocol = _typing.Protocol
TypedDict = _typing.TypedDict

try:  # Optional convenience only; doctor never requires this package.
    import typing_extensions as _extensions
except Exception:  # pragma: no cover - exercised on minimal Apple Python
    _extensions = None


def _symbol(name: str, fallback: Any = Any) -> Any:
    value = getattr(_typing, name, None)
    if value is not None:
        return value
    if _extensions is not None:
        value = getattr(_extensions, name, None)
        if value is not None:
            return value
    return fallback


TypeAlias = _symbol("TypeAlias")
Self = _symbol("Self")
Required = _symbol("Required")
NotRequired = _symbol("NotRequired")
TypeGuard = _symbol("TypeGuard")

__all__ = [
    "Any", "Callable", "Iterable", "Literal", "Mapping", "MutableMapping",
    "NotRequired", "Optional", "Protocol", "Required", "Self", "Sequence",
    "TYPE_CHECKING", "TypeAlias", "TypeGuard", "TypedDict", "Union",
]
