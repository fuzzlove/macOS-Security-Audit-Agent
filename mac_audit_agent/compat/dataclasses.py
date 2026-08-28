"""Stable dataclass exports used by MSAA, including Python 3.9 support."""

import dataclasses as _stdlib_dataclasses
import sys

from dataclasses import asdict, astuple, field, fields, is_dataclass, replace


_stdlib_dataclass = _stdlib_dataclasses.dataclass


def dataclass(cls=None, /, **kwargs):
    """Use stdlib dataclasses while accepting newer layout flags on 3.9.

    ``slots`` and ``weakref_slot`` affect object layout, not serialized data or
    validation semantics. Python 3.9 cannot synthesize those layouts, so legacy
    headless mode safely ignores the flags instead of failing during import.
    """
    if sys.version_info < (3, 10):
        kwargs.pop("slots", None)
        kwargs.pop("weakref_slot", None)
    return _stdlib_dataclass(cls, **kwargs) if cls is not None else lambda target: _stdlib_dataclass(target, **kwargs)


def install_legacy_dataclass_compat() -> None:
    """Make imports from stdlib ``dataclasses`` tolerate 3.10+ flags on 3.9."""
    if sys.version_info < (3, 10) and _stdlib_dataclasses.dataclass is not dataclass:
        _stdlib_dataclasses.dataclass = dataclass

__all__ = ["asdict", "astuple", "dataclass", "field", "fields", "install_legacy_dataclass_compat", "is_dataclass", "replace"]
