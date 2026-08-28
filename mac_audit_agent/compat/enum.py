"""Enum compatibility for every supported MSAA Python runtime."""

from enum import Enum, Flag, IntEnum, IntFlag, auto, unique

try:
    from enum import StrEnum as _StdlibStrEnum
except ImportError:  # Python 3.10
    _StdlibStrEnum = None


if _StdlibStrEnum is not None:
    StrEnum = _StdlibStrEnum
else:
    class StrEnum(str, Enum):
        """Minimal Python 3.10 fallback matching the StrEnum behavior MSAA uses."""

        def __str__(self) -> str:
            return str(self.value)

        @staticmethod
        def _generate_next_value_(name, start, count, last_values):
            return name.lower()


__all__ = ["Enum", "Flag", "IntEnum", "IntFlag", "StrEnum", "auto", "unique"]
