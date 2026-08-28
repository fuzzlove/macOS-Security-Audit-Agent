"""Non-destructive containment policy definitions."""

from dataclasses import dataclass
from enum import Enum


class ContainmentMode(str, Enum):
    OBSERVE = "observe"
    WARN = "warn"
    CONFIRM = "confirm_before_containment"
    STRICT = "strict_local_protection"


@dataclass(frozen=True)
class ContainmentPolicy:
    mode: ContainmentMode = ContainmentMode.CONFIRM
    allow_process_suspend: bool = False
    allow_process_terminate: bool = False
    allow_quarantine: bool = False
    delete_files: bool = False
    require_local_confirmation: bool = True

    def __post_init__(self) -> None:
        if self.delete_files:
            raise ValueError("MSAA does not permit automatic file deletion")


__all__ = ["ContainmentMode", "ContainmentPolicy"]
