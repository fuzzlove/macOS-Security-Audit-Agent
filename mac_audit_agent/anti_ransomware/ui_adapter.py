"""Qt-free adapter used by GUI and tests."""

from .status import get_status
from .recovery import analyze_recovery_readiness


class AntiRansomwareUIAdapter:
    def status(self) -> dict:
        return get_status()

    def readiness(self) -> dict:
        return {"status": get_status(), "recovery": analyze_recovery_readiness()}


__all__ = ["AntiRansomwareUIAdapter"]
