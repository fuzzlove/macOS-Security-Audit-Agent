from __future__ import annotations

import threading
import time
from types import SimpleNamespace

from mac_audit_agent.hardware_monitor import USBReconnectObserver
from mac_audit_agent.runtime import python_compat
from mac_audit_agent.runtime.python_runtime_gate import evaluate_python_runtime


class _Monitor:
    def collect_usb_devices(self):
        return []

    def _usb_key(self, item):
        return ""

    def usb_physical_key(self, item):
        return ""

    def usb_connection_events(self, previous, current):
        return []


def test_python_314_is_headless_only_by_default(monkeypatch) -> None:
    monkeypatch.setattr(python_compat.sys, "version_info", SimpleNamespace(major=3, minor=14, micro=6))
    assert python_compat.current_python_gui_compatibility().supported_for_gui is False


def test_runtime_gate_accepts_current_standard_cpython() -> None:
    result = evaluate_python_runtime()
    if result.python_version.startswith("3.14."):
        assert result.supported_for_integrity_cli is True
        assert result.supported_for_gui is False


def test_usb_observer_repeated_and_concurrent_start_is_singleton() -> None:
    observer = USBReconnectObserver(_Monitor(), poll_seconds=0.01)  # type: ignore[arg-type]
    results: list[bool] = []
    workers = [threading.Thread(target=lambda: results.append(observer.start())) for _ in range(20)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()
    try:
        assert results.count(True) == 1
        assert sum(thread.name == "mac-audit-usb-observer" for thread in threading.enumerate()) == 1
    finally:
        assert observer.stop() is True
    assert sum(thread.name == "mac-audit-usb-observer" for thread in threading.enumerate()) == 0


def test_usb_observer_100_lifecycle_iterations_leave_no_threads() -> None:
    for _ in range(100):
        observer = USBReconnectObserver(_Monitor(), poll_seconds=0.01)  # type: ignore[arg-type]
        assert observer.start() is True
        time.sleep(0.001)
        assert observer.stop() is True
    assert sum(thread.name == "mac-audit-usb-observer" for thread in threading.enumerate()) == 0
