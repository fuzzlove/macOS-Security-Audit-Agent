from __future__ import annotations

from mac_audit_agent.performance import api_refresh_manager
from mac_audit_agent.hardware_monitor import USBReconnectObserver


class _Response:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.read_size = 0

    def __enter__(self):
        return self

    def __exit__(self, *args) -> None:
        return None

    def read(self, size: int) -> bytes:
        self.read_size = size
        return self.payload[:size]


def test_url_loader_bounds_response_memory(monkeypatch) -> None:
    response = _Response(b"x" * 12)
    monkeypatch.setattr(api_refresh_manager.urllib.request, "urlopen", lambda request, timeout: response)

    try:
        api_refresh_manager.fetch_url_bytes("https://example.invalid/data", max_bytes=10)
    except ValueError as exc:
        assert "NET001" in str(exc)
    else:
        raise AssertionError("oversized response was not rejected")

    assert response.read_size == 11


def test_url_loader_returns_bounded_payload(monkeypatch) -> None:
    response = _Response(b"payload")
    monkeypatch.setattr(api_refresh_manager.urllib.request, "urlopen", lambda request, timeout: response)

    assert api_refresh_manager.fetch_url_bytes("https://example.invalid/data", max_bytes=10) == b"payload"


def test_usb_observer_queue_is_bounded() -> None:
    observer = USBReconnectObserver(object(), max_queue_size=7)  # type: ignore[arg-type]

    assert observer.events.maxsize == 7
