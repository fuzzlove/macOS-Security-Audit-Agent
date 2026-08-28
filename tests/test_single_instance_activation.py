from __future__ import annotations

from pathlib import Path

from mac_audit_agent.runtime.single_instance import SingleInstanceLock


def test_second_instance_requests_activation_from_lock_owner(tmp_path: Path) -> None:
    owner = SingleInstanceLock("msaa-test", tmp_path / "msaa.lock")
    duplicate = SingleInstanceLock("msaa-test", tmp_path / "msaa.lock")
    assert owner.acquire()
    try:
        assert not duplicate.acquire()
        assert duplicate.request_activation()
        assert owner.consume_activation_request()
        assert not owner.consume_activation_request()
    finally:
        owner.release()


def test_main_window_is_presented_before_integrity_gate() -> None:
    source = (Path(__file__).resolve().parents[1] / "mac_audit_agent" / "app.py").read_text(encoding="utf-8")
    construction = source.index("window = _open_main_window_with_writable_db")
    presentation = source.index("window.show()", construction)
    gate = source.index("run_launch_integrity_gate", construction)

    assert construction < presentation < gate
