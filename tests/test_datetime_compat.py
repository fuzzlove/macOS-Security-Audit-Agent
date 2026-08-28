from __future__ import annotations

from datetime import datetime, timezone

from mac_audit_agent.compat.datetime_compat import UTC, utc_now


def test_utc_is_standard_utc_timezone() -> None:
    assert UTC is timezone.utc


def test_utc_now_is_timezone_aware() -> None:
    value = utc_now()

    assert value.tzinfo is not None
    assert value.utcoffset() is not None
    assert value.utcoffset().total_seconds() == 0


def test_development_manifest_preserves_canonical_z_timestamp(monkeypatch) -> None:
    from mac_audit_agent.integrity import dev_manifest

    fixed = datetime(2026, 7, 10, 12, 34, 56, 987654, tzinfo=timezone.utc)
    monkeypatch.setattr(dev_manifest, "utc_now", lambda: fixed)

    assert dev_manifest.utc_now_iso() == "2026-07-10T12:34:56Z"


def test_integrity_import_paths_initialize() -> None:
    import mac_audit_agent.integrity  # noqa: F401
    import mac_audit_agent.integrity.dev_manifest  # noqa: F401
    import mac_audit_agent.integrity.signed_manifest_validator  # noqa: F401
    from mac_audit_agent.integrity.strict_verifier import StrictIntegrityVerifier

    assert StrictIntegrityVerifier is not None
