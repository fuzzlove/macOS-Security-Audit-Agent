from __future__ import annotations

import pytest

from mac_audit_agent.runtime.safe_import import RequiredDependencyMissing, safe_import


def test_safe_import_returns_module_when_available() -> None:
    result = safe_import("json", capability_id="json_export")
    assert result.available and result.module.dumps({"ok": True})


def test_optional_missing_module_uses_fallback_without_raising() -> None:
    result = safe_import("msaa_module_that_does_not_exist", capability_id="optional", fallback={"reduced": True})
    assert not result.available and result.fallback_used and result.module == {"reduced": True}


def test_required_missing_module_has_guided_exception() -> None:
    with pytest.raises(RequiredDependencyMissing, match="Other MSAA features remain available"):
        safe_import("msaa_module_that_does_not_exist", capability_id="required", required=True)
