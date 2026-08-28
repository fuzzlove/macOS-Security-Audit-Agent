import sys

from mac_audit_agent.runtime.optional_dependencies import missing_office_dependency


def test_source_remediation_uses_detected_interpreter(monkeypatch) -> None:
    monkeypatch.delattr(sys, "frozen", raising=False)
    message = str(missing_office_dependency("docx"))
    assert "DEP001" in message
    assert sys.executable in message
    assert "-m pip install" in message
    assert "[office]" in message


def test_frozen_remediation_does_not_recommend_pip(monkeypatch) -> None:
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    message = str(missing_office_dependency("openpyxl"))
    assert "PKG001" in message
    assert "reinstall" in message.lower()
    assert "pip install" not in message
