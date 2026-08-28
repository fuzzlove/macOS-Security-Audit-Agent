from __future__ import annotations

from mac_audit_agent.runtime.doctor import DEPENDENCIES, _dependency_status, _tool_status


def test_office_dependencies_are_optional_in_doctor_only(monkeypatch) -> None:
    monkeypatch.setattr("importlib.util.find_spec", lambda name: None)
    for name in ("openpyxl", "python-docx"):
        item = _dependency_status(name, DEPENDENCIES[name], doctor_only=True)
        assert item["status"] == "OPTIONAL_MISSING"
        assert item["current_mode_affected"] is False
        assert item["install_into_current_interpreter"] is False


def test_optional_tools_do_not_degrade_doctor_only(monkeypatch) -> None:
    monkeypatch.setattr("shutil.which", lambda name: None)
    nmap = _tool_status("nmap", doctor_only=True)
    pkcs11 = _tool_status("pkcs11-tool", doctor_only=True)
    assert nmap["status"] == "OPTIONAL_MISSING"
    assert pkcs11["status"] == "INFO"
    assert pkcs11["trust_policy"] == "developer-machine signing"


def test_pyside_presence_does_not_override_runtime_policy() -> None:
    item = _dependency_status("PySide6", DEPENDENCIES["PySide6"], doctor_only=True)
    assert item["status"] in {"INFO", "OPTIONAL_MISSING"}
    assert "GUI blocked" in item["runtime_decision"]
