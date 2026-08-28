from __future__ import annotations

import subprocess

import pytest

from mac_audit_agent.threat_definitions import credentials


def _enable_fake_keychain(monkeypatch, tmp_path):
    security = tmp_path / "security"
    security.touch()
    monkeypatch.setattr(credentials, "_SECURITY", str(security))
    monkeypatch.setattr(credentials.sys, "platform", "darwin")
    monkeypatch.delenv("SUDO_UID", raising=False)


def test_keychain_save_never_places_secret_in_process_arguments(monkeypatch, tmp_path):
    _enable_fake_keychain(monkeypatch, tmp_path)
    secret = "A" * 48
    captured = {}

    def runner(args, **kwargs):
        captured.update(args=list(args), kwargs=kwargs)
        return subprocess.CompletedProcess(args, 0, "", "")

    status = credentials.save_abuse_ch_auth_key(secret, runner=runner)

    assert status.configured is True
    assert secret not in " ".join(captured["args"])
    assert captured["args"][-1] == "-w"
    assert captured["kwargs"]["input"] == f"{secret}\n"
    assert "capture_output" in captured["kwargs"]


def test_keychain_load_returns_valid_secret_without_exposing_it_in_argv(monkeypatch, tmp_path):
    _enable_fake_keychain(monkeypatch, tmp_path)
    monkeypatch.delenv(credentials.ABUSE_CH_AUTH_ENV, raising=False)
    secret = "B" * 48
    captured = {}

    def runner(args, **kwargs):
        captured["args"] = list(args)
        return subprocess.CompletedProcess(args, 0, f"{secret}\n", "")

    assert credentials.load_abuse_ch_auth_key(runner=runner) == secret
    assert secret not in " ".join(captured["args"])
    assert captured["args"][-1] == "-w"


def test_environment_override_precedes_keychain(monkeypatch):
    secret = "C" * 48
    monkeypatch.setenv(credentials.ABUSE_CH_AUTH_ENV, secret)

    def runner(*_args, **_kwargs):
        pytest.fail("Keychain must not be called when a valid temporary override exists")

    assert credentials.load_abuse_ch_auth_key(runner=runner) == secret
    status = credentials.abuse_ch_credential_status(runner=runner)
    assert status.configured is True
    assert status.source == "environment"


def test_invalid_secret_is_rejected_before_keychain_invocation(monkeypatch, tmp_path):
    _enable_fake_keychain(monkeypatch, tmp_path)

    def runner(*_args, **_kwargs):
        pytest.fail("Invalid data must not reach Keychain")

    with pytest.raises(credentials.CredentialValidationError):
        credentials.save_abuse_ch_auth_key("too short", runner=runner)


def test_credential_errors_are_sanitized(monkeypatch, tmp_path):
    _enable_fake_keychain(monkeypatch, tmp_path)
    secret = "D" * 48

    def runner(args, **_kwargs):
        return subprocess.CompletedProcess(args, 1, "", f"provider rejected {secret}")

    with pytest.raises(credentials.CredentialStoreError) as failure:
        credentials.save_abuse_ch_auth_key(secret, runner=runner)
    assert secret not in str(failure.value)


def test_root_automatic_credential_uses_system_keychain(monkeypatch, tmp_path):
    _enable_fake_keychain(monkeypatch, tmp_path)
    system_keychain = tmp_path / "System.keychain"
    system_keychain.touch()
    monkeypatch.setattr(credentials, "SYSTEM_KEYCHAIN", system_keychain)
    monkeypatch.setattr(credentials.os, "geteuid", lambda: 0)
    secret = "E" * 48
    calls = []

    def runner(args, **kwargs):
        calls.append((list(args), kwargs))
        if "find-generic-password" in args:
            return subprocess.CompletedProcess(args, 0, secret + "\n", "")
        return subprocess.CompletedProcess(args, 0, "", "")

    assert credentials.load_abuse_ch_auth_key(runner=runner) == secret
    assert str(system_keychain) in calls[0][0]
    status = credentials.automatic_abuse_ch_credential_status(runner=runner)
    assert status.configured is True
    assert status.source == "system_keychain"


def test_automatic_credential_install_never_places_secret_in_argv(monkeypatch, tmp_path):
    _enable_fake_keychain(monkeypatch, tmp_path)
    system_keychain = tmp_path / "System.keychain"
    system_keychain.touch()
    monkeypatch.setattr(credentials, "SYSTEM_KEYCHAIN", system_keychain)
    monkeypatch.setattr(credentials.os, "geteuid", lambda: 0)
    secret = "F" * 48
    captured = {}

    def native_writer(value):
        captured["value"] = value

    def runner(*_args, **_kwargs):
        pytest.fail("Automatic credential provisioning must not launch a subprocess")

    monkeypatch.setattr(credentials, "_upsert_system_keychain_secret", native_writer)
    status = credentials.save_automatic_abuse_ch_auth_key(secret, runner=runner)
    assert status.configured is True
    assert captured["value"] == secret


def test_definition_panel_uses_password_entry_and_never_prefills_saved_key(monkeypatch):
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    pytest.importorskip("PySide6")
    from PySide6.QtWidgets import QApplication, QLineEdit

    from mac_audit_agent.ui import malware_definitions_panel as panel_module

    monkeypatch.setattr(panel_module.QTimer, "singleShot", lambda *_args: None)
    app = QApplication.instance() or QApplication([])
    panel = panel_module.MalwareDefinitionsPanel()
    assert panel.abuse_ch_key_input.text() == ""
    assert panel.abuse_ch_key_input.echoMode() == QLineEdit.EchoMode.Password
    assert panel.save_abuse_ch_key_button.text() == "Save / Replace Key"
    assert panel.automatic_feed_auth_button.text() == "Enable Automatic Feed Updates"
    assert panel.repair_updater_button.text() == "Repair Automatic Updater"
    panel.close()
    app.processEvents()
