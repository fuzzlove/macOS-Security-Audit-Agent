from __future__ import annotations

import builtins
import subprocess
from pathlib import Path

import pytest

from mac_audit_agent.integrity import __main__ as integrity_cli
from mac_audit_agent.integrity.trust_policy import EnrolledYubiKey
from mac_audit_agent.integrity.yubikey_signing import (
    DEFAULT_PIV_MANAGEMENT_KEY_HEX,
    ManagementKey,
    ManagementKeyInputError,
    YubiKeyDiagnostics,
    YubiKeySigningError,
    _run,
    enroll_yubikey,
    parse_management_key_input,
)


def test_blank_input_maps_to_default_key() -> None:
    parsed = parse_management_key_input("")
    assert parsed.hex_value == DEFAULT_PIV_MANAGEMENT_KEY_HEX
    assert parsed.is_default


def test_whitespace_input_maps_to_default_key() -> None:
    assert parse_management_key_input("  \t\n  ").hex_value == DEFAULT_PIV_MANAGEMENT_KEY_HEX


def test_default_keyword_maps_to_default_key() -> None:
    assert parse_management_key_input("default").hex_value == DEFAULT_PIV_MANAGEMENT_KEY_HEX


def test_uppercase_default_keyword_maps_to_default_key() -> None:
    assert parse_management_key_input("DEFAULT").hex_value == DEFAULT_PIV_MANAGEMENT_KEY_HEX


def test_48_char_default_hex_validates() -> None:
    parsed = parse_management_key_input(DEFAULT_PIV_MANAGEMENT_KEY_HEX)
    assert parsed.hex_value == DEFAULT_PIV_MANAGEMENT_KEY_HEX


def test_32_char_aes_128_key_validates() -> None:
    assert parse_management_key_input("aa" * 16).hex_value == "aa" * 16


def test_64_char_aes_256_key_validates() -> None:
    assert parse_management_key_input("hex:" + "bb" * 32).hex_value == "bb" * 32


def test_hex_with_spaces_and_colons_validates() -> None:
    assert parse_management_key_input("01:02 03:04 " + "05" * 20).hex_value == "01020304" + "05" * 20


def test_invalid_hex_fails_with_actionable_message() -> None:
    with pytest.raises(ManagementKeyInputError, match="expected hex characters only"):
        parse_management_key_input("zz" * 24)


def test_invalid_length_fails_with_actionable_message() -> None:
    with pytest.raises(ManagementKeyInputError, match="expected 32, 48, or 64 hex characters"):
        parse_management_key_input("aa")


def test_supplied_key_is_never_logged(monkeypatch: pytest.MonkeyPatch) -> None:
    secret = "aa" * 24

    def fake_run(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(["ykman"], 1, "", f"bad --management-key {secret}")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(YubiKeySigningError) as exc:
        _run(["ykman", "piv", "keys", "generate", "--management-key", secret])
    assert secret not in str(exc.value)
    assert "<redacted>" in str(exc.value)


def test_prompt_occurs_once(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    prompts: list[str] = []
    captured: dict[str, object] = {}

    def fake_getpass(prompt: str) -> str:
        prompts.append(prompt)
        return ""

    def fake_enroll(*_args: object, **kwargs: object) -> EnrolledYubiKey:
        captured.update(kwargs)
        return _enrolled()

    monkeypatch.setattr(integrity_cli.getpass, "getpass", fake_getpass)
    monkeypatch.setattr(integrity_cli, "get_yubikey_diagnostics", lambda: YubiKeyDiagnostics())
    monkeypatch.setattr(integrity_cli, "enroll_yubikey", fake_enroll)
    args = integrity_cli.build_parser().parse_args(
        ["yubikey", "enroll", "--root", str(tmp_path), "--label", "Key 1", "--developer-id", "dev", "--slot", "9c"]
    )
    assert integrity_cli.command_yubikey(args) == 0
    assert prompts == ["Enter a management key [blank to use default key]: "]
    assert isinstance(captured["management_key"], ManagementKey)
    assert captured["management_key"].hex_value == DEFAULT_PIV_MANAGEMENT_KEY_HEX


def test_management_key_default_skips_prompt(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    captured: dict[str, object] = {}

    def fail_getpass(_prompt: str) -> str:
        raise AssertionError("management key prompt should be skipped")

    def fake_enroll(*_args: object, **kwargs: object) -> EnrolledYubiKey:
        captured.update(kwargs)
        return _enrolled()

    monkeypatch.setattr(integrity_cli.getpass, "getpass", fail_getpass)
    monkeypatch.setattr(integrity_cli, "get_yubikey_diagnostics", lambda: YubiKeyDiagnostics())
    monkeypatch.setattr(integrity_cli, "enroll_yubikey", fake_enroll)
    args = integrity_cli.build_parser().parse_args(
        ["yubikey", "enroll", "--root", str(tmp_path), "--label", "Key 1", "--developer-id", "dev", "--slot", "9c", "--management-key", "default"]
    )
    assert integrity_cli.command_yubikey(args) == 0
    assert captured["management_key"].hex_value == DEFAULT_PIV_MANAGEMENT_KEY_HEX


def test_backend_does_not_prompt_if_key_object_supplied(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def fail_input(_prompt: str = "") -> str:
        raise AssertionError("backend must not prompt when management_key is supplied")

    monkeypatch.setattr(builtins, "input", fail_input)
    monkeypatch.setattr("mac_audit_agent.integrity.yubikey_signing.shutil.which", lambda _tool: None)
    with pytest.raises(YubiKeySigningError, match="required tool is missing"):
        enroll_yubikey("Key 1", "dev", root=tmp_path, management_key=parse_management_key_input("default"))


def test_enroll_path_does_not_import_pyside_or_qapplication(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    real_import = builtins.__import__

    def guarded_import(name: str, *args: object, **kwargs: object) -> object:
        if name.startswith("PySide6") or name in {"AppKit", "QApplication"}:
            raise AssertionError(f"forbidden GUI import: {name}")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    monkeypatch.setattr(integrity_cli, "get_yubikey_diagnostics", lambda: YubiKeyDiagnostics())
    monkeypatch.setattr(integrity_cli, "enroll_yubikey", lambda *_args, **_kwargs: _enrolled())
    args = integrity_cli.build_parser().parse_args(
        ["yubikey", "enroll", "--root", str(tmp_path), "--label", "Key 1", "--developer-id", "dev", "--slot", "9c", "--management-key", "default"]
    )
    assert integrity_cli.command_yubikey(args) == 0


def test_bad_key_exits_nonzero_with_actionable_message(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    args = integrity_cli.build_parser().parse_args(
        ["yubikey", "enroll", "--root", str(tmp_path), "--label", "Key 1", "--developer-id", "dev", "--management-key", "not-hex"]
    )
    assert integrity_cli.command_yubikey(args) == 2
    err = capsys.readouterr().err
    assert "Invalid management key: expected hex characters only." in err
    assert "not-hex" not in err


def _enrolled() -> EnrolledYubiKey:
    return EnrolledYubiKey(
        yubikey_id="yk1",
        label="Key 1",
        owner_developer_id="dev",
        public_key_pem="pub",
        certificate_pem="cert",
        certificate_fingerprint_sha256="fp",
    )
