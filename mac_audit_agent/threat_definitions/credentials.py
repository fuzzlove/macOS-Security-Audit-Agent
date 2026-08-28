"""Credential storage for definition providers.

Provider secrets belong in macOS Keychain.  This module deliberately exposes
only fixed-purpose operations so callers cannot turn it into a general secret
reader or accidentally place credentials in command-line arguments.
"""

from __future__ import annotations

import os
import pwd
import re
import subprocess
import sys
from ctypes import CDLL, POINTER, byref, c_char_p, c_int32, c_uint32, c_void_p
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable

ABUSE_CH_AUTH_ENV = "MSAA_ABUSE_CH_AUTH_KEY"
ABUSE_CH_KEYCHAIN_SERVICE = "com.liquidsky.msaa.threat-definitions"
ABUSE_CH_KEYCHAIN_ACCOUNT = "abuse.ch-auth-key"
ABUSE_CH_KEYCHAIN_LABEL = "MSAA abuse.ch Definition Auth-Key"
ABUSE_CH_SYSTEM_KEYCHAIN_LABEL = "MSAA abuse.ch Automatic Definition Auth-Key"
SYSTEM_KEYCHAIN = Path("/Library/Keychains/System.keychain")
_AUTH_KEY_PATTERN = re.compile(r"^[A-Za-z0-9_-]{16,256}$")
_SECURITY = "/usr/bin/security"
_SECURITY_FRAMEWORK = "/System/Library/Frameworks/Security.framework/Security"
_COREFOUNDATION_FRAMEWORK = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
_ERR_SEC_ITEM_NOT_FOUND = -25300


class CredentialStoreError(RuntimeError):
    """A sanitized credential-store operation failed."""


class CredentialValidationError(ValueError):
    """A provider key does not satisfy the provider's safe input format."""


@dataclass(frozen=True)
class CredentialStatus:
    provider: str
    available: bool
    configured: bool
    source: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


Runner = Callable[..., subprocess.CompletedProcess[str]]


def validate_abuse_ch_auth_key(value: str) -> str:
    """Validate without normalizing or logging credential material."""
    key = str(value).strip()
    if not _AUTH_KEY_PATTERN.fullmatch(key):
        raise CredentialValidationError(
            "The abuse.ch Auth-Key must be 16-256 letters, numbers, underscores, or hyphens."
        )
    return key


def _keychain_args(action: str) -> list[str]:
    return [_SECURITY, action, "-a", ABUSE_CH_KEYCHAIN_ACCOUNT, "-s", ABUSE_CH_KEYCHAIN_SERVICE]


def _sudo_user_login_keychain() -> Path | None:
    """Use the interactive user's Keychain when an updater is run by sudo."""
    value = os.environ.get("SUDO_UID", "").strip()
    if not value.isdecimal():
        return None
    try:
        entry = pwd.getpwuid(int(value))
    except (KeyError, OverflowError, ValueError):
        return None
    candidate = Path(entry.pw_dir) / "Library" / "Keychains" / "login.keychain-db"
    return candidate if candidate.is_file() else None


def _load_keychain_secret(keychain: Path | None, *, runner: Runner) -> str:
    args = [*_keychain_args("find-generic-password"), "-w"]
    if keychain is not None:
        args.append(str(keychain))
    try:
        completed = _run_keychain(args, runner=runner)
    except CredentialStoreError:
        return ""
    if completed.returncode != 0:
        return ""
    try:
        return validate_abuse_ch_auth_key(completed.stdout.strip())
    except CredentialValidationError:
        return ""


def _run_keychain(
    args: list[str],
    *,
    runner: Runner,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    if sys.platform != "darwin" or not Path(_SECURITY).is_file():
        raise CredentialStoreError("macOS Keychain is unavailable on this system.")
    try:
        return runner(
            args,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        # Never include process output or input in this exception.
        raise CredentialStoreError("macOS Keychain could not complete the credential operation.") from exc


def _upsert_system_keychain_secret(value: str) -> None:
    """Write one fixed-purpose secret through Security.framework, never argv."""
    if sys.platform != "darwin":
        raise CredentialStoreError("The macOS Security framework is unavailable.")
    try:
        security = CDLL(_SECURITY_FRAMEWORK)
        core_foundation = CDLL(_COREFOUNDATION_FRAMEWORK)
    except OSError as exc:
        raise CredentialStoreError("The macOS Security framework is unavailable.") from exc

    security.SecKeychainOpen.argtypes = [c_char_p, POINTER(c_void_p)]
    security.SecKeychainOpen.restype = c_int32
    security.SecKeychainFindGenericPassword.argtypes = [
        c_void_p, c_uint32, c_char_p, c_uint32, c_char_p,
        POINTER(c_uint32), POINTER(c_void_p), POINTER(c_void_p),
    ]
    security.SecKeychainFindGenericPassword.restype = c_int32
    security.SecKeychainItemModifyAttributesAndData.argtypes = [
        c_void_p, c_void_p, c_uint32, c_void_p,
    ]
    security.SecKeychainItemModifyAttributesAndData.restype = c_int32
    security.SecKeychainAddGenericPassword.argtypes = [
        c_void_p, c_uint32, c_char_p, c_uint32, c_char_p,
        c_uint32, c_void_p, POINTER(c_void_p),
    ]
    security.SecKeychainAddGenericPassword.restype = c_int32
    core_foundation.CFRelease.argtypes = [c_void_p]
    core_foundation.CFRelease.restype = None

    keychain = c_void_p()
    item = c_void_p()
    service = ABUSE_CH_KEYCHAIN_SERVICE.encode("utf-8")
    account = ABUSE_CH_KEYCHAIN_ACCOUNT.encode("utf-8")
    secret = bytearray(value.encode("utf-8"))
    secret_buffer = (c_char_p(bytes(secret)))
    try:
        status = int(security.SecKeychainOpen(os.fsencode(SYSTEM_KEYCHAIN), byref(keychain)))
        if status != 0 or not keychain.value:
            raise CredentialStoreError(f"macOS could not open the System Keychain (OSStatus {status}).")
        status = int(security.SecKeychainFindGenericPassword(
            keychain, len(service), service, len(account), account,
            None, None, byref(item),
        ))
        if status == 0 and item.value:
            status = int(security.SecKeychainItemModifyAttributesAndData(
                item, None, len(secret), secret_buffer,
            ))
        elif status == _ERR_SEC_ITEM_NOT_FOUND:
            status = int(security.SecKeychainAddGenericPassword(
                keychain, len(service), service, len(account), account,
                len(secret), secret_buffer, byref(item),
            ))
        if status != 0:
            raise CredentialStoreError(f"macOS Keychain refused automatic credential provisioning (OSStatus {status}).")
    finally:
        for index in range(len(secret)):
            secret[index] = 0
        if item.value:
            core_foundation.CFRelease(item)
        if keychain.value:
            core_foundation.CFRelease(keychain)


def load_abuse_ch_auth_key(*, runner: Runner = subprocess.run) -> str:
    """Load the Auth-Key from an ephemeral override or macOS Keychain."""
    environment_key = os.environ.get(ABUSE_CH_AUTH_ENV, "").strip()
    if environment_key:
        return validate_abuse_ch_auth_key(environment_key)
    if sys.platform != "darwin" or not Path(_SECURITY).is_file():
        return ""
    login_keychain = _sudo_user_login_keychain()
    # An interactive user or sudo-launched update first uses that user's login
    # Keychain. A launchd root service has no SUDO_UID and must use the
    # administrator-provisioned System Keychain entry instead.
    if os.geteuid() != 0 or login_keychain is not None:
        value = _load_keychain_secret(login_keychain, runner=runner)
        if value:
            return value
    if os.geteuid() == 0 and SYSTEM_KEYCHAIN.is_file():
        return _load_keychain_secret(SYSTEM_KEYCHAIN, runner=runner)
    return ""


def automatic_abuse_ch_credential_status(*, runner: Runner = subprocess.run) -> CredentialStatus:
    """Report only whether the launchd-safe System Keychain credential exists."""
    available = sys.platform == "darwin" and Path(_SECURITY).is_file() and SYSTEM_KEYCHAIN.is_file()
    configured = bool(_load_keychain_secret(SYSTEM_KEYCHAIN, runner=runner)) if available and os.geteuid() == 0 else False
    return CredentialStatus(
        "abuse.ch-automatic",
        available,
        configured,
        "system_keychain" if configured else "none",
        "Automatic feed authentication is provisioned." if configured else (
            "Automatic feed authentication requires administrator setup."
            if available else "The macOS System Keychain is unavailable."
        ),
    )


def abuse_ch_credential_status(*, runner: Runner = subprocess.run) -> CredentialStatus:
    if os.environ.get(ABUSE_CH_AUTH_ENV, "").strip():
        try:
            validate_abuse_ch_auth_key(os.environ[ABUSE_CH_AUTH_ENV])
        except CredentialValidationError:
            return CredentialStatus("abuse.ch", True, False, "environment", "Temporary environment key is invalid.")
        return CredentialStatus("abuse.ch", True, True, "environment", "Configured for this process only.")
    available = sys.platform == "darwin" and Path(_SECURITY).is_file()
    configured = bool(load_abuse_ch_auth_key(runner=runner)) if available else False
    return CredentialStatus(
        "abuse.ch",
        available,
        configured,
        "keychain" if configured else "none",
        "Saved securely in macOS Keychain." if configured else (
            "No Auth-Key is saved." if available else "macOS Keychain is unavailable."
        ),
    )


def save_abuse_ch_auth_key(value: str, *, runner: Runner = subprocess.run) -> CredentialStatus:
    key = validate_abuse_ch_auth_key(value)
    args = _keychain_args("add-generic-password")
    keychain = _sudo_user_login_keychain()
    if keychain is not None:
        args.append(str(keychain))
    args.extend([
        "-U",
        "-l",
        ABUSE_CH_KEYCHAIN_LABEL,
        "-w",
    ])
    # With -w as the final option, security reads the password from stdin. The
    # secret therefore does not appear in argv, process listings, or shell history.
    completed = _run_keychain(args, runner=runner, input_text=f"{key}\n")
    if completed.returncode != 0:
        raise CredentialStoreError(
            f"macOS Keychain refused the credential operation (exit {completed.returncode})."
        )
    return CredentialStatus("abuse.ch", True, True, "keychain", "Saved securely in macOS Keychain.")


def save_automatic_abuse_ch_auth_key(value: str, *, runner: Runner = subprocess.run) -> CredentialStatus:
    """Provision the root launchd updater without placing the secret in argv."""
    if os.geteuid() != 0:
        raise CredentialStoreError("Administrator authorization is required for automatic feed authentication.")
    if not SYSTEM_KEYCHAIN.is_file():
        raise CredentialStoreError("The macOS System Keychain is unavailable.")
    key = validate_abuse_ch_auth_key(value)
    del runner  # Native framework write avoids command arguments and subprocesses.
    _upsert_system_keychain_secret(key)
    key = ""
    return CredentialStatus(
        "abuse.ch-automatic", True, True, "system_keychain", "Automatic feed authentication is provisioned."
    )


def remove_abuse_ch_auth_key(*, runner: Runner = subprocess.run) -> CredentialStatus:
    args = _keychain_args("delete-generic-password")
    keychain = _sudo_user_login_keychain()
    if keychain is not None:
        args.append(str(keychain))
    completed = _run_keychain(args, runner=runner)
    if completed.returncode not in {0, 44}:  # errSecItemNotFound is harmless for removal.
        raise CredentialStoreError(
            f"macOS Keychain refused the credential removal (exit {completed.returncode})."
        )
    return CredentialStatus("abuse.ch", True, False, "none", "No Auth-Key is saved.")


def remove_automatic_abuse_ch_auth_key(*, runner: Runner = subprocess.run) -> CredentialStatus:
    if os.geteuid() != 0:
        raise CredentialStoreError("Administrator authorization is required for automatic feed authentication.")
    args = [*_keychain_args("delete-generic-password"), str(SYSTEM_KEYCHAIN)]
    completed = _run_keychain(args, runner=runner)
    if completed.returncode not in {0, 44}:
        raise CredentialStoreError(
            f"macOS Keychain refused automatic credential removal (exit {completed.returncode})."
        )
    return CredentialStatus(
        "abuse.ch-automatic", True, False, "none", "Automatic feed authentication is not provisioned."
    )
