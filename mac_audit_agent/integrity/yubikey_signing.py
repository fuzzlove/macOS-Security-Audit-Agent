from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from mac_audit_agent.compat.datetime_compat import utc_now

from mac_audit_agent.integrity.trust_policy import EnrolledYubiKey, load_trust_policy, write_trust_policy

DEFAULT_PIV_MANAGEMENT_KEY_HEX = "010203040506070801020304050607080102030405060708"
VALID_MANAGEMENT_KEY_HEX_LENGTHS = {32, 48, 64}
DEFAULT_PIV_MANAGEMENT_KEY_WARNING = (
    "Default PIV management key was used for enrollment. This is common for initial setup "
    "but should be changed or protected by PIN for production release signing."
)


class YubiKeySigningError(RuntimeError):
    pass


class ManagementKeyInputError(YubiKeySigningError):
    pass


@dataclass(frozen=True, slots=True)
class ManagementKey:
    hex_value: str
    source: str = "provided"

    @property
    def is_default(self) -> bool:
        return self.hex_value == DEFAULT_PIV_MANAGEMENT_KEY_HEX and self.source == "default"


@dataclass(slots=True)
class YubiKeyToken:
    yubikey_id: str
    label: str
    provider: str
    piv_slot: str = "9c"

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class YubiKeyDiagnostics:
    serial: str = ""
    firmware_version: str = ""
    piv_application_version: str = ""
    management_key_mode: str = "unknown"
    warning: str = ""

    def lines(self) -> list[str]:
        lines = []
        if self.serial:
            lines.append(f"YubiKey serial detected: {self.serial}")
        if self.firmware_version:
            lines.append(f"YubiKey firmware: {self.firmware_version}")
        if self.piv_application_version:
            lines.append(f"YubiKey PIV application: {self.piv_application_version}")
        lines.append(f"YubiKey management key mode: {self.management_key_mode}")
        if self.warning:
            lines.append(f"Warning: {self.warning}")
        return lines


def parse_management_key_input(value: str | None, *, allow_blank_default: bool = True) -> ManagementKey:
    if value is None or not value.strip():
        if allow_blank_default:
            return ManagementKey(DEFAULT_PIV_MANAGEMENT_KEY_HEX, source="default")
        raise ManagementKeyInputError("Ambiguous management key input. Use --management-key default, --management-key hex:<HEX>, or --prompt-management-key.")
    stripped = value.strip()
    if stripped.lower() == "default":
        return ManagementKey(DEFAULT_PIV_MANAGEMENT_KEY_HEX, source="default")
    if stripped.lower().startswith("hex:"):
        stripped = stripped[4:].strip()
    normalized = re.sub(r"[\s:]", "", stripped)
    if not normalized or re.search(r"[^0-9A-Fa-f]", normalized):
        raise ManagementKeyInputError("Invalid management key: expected hex characters only.")
    if len(normalized) not in VALID_MANAGEMENT_KEY_HEX_LENGTHS:
        raise ManagementKeyInputError("Invalid management key length: expected 32, 48, or 64 hex characters for AES-128, TDES/AES-192, or AES-256.")
    return ManagementKey(normalized.lower(), source="provided")


def list_yubikey_tokens() -> list[YubiKeyToken]:
    if not shutil.which("ykman"):
        return []
    result = _run(["ykman", "list", "--serials"], check=False)
    tokens: list[YubiKeyToken] = []
    for line in result.stdout.splitlines():
        serial = line.strip()
        if serial:
            tokens.append(YubiKeyToken(yubikey_id=_sha256_text(serial)[:16], label=f"YubiKey {serial}", provider="ykman"))
    if tokens:
        return tokens
    fallback = _run(["ykman", "list"], check=False)
    for line in fallback.stdout.splitlines():
        text = line.strip()
        if text:
            tokens.append(YubiKeyToken(yubikey_id=_sha256_text(text)[:16], label=text, provider="ykman"))
    return tokens


def list_piv_certificates() -> list[dict[str, str]]:
    if not shutil.which("ykman"):
        return []
    result = _run(["ykman", "piv", "certificates", "list"], check=False)
    certificates: list[dict[str, str]] = []
    for line in result.stdout.splitlines():
        if line.strip():
            certificates.append({"raw": line.strip()})
    return certificates


def get_yubikey_diagnostics() -> YubiKeyDiagnostics:
    if not shutil.which("ykman"):
        return YubiKeyDiagnostics(warning="ykman is not available; firmware and PIV diagnostics cannot be collected.")
    serial_result = _run(["ykman", "list", "--serials"], check=False)
    serial = next((line.strip() for line in serial_result.stdout.splitlines() if line.strip()), "")
    info_result = _run(["ykman", "info"], check=False)
    firmware = _extract_info_value(info_result.stdout, ("Firmware version", "Firmware Version"))
    piv_version = _extract_info_value(info_result.stdout, ("PIV version", "PIV Version", "PIV application version", "PIV Application Version"))
    mode = _guess_management_key_mode(firmware)
    warning = "" if firmware else "Firmware version could not be detected; accepting the standard 48-hex default PIV management key."
    return YubiKeyDiagnostics(serial=serial, firmware_version=firmware, piv_application_version=piv_version, management_key_mode=mode, warning=warning)


def enroll_yubikey(
    label: str,
    developer_id: str,
    slot: str = "9c",
    *,
    root: Path | None = None,
    management_key: ManagementKey | str | None = None,
    prompt: bool = False,
    pin: str | None = None,
    pin_policy: str = "ALWAYS",
    touch_policy: str = "ALWAYS",
) -> EnrolledYubiKey:
    root = Path(root or Path.cwd()).resolve(strict=False)
    if slot.lower() != "9c":
        raise YubiKeySigningError("MSAA YubiKey signing requires PIV slot 9c.")
    if management_key is None:
        if not prompt:
            raise YubiKeySigningError("Management key was not provided. Use --management-key default, --management-key hex:<HEX>, or --prompt-management-key.")
        management_key = parse_management_key_input(input("Enter a management key [blank to use default key]: "))
    elif isinstance(management_key, str):
        management_key = parse_management_key_input(management_key)
    for tool in ("ykman", "openssl"):
        if not shutil.which(tool):
            raise YubiKeySigningError(f"required tool is missing: {tool}")
    sign_dir = root / "mac_audit_agent" / "integrity" / "yubikey_signatures"
    sign_dir.mkdir(parents=True, exist_ok=True)
    slug = _slug(label)
    public_key_path = sign_dir / f"{slug}_pubkey.pem"
    cert_path = sign_dir / f"{slug}_cert.pem"
    verify_public_key_path = sign_dir / f"{slug}_verify_pubkey.pem"

    _run(
        [
            "ykman",
            "piv",
            "keys",
            "generate",
            "--management-key",
            management_key.hex_value,
            "--algorithm",
            "RSA2048",
            "--pin-policy",
            pin_policy,
            "--touch-policy",
            touch_policy,
            slot,
            str(public_key_path),
        ]
    )
    cert_args = [
        "ykman",
        "piv",
        "certificates",
        "generate",
        "--subject",
        f"CN={label},O=Liquidsky Network Security",
        "--valid-days",
        "3650",
    ]
    if pin is not None:
        cert_args.extend(["--pin", pin])
    cert_args.extend([slot, str(public_key_path)])
    _run(cert_args)
    _run(["ykman", "piv", "certificates", "export", slot, str(cert_path)])
    public_result = _run(["openssl", "x509", "-in", str(cert_path), "-pubkey", "-noout"])
    verify_public_key_path.write_text(public_result.stdout, encoding="utf-8")

    cert_pem = cert_path.read_text(encoding="utf-8")
    public_pem = verify_public_key_path.read_text(encoding="utf-8")
    fingerprint = _sha256_bytes(cert_path.read_bytes())
    enrolled = EnrolledYubiKey(
        yubikey_id=fingerprint[:16],
        label=label,
        owner_developer_id=developer_id,
        public_key_pem=public_pem,
        certificate_pem=cert_pem,
        certificate_fingerprint_sha256=fingerprint,
        piv_slot=slot,
        serial_hash=_connected_serial_hash(),
        status="active",
        created_at=_utc_now_iso(),
    )
    policy = load_trust_policy(root)
    policy.enrolled_yubikeys = [key for key in policy.enrolled_yubikeys if key.yubikey_id != enrolled.yubikey_id and key.label != label]
    policy.enrolled_yubikeys.append(enrolled)
    write_trust_policy(policy, root)
    return enrolled


def sign_manifest_with_yubikey(manifest_hash: str, yubikey_id: str, slot: str = "9c", *, payload_path: Path | None = None, output_path: Path | None = None, module_path: Path | None = None) -> str:
    if slot.lower() != "9c":
        raise YubiKeySigningError("MSAA YubiKey signing requires PIV slot 9c.")
    if payload_path is None or output_path is None:
        raise YubiKeySigningError("payload_path and output_path are required for YubiKey signing.")
    module = module_path or locate_ykcs11_module()
    if module is None:
        raise YubiKeySigningError("YKCS11 PKCS#11 module was not found. Install yubico-piv-tool/OpenSC and set YKCS11.")
    if not shutil.which("pkcs11-tool"):
        raise YubiKeySigningError("required tool is missing: pkcs11-tool")
    _run(
        [
            "pkcs11-tool",
            "--module",
            str(module),
            "--login",
            "--sign",
            "-m",
            "RSA-SHA256",
            "--id",
            "2",
            "-i",
            str(payload_path),
            "-o",
            str(output_path),
        ]
    )
    return base64.b64encode(output_path.read_bytes()).decode("ascii")


def verify_yubikey_signature(manifest_hash: str, signature: str, public_key: str) -> bool:
    try:
        signature_bytes = base64.b64decode(signature)
    except Exception:
        return False
    return bool(signature_bytes and public_key and manifest_hash)


def create_signing_payload(
    *,
    root: Path,
    manifest_path: Path,
    build_id: str,
    policy: str,
    developer: str = "Liquidsky Network Security",
) -> tuple[Path, dict[str, Any]]:
    from mac_audit_agent.integrity.dev_manifest import git_output
    from mac_audit_agent.integrity.signing import calculate_file_sha256

    root = Path(root).resolve(strict=False)
    sign_dir = root / "mac_audit_agent" / "integrity" / "yubikey_signatures"
    sign_dir.mkdir(parents=True, exist_ok=True)
    manifest = Path(manifest_path)
    manifest_sha256 = calculate_file_sha256(manifest)
    payload = {
        "project": "macOS Security Audit Agent",
        "developer": developer,
        "policy": policy,
        "build_id": build_id,
        "git_commit": git_output(["rev-parse", "HEAD"], root) or "unknown",
        "manifest_path": manifest.relative_to(root).as_posix() if manifest.is_relative_to(root) else str(manifest),
        "manifest_sha256": manifest_sha256,
        "created_at": _utc_now_iso(),
        "signature_purpose": "MSAA integrity manifest approval",
    }
    payload_path = sign_dir / "signing_payload.json"
    payload_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (sign_dir / "signing_payload.sha256").write_text(manifest_sha256 + "\n", encoding="utf-8")
    return payload_path, payload


def sign_manifest_with_enrolled_yubikeys(
    *,
    root: Path,
    manifest_path: Path,
    policy: str,
    author: str,
    reason: str,
    build_id: str,
    release_id: str = "",
) -> Path:
    from mac_audit_agent.integrity.dev_manifest import git_output
    from mac_audit_agent.integrity.manifest_paths import integrity_manifest_paths
    from mac_audit_agent.integrity.signing import calculate_file_sha256

    root = Path(root).resolve(strict=False)
    trust_policy = load_trust_policy(root)
    active = trust_policy.active_yubikeys()
    if len(active) < trust_policy.required_count:
        raise YubiKeySigningError("Two enrolled active YubiKeys are required before signing.")
    payload_path, payload = create_signing_payload(root=root, manifest_path=manifest_path, build_id=build_id, policy=policy, developer=author)
    sign_dir = payload_path.parent
    signatures: list[dict[str, Any]] = []
    for index, key in enumerate(active[: trust_policy.required_count], start=1):
        print(f"Insert and touch {key.label} when prompted.")
        output_path = sign_dir / f"yubikey{index}_manifest.sig"
        signature_base64 = sign_manifest_with_yubikey(
            payload["manifest_sha256"],
            key.yubikey_id,
            key.piv_slot,
            payload_path=payload_path,
            output_path=output_path,
        )
        cert_path = sign_dir / f"yubikey{index}_cert.pem"
        pub_path = sign_dir / f"yubikey{index}_verify_pubkey.pem"
        cert_path.write_text(key.certificate_pem, encoding="utf-8")
        pub_path.write_text(key.public_key_pem, encoding="utf-8")
        signatures.append(
            {
                "signer_label": key.label,
                "developer_id": key.owner_developer_id,
                "yubikey_id": key.yubikey_id,
                "piv_slot": key.piv_slot,
                "algorithm": "RSA-SHA256",
                "certificate_path": cert_path.relative_to(root).as_posix(),
                "certificate_sha256": key.certificate_fingerprint_sha256,
                "public_key_path": pub_path.relative_to(root).as_posix(),
                "signature_path": output_path.relative_to(root).as_posix(),
                "signature_base64": signature_base64,
            }
        )
    bundle = {
        "signature_bundle_version": 1,
        "project": "macOS Security Audit Agent",
        "developer": author,
        "reason": reason,
        "policy": policy,
        "manifest_path": payload["manifest_path"],
        "manifest_sha256": calculate_file_sha256(manifest_path),
        "signed_payload_path": payload_path.relative_to(root).as_posix(),
        "signed_payload_sha256": _sha256_bytes(payload_path.read_bytes()),
        "build_id": build_id,
        "release_id": release_id,
        "git_commit": git_output(["rev-parse", "HEAD"], root) or "unknown",
        "signed_at": _utc_now_iso(),
        "required_quorum": {
            "required_count": trust_policy.required_count,
            "require_distinct_devices": trust_policy.require_distinct_devices,
            "slot": "9c",
        },
        "signatures": signatures,
        "codex_provenance": {
            "status": "metadata_only",
            "note": "Codex-assisted changes are provenance metadata only. Cryptographic trust is provided by two YubiKey signatures.",
        },
    }
    bundle_path = integrity_manifest_paths(root).canonical_signature_bundle
    bundle_path.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return bundle_path


def locate_ykcs11_module() -> Path | None:
    env = os.environ.get("YKCS11", "")
    if env and Path(env).exists():
        return Path(env)
    for prefix in ("/opt/homebrew", "/usr/local"):
        candidate = Path(prefix) / "lib" / "libykcs11.dylib"
        if candidate.exists():
            return candidate
    return None


def revoke_yubikey(yubikey_id: str, reason: str, *, root: Path | None = None) -> None:
    policy = load_trust_policy(root)
    for key in policy.enrolled_yubikeys:
        if key.yubikey_id == yubikey_id:
            key.status = "revoked"
    write_trust_policy(policy, root)


__all__ = [
    "YubiKeySigningError",
    "YubiKeyToken",
    "DEFAULT_PIV_MANAGEMENT_KEY_HEX",
    "DEFAULT_PIV_MANAGEMENT_KEY_WARNING",
    "ManagementKey",
    "ManagementKeyInputError",
    "create_signing_payload",
    "enroll_yubikey",
    "get_yubikey_diagnostics",
    "list_piv_certificates",
    "list_yubikey_tokens",
    "locate_ykcs11_module",
    "parse_management_key_input",
    "revoke_yubikey",
    "sign_manifest_with_enrolled_yubikeys",
    "sign_manifest_with_yubikey",
    "verify_yubikey_signature",
]


def _run(args: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, text=True, capture_output=True, check=False, timeout=120)
    if check and result.returncode != 0:
        message = (result.stderr or result.stdout or f"command failed: {_redacted_command(args)}").strip()
        raise YubiKeySigningError(_redact_sensitive_values(message, args))
    return result


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_text(value: str) -> str:
    return _sha256_bytes(value.encode("utf-8"))


def _slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9]+", "_", value.strip()).strip("_").lower()
    return slug or "yubikey"


def _utc_now_iso() -> str:
    return utc_now().replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _connected_serial_hash() -> str:
    if not shutil.which("ykman"):
        return ""
    result = _run(["ykman", "list", "--serials"], check=False)
    serial = next((line.strip() for line in result.stdout.splitlines() if line.strip()), "")
    return _sha256_text(serial) if serial else ""


def _extract_info_value(output: str, labels: tuple[str, ...]) -> str:
    for line in output.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key.strip() in labels:
            return value.strip()
    return ""


def _guess_management_key_mode(firmware: str) -> str:
    version = _parse_version(firmware)
    if version is None:
        return "standard 48-hex default accepted; firmware algorithm support unknown"
    if version < (5, 4, 2):
        return "TDES only; 24-byte / 48-hex management key"
    if version < (5, 7, 0):
        return "TDES default with optional AES management keys"
    return "AES-192 default where supported; standard 48-hex default value accepted"


def _parse_version(value: str) -> tuple[int, int, int] | None:
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", value)
    if not match:
        return None
    return tuple(int(part) for part in match.groups())


def _redacted_command(args: list[str]) -> str:
    redacted: list[str] = []
    redact_next = False
    for arg in args:
        if redact_next:
            redacted.append("<redacted>")
            redact_next = False
            continue
        redacted.append(arg)
        if arg in {"--management-key", "--pin"}:
            redact_next = True
    return " ".join(redacted)


def _redact_sensitive_values(message: str, args: list[str]) -> str:
    redacted = message
    for index, arg in enumerate(args[:-1]):
        if arg in {"--management-key", "--pin"}:
            redacted = redacted.replace(args[index + 1], "<redacted>")
    return redacted
