from __future__ import annotations

import hashlib
import json
import platform
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from mac_audit_agent.compat.datetime_compat import utc_now

from mac_audit_agent.integrity.manifest_paths import integrity_manifest_paths


PROJECT_SALT = "msaa-developer-machine-integrity-v1"


@dataclass(slots=True)
class DeveloperMachineIdentity:
    developer_machine_id: str
    developer_name: str
    organization: str
    machine_label: str
    machine_fingerprint: str
    hardware_uuid_hash: str
    boot_volume_uuid_hash: str = ""
    platform_serial_hash: str = ""
    macos_version_at_enrollment: str = ""
    architecture: str = ""
    enrolled_at: str = ""
    enrolled_by: str = ""
    signing_key_label: str = ""
    public_key_pem: str = ""
    public_key_fingerprint_sha256: str = ""
    secure_enclave_backed: bool = False
    keychain_backed: bool = False
    trust_status: str = "active"
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class TrustedDeveloperMachineRegistry:
    registry_version: str = "1"
    generated_at: str = ""
    trusted_machines: list[DeveloperMachineIdentity] = field(default_factory=list)
    limitations: list[str] = field(default_factory=lambda: [
        "Developer-machine signing is local trust metadata, not proof of physical possession.",
        "This model does not protect against a fully compromised enrolled developer machine.",
        "This is readiness/evidence support and is not a claim of CISA, DoD, CMMC, or NIST certification.",
    ])

    def active_machines(self) -> list[DeveloperMachineIdentity]:
        return [machine for machine in self.trusted_machines if machine.trust_status == "active"]

    def find(self, developer_machine_id: str) -> DeveloperMachineIdentity | None:
        for machine in self.trusted_machines:
            if machine.developer_machine_id == developer_machine_id:
                return machine
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "registry_version": self.registry_version,
            "generated_at": self.generated_at,
            "trusted_machines": [machine.to_dict() for machine in self.trusted_machines],
            "limitations": list(self.limitations),
        }


def utc_now_iso() -> str:
    return utc_now().replace(microsecond=0).isoformat().replace("+00:00", "Z")


def trusted_developer_machines_path(root: Path | None = None) -> Path:
    return integrity_manifest_paths(root).canonical_trusted_developer_machines


def load_trusted_developer_machines(root: Path | None = None, path: Path | None = None) -> TrustedDeveloperMachineRegistry:
    registry_path = Path(path) if path else trusted_developer_machines_path(root)
    if not registry_path.exists():
        return TrustedDeveloperMachineRegistry(generated_at=utc_now_iso())
    payload = json.loads(registry_path.read_text(encoding="utf-8"))
    machines = [DeveloperMachineIdentity(**item) for item in payload.get("trusted_machines", []) if isinstance(item, dict)]
    return TrustedDeveloperMachineRegistry(
        registry_version=str(payload.get("registry_version", "1")),
        generated_at=str(payload.get("generated_at", "")),
        trusted_machines=machines,
        limitations=list(payload.get("limitations", [])) or TrustedDeveloperMachineRegistry().limitations,
    )


def write_trusted_developer_machines(registry: TrustedDeveloperMachineRegistry, root: Path | None = None, path: Path | None = None) -> Path:
    registry_path = Path(path) if path else trusted_developer_machines_path(root)
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    registry.generated_at = utc_now_iso()
    registry_path.write_text(json.dumps(registry.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return registry_path


def current_machine_fingerprint() -> dict[str, str]:
    hardware_uuid = _ioreg_value("IOPlatformUUID")
    boot_uuid = _diskutil_boot_volume_uuid()
    serial = _ioreg_value("IOPlatformSerialNumber")
    architecture = platform.machine() or "unknown"
    macos_version = platform.mac_ver()[0] or platform.platform()
    components = {
        "hardware_uuid_hash": _hash_identifier("hardware_uuid", hardware_uuid),
        "boot_volume_uuid_hash": _hash_identifier("boot_volume_uuid", boot_uuid),
        "platform_serial_hash": _hash_identifier("platform_serial", serial),
        "architecture": architecture,
        "macos_version": macos_version,
    }
    fingerprint_basis = "|".join([components["hardware_uuid_hash"], components["boot_volume_uuid_hash"], architecture, macos_version.split(".")[0]])
    components["machine_fingerprint"] = _hash_identifier("machine_fingerprint", fingerprint_basis)
    return components


def create_developer_machine_identity(
    *,
    developer: str,
    organization: str,
    machine_label: str,
    public_key_pem: str,
    public_key_fingerprint_sha256: str,
    enrolled_by: str = "",
    signing_key_label: str = "",
    secure_enclave_backed: bool = False,
    keychain_backed: bool = False,
) -> DeveloperMachineIdentity:
    fingerprint = current_machine_fingerprint()
    developer_machine_id = fingerprint["machine_fingerprint"][:24]
    return DeveloperMachineIdentity(
        developer_machine_id=developer_machine_id,
        developer_name=developer,
        organization=organization,
        machine_label=machine_label,
        machine_fingerprint=fingerprint["machine_fingerprint"],
        hardware_uuid_hash=fingerprint["hardware_uuid_hash"],
        boot_volume_uuid_hash=fingerprint["boot_volume_uuid_hash"],
        platform_serial_hash=fingerprint["platform_serial_hash"],
        macos_version_at_enrollment=fingerprint["macos_version"],
        architecture=fingerprint["architecture"],
        enrolled_at=utc_now_iso(),
        enrolled_by=enrolled_by or developer,
        signing_key_label=signing_key_label,
        public_key_pem=public_key_pem,
        public_key_fingerprint_sha256=public_key_fingerprint_sha256,
        secure_enclave_backed=secure_enclave_backed,
        keychain_backed=keychain_backed,
        trust_status="active",
        limitations=[
            "Machine fingerprint values are salted SHA-256 hashes; raw serial and UUID values are not stored.",
            "Developer-machine signing cannot protect against a compromised enrolled developer machine.",
        ],
    )


def current_machine_matches(identity: DeveloperMachineIdentity) -> bool:
    current = current_machine_fingerprint()
    if current.get("machine_fingerprint") == identity.machine_fingerprint:
        return True

    # Headless/sandboxed macOS contexts can deny DiskManagement access, which
    # makes the boot volume UUID unavailable even on the enrolled hardware.
    # Keep signing closed for different hardware, but do not reject the same
    # machine solely because that volatile signal could not be read.
    boot_uuid_unavailable = current.get("boot_volume_uuid_hash") == _hash_identifier("boot_volume_uuid", "")
    stable_hardware_matches = (
        current.get("hardware_uuid_hash") == identity.hardware_uuid_hash
        and current.get("platform_serial_hash") == identity.platform_serial_hash
        and current.get("architecture") == identity.architecture
    )
    return bool(boot_uuid_unavailable and stable_hardware_matches)


def revoke_developer_machine(root: Path, developer_machine_id: str, reason: str = "") -> DeveloperMachineIdentity | None:
    registry = load_trusted_developer_machines(root)
    machine = registry.find(developer_machine_id)
    if machine is None:
        return None
    machine.trust_status = "revoked"
    machine.limitations.append(f"Revoked at {utc_now_iso()}: {reason or 'no reason recorded'}")
    write_trusted_developer_machines(registry, root)
    return machine


def _hash_identifier(label: str, value: str) -> str:
    normalized = value.strip() or "unavailable"
    return hashlib.sha256(f"{PROJECT_SALT}:{label}:{normalized}".encode("utf-8")).hexdigest()


def _ioreg_value(key: str) -> str:
    try:
        result = subprocess.run(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"], text=True, capture_output=True, check=False, timeout=5)
    except Exception:
        return ""
    for line in result.stdout.splitlines():
        marker = f'"{key}" = '
        if marker in line:
            return line.split(marker, 1)[1].strip().strip('"')
    return ""


def _diskutil_boot_volume_uuid() -> str:
    try:
        result = subprocess.run(["diskutil", "info", "/"], text=True, capture_output=True, check=False, timeout=5)
    except Exception:
        return ""
    for line in result.stdout.splitlines():
        if "Volume UUID:" in line:
            return line.split(":", 1)[1].strip()
    return ""


__all__ = [
    "DeveloperMachineIdentity",
    "TrustedDeveloperMachineRegistry",
    "create_developer_machine_identity",
    "current_machine_fingerprint",
    "current_machine_matches",
    "load_trusted_developer_machines",
    "revoke_developer_machine",
    "trusted_developer_machines_path",
    "write_trusted_developer_machines",
]
