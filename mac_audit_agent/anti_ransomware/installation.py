from __future__ import annotations

import os
import subprocess
import sys
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable

from mac_audit_agent.compat.python_features import tomllib


DEFAULT_PACKAGE_NAME = "MSAAActiveContainment.pkg"


@dataclass(frozen=True)
class ActiveProtectionInstallOffer:
    status: str
    package_path: str
    package_exists: bool
    package_signature_valid: bool
    expected_team_id_configured: bool
    expected_team_id: str
    gatekeeper_accepted: bool
    ready_to_open_installer: bool
    administrator_approval_required: bool
    automatic_install_performed: bool
    message: str
    next_action: str
    verification_commands: tuple[str, ...]
    blocked_by: tuple[str, ...]

    def to_dict(self) -> dict:
        return asdict(self)


def _run(argv: list[str]):
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=15, check=False)
    except (OSError, subprocess.SubprocessError):
        return None


def package_candidates(root: Path | None = None) -> tuple[Path, ...]:
    candidates: list[Path] = []
    configured = os.environ.get("MSAA_ACTIVE_PROTECTION_PACKAGE", "").strip()
    if configured:
        candidates.append(Path(configured).expanduser())
    if getattr(sys, "frozen", False):
        executable = Path(sys.executable).resolve(strict=False)
        candidates.extend(
            (
                executable.parents[1] / "Resources" / DEFAULT_PACKAGE_NAME,
                executable.parent / DEFAULT_PACKAGE_NAME,
            )
        )
    source_root = Path(root or Path(__file__).parents[2]).resolve(strict=False)
    candidates.extend(
        (
            source_root / "dist" / "active-containment" / DEFAULT_PACKAGE_NAME,
            source_root / "packaging" / "anti_ransomware" / DEFAULT_PACKAGE_NAME,
        )
    )
    unique: list[Path] = []
    for candidate in candidates:
        resolved = candidate.resolve(strict=False)
        if resolved not in unique:
            unique.append(resolved)
    return tuple(unique)


def expected_team_id(root: Path | None = None) -> str:
    configured = os.environ.get("MSAA_TEAM_ID", "").strip().upper()
    if not configured:
        config = Path(root or Path(__file__).parents[2]) / "config" / "apple_product_identifiers.toml"
        try:
            if tomllib is None:
                raise ValueError("TOML parsing is unavailable on this runtime")
            configured = str(tomllib.loads(config.read_text(encoding="utf-8")).get("team_id", "")).strip().upper()
        except (OSError, ValueError):
            configured = ""
    return configured if re.fullmatch(r"[A-Z0-9]{10}", configured) else ""


def inspect_install_offer(
    package_path: Path | None = None,
    *,
    root: Path | None = None,
    runner: Callable[[list[str]], object | None] = _run,
) -> ActiveProtectionInstallOffer:
    candidates = (Path(package_path).expanduser().resolve(strict=False),) if package_path else package_candidates(root)
    package = next((item for item in candidates if item.is_file()), candidates[0] if candidates else Path(DEFAULT_PACKAGE_NAME))
    team_id = expected_team_id(root)
    exists = package.is_file() and package.suffix.lower() == ".pkg"
    signature_valid = False
    gatekeeper_accepted = False
    blocked: list[str] = []
    if exists:
        signature = runner(["/usr/sbin/pkgutil", "--check-signature", str(package)])
        signature_text = ((getattr(signature, "stdout", "") or "") + (getattr(signature, "stderr", "") or "")).lower()
        signature_valid = bool(
            signature
            and getattr(signature, "returncode", 1) == 0
            and "developer id installer" in signature_text
            and bool(team_id)
            and f"({team_id.lower()})" in signature_text
        )
        gatekeeper = runner(["/usr/sbin/spctl", "--assess", "--type", "install", "--verbose=4", str(package)])
        gatekeeper_accepted = bool(gatekeeper and getattr(gatekeeper, "returncode", 1) == 0)
    else:
        blocked.append("signed_install_package_missing")
    if not team_id:
        blocked.append("production_team_id_not_configured")
    if exists and not signature_valid:
        blocked.append("developer_id_installer_signature_invalid")
    if exists and signature_valid and not gatekeeper_accepted:
        blocked.append("gatekeeper_or_notarization_not_accepted")
    ready = exists and signature_valid and gatekeeper_accepted and sys.platform == "darwin"
    if sys.platform != "darwin":
        blocked.append("macos_required")
    if ready:
        message = "The verified MSAA active-protection package is ready. Apple Installer will request administrator approval before making changes."
        next_action = "Open the verified package in Apple Installer, review its signature, approve installation, then run the protection readiness check."
        status = "ready_to_install"
    elif not exists:
        message = "Active protection is not installed and no verified release package is available in this build."
        next_action = "Obtain the Developer-ID-signed and notarized MSAA active-protection package from the project release engineer."
        status = "package_required"
    else:
        message = "An active-protection package was found, but its release trust checks did not pass. It will not be opened."
        next_action = "Ask the release engineer to sign with Developer ID Installer, notarize, staple, and re-verify the package."
        status = "package_rejected"
    quoted = f'"{package}"'
    return ActiveProtectionInstallOffer(
        status=status,
        package_path=str(package),
        package_exists=exists,
        package_signature_valid=signature_valid,
        expected_team_id_configured=bool(team_id),
        expected_team_id=team_id,
        gatekeeper_accepted=gatekeeper_accepted,
        ready_to_open_installer=ready,
        administrator_approval_required=True,
        automatic_install_performed=False,
        message=message,
        next_action=next_action,
        verification_commands=(
            f"pkgutil --check-signature {quoted}",
            f"spctl --assess --type install --verbose=4 {quoted}",
            "msaa anti-ransomware status --json",
        ),
        blocked_by=tuple(blocked),
    )


def open_verified_installer(
    package_path: Path,
    *,
    root: Path | None = None,
    runner: Callable[[list[str]], object | None] = _run,
    opener: Callable[[list[str]], object | None] = _run,
) -> ActiveProtectionInstallOffer:
    offer = inspect_install_offer(package_path, root=root, runner=runner)
    if not offer.ready_to_open_installer:
        return offer
    opened = opener(["/usr/bin/open", str(Path(offer.package_path))])
    if not opened or getattr(opened, "returncode", 1) != 0:
        return ActiveProtectionInstallOffer(
            **{
                **offer.to_dict(),
                "status": "installer_open_failed",
                "ready_to_open_installer": False,
                "message": "The verified package passed trust checks, but Apple Installer could not be opened.",
                "next_action": f'Open the package manually in Finder: "{offer.package_path}"',
                "blocked_by": ("apple_installer_open_failed",),
            }
        )
    return ActiveProtectionInstallOffer(
        **{
            **offer.to_dict(),
            "status": "installer_opened",
            "message": "The verified package was opened in Apple Installer. Installation is not complete until administrator approval and live readiness verification succeed.",
            "next_action": "Complete Apple Installer, approve required system extension and privacy prompts, then run the protection readiness check.",
        }
    )


__all__ = ["ActiveProtectionInstallOffer", "expected_team_id", "inspect_install_offer", "open_verified_installer", "package_candidates"]
