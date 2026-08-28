"""Commercial-license enforcement for launchd service registration.

The licensing server is intentionally not covered by this gate: it must remain
available so an unlicensed installation can purchase and activate a license.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .manager import LicenseManager
from .storage import LicenseStorage

SERVICE_REGISTRATION_LICENSE_REQUIRED = "LIC_SERVICE_REGISTRATION_REQUIRED"


@dataclass(frozen=True)
class ServiceRegistrationLicenseDecision:
    allowed: bool
    code: str
    message: str
    license_state: str
    activation_mode: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ServiceRegistrationLicenseError(PermissionError):
    def __init__(self, decision: ServiceRegistrationLicenseDecision) -> None:
        self.code = decision.code
        self.decision = decision
        super().__init__(f"{decision.code}: {decision.message}")


def licensing_root_for_home(home: Path) -> Path:
    return Path(home).expanduser() / "Library" / "Application Support" / "MSAA" / "Licensing"


def service_registration_license_decision(
    home: Path,
    *,
    manager: LicenseManager | None = None,
) -> ServiceRegistrationLicenseDecision:
    """Fail closed unless the target user has a valid commercial activation."""
    try:
        license_manager = manager or LicenseManager(
            storage=LicenseStorage(licensing_root_for_home(home))
        )
        status = license_manager.status()
        access = license_manager.product_access(status)
        allowed = bool(access.get("operator_actions_enabled", False))
        if allowed:
            return ServiceRegistrationLicenseDecision(
                allowed=True,
                code="LICENSE_VALID",
                message="The signed product license permits service registration.",
                license_state=status.state.value,
                activation_mode=status.activation_mode,
            )
        reason_code = status.error_code or SERVICE_REGISTRATION_LICENSE_REQUIRED
        return ServiceRegistrationLicenseDecision(
            allowed=False,
            code=reason_code,
            message=(
                "A valid activated MSAA commercial license is required before protection "
                "services can be registered. Complete the $10/month purchase and activation, "
                "then register the services again."
            ),
            license_state=status.state.value,
            activation_mode=status.activation_mode,
        )
    except Exception:  # noqa: BLE001 - a security gate must fail closed on verifier faults
        return ServiceRegistrationLicenseDecision(
            allowed=False,
            code=SERVICE_REGISTRATION_LICENSE_REQUIRED,
            message=(
                "MSAA could not safely verify an activated commercial license, so protection "
                "service registration was blocked."
            ),
            license_state="VERIFICATION_FAILED",
            activation_mode="none",
        )


def require_service_registration_license(home: Path) -> ServiceRegistrationLicenseDecision:
    decision = service_registration_license_decision(home)
    if not decision.allowed:
        raise ServiceRegistrationLicenseError(decision)
    return decision


__all__ = [
    "SERVICE_REGISTRATION_LICENSE_REQUIRED",
    "ServiceRegistrationLicenseDecision",
    "ServiceRegistrationLicenseError",
    "licensing_root_for_home",
    "require_service_registration_license",
    "service_registration_license_decision",
]
