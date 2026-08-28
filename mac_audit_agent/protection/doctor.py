"""Read-only, headless Active Protection diagnostic API."""

from .status import ActiveProtectionStatus, resolve_active_protection_status

__all__ = ["ActiveProtectionStatus", "resolve_active_protection_status"]
