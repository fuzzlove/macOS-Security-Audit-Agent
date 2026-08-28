"""Headless active-protection installation, repair, and status APIs."""

from .status import ActiveProtectionStatus, resolve_active_protection_status

__all__ = ["ActiveProtectionStatus", "resolve_active_protection_status"]
