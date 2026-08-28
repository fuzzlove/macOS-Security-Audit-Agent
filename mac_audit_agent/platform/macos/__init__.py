"""macOS-specific platform adapters."""

from .launchd_service import LaunchdDomainType, LaunchdServiceLocation, LaunchdServiceManager

__all__ = ["LaunchdDomainType", "LaunchdServiceLocation", "LaunchdServiceManager"]
