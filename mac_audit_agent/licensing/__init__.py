"""Signed MSAA product licensing and activation services."""

from .manager import LicenseManager
from .models import LicenseFeature, LicenseState, LicenseStatus

__all__ = ["LicenseFeature", "LicenseManager", "LicenseState", "LicenseStatus"]
