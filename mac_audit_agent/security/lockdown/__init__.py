"""MSAA Emergency Protection Mode (not Apple's Lockdown Mode)."""

from .lockdown_manager import LockdownManager
from .lockdown_policy import FEATURE_ID, PRODUCT_NAME, load_profile

__all__ = ["FEATURE_ID", "PRODUCT_NAME", "LockdownManager", "load_profile"]
