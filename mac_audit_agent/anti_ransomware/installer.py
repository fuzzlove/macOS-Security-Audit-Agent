"""Canonical anti-ransomware aliases for Active Protection installation."""

from mac_audit_agent.protection.installer import ActiveProtectionInstallOptions, install_active_protection
from mac_audit_agent.protection.repair import ActiveProtectionRepairOptions, repair_active_protection
from mac_audit_agent.protection.status import resolve_active_protection_status

__all__ = ["ActiveProtectionInstallOptions", "ActiveProtectionRepairOptions", "install_active_protection",
           "repair_active_protection", "resolve_active_protection_status"]
