from __future__ import annotations

from mac_audit_agent.integrity.change_authorization import AuthorizedChangeRegistry, AuthorizedChangeRecord
from mac_audit_agent.integrity.signed_manifest import SignedManifest, SignedManifestFileEntry
from mac_audit_agent.integrity.strict_verifier import FileIntegrityChange, IntegrityDiffReport, StrictIntegrityVerifier

__all__ = [
    "AuthorizedChangeRecord",
    "AuthorizedChangeRegistry",
    "FileIntegrityChange",
    "IntegrityDiffReport",
    "SignedManifest",
    "SignedManifestFileEntry",
    "StrictIntegrityVerifier",
]
from mac_audit_agent.integrity.hasher import DEFAULT_EXCLUDED_PATTERNS, calculate_sha256, collect_integrity_files
from mac_audit_agent.integrity.core import IntegrityEngine
from mac_audit_agent.integrity.diff_report import IntegrityDiffReport, IntegrityFileChange, IntegrityState
from mac_audit_agent.integrity.manifest import (
    DEFAULT_EXCLUDED_PATTERNS,
    IntegrityFileEntry,
    IntegrityManifest,
    TrustedManifest,
    create_integrity_manifest,
    load_integrity_manifest,
    write_integrity_manifest,
)
from mac_audit_agent.integrity.verifier import (
    IntegrityVerificationResult,
    verify_integrity_manifest,
)

__all__ = [
    "DEFAULT_EXCLUDED_PATTERNS",
    "IntegrityDiffReport",
    "IntegrityEngine",
    "IntegrityFileChange",
    "IntegrityFileEntry",
    "IntegrityManifest",
    "IntegrityState",
    "IntegrityVerificationResult",
    "TrustedManifest",
    "calculate_sha256",
    "collect_integrity_files",
    "create_integrity_manifest",
    "load_integrity_manifest",
    "verify_integrity_manifest",
    "write_integrity_manifest",
]
