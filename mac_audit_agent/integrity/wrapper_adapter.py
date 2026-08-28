from __future__ import annotations

import os
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from mac_audit_agent.integrity.authority import IntegrityAuthority
from mac_audit_agent.integrity.result_cache import build_current_integrity_status, cache_is_stale, read_current_integrity_status


def default_wrapper_policy(policy: str | None = None) -> str:
    if policy:
        return policy
    configured = os.environ.get("MSAA_INTEGRITY_POLICY") or os.environ.get("MSAA_RELEASE_POLICY")
    if configured:
        return configured
    # Displayed integrity must describe the shipped/public trust policy unless
    # a caller explicitly selects a development policy.  Previously source-mode
    # GUI wrappers silently selected ``dev`` while the CLI was explicitly
    # verifying ``public_release``, producing contradictory status cards.
    return "public_release"


@dataclass(slots=True)
class WrapperIntegrityStatus:
    consumer: str
    policy: str
    status: str
    trust_state: str
    result_code: str
    failure_code: str
    manifest_path: str
    signature_path: str
    manifest_sha256: str
    signature_valid: bool | None
    release_id: str = ""
    build_id: str = ""
    git_commit: str = ""
    signing_key_fingerprint: str = ""
    developer_machine_id: str = ""
    source_modified_files: list[str] = field(default_factory=list)
    missing_files: list[str] = field(default_factory=list)
    extra_files: list[str] = field(default_factory=list)
    generated_modified_files: list[str] = field(default_factory=list)
    pre_uat_compatible: bool = False
    recommended_action: str = ""
    reason: str = ""
    module_path: str = ""
    source_file: str = ""
    cache_status: str = "not_loaded"
    cache_stale: bool = True
    cache: dict[str, Any] = field(default_factory=dict)
    authority: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def modified_files(self) -> list[str]:
        return self.source_modified_files

    @property
    def canonical_manifest_path(self) -> str:
        return self.manifest_path

    @property
    def canonical_manifest_used(self) -> bool:
        return bool(self.authority.get("canonical_manifest_used", True))

    @property
    def policy_mode(self) -> str:
        return self.policy

    @property
    def details(self) -> dict[str, Any]:
        value = self.authority.get("details", {})
        return value if isinstance(value, dict) else {}

    @property
    def signer_status(self) -> list[dict[str, Any]]:
        value = self.authority.get("signer_status", [])
        return value if isinstance(value, list) else []


class IntegrityWrapperAdapter:
    def __init__(self, root: Path | None = None) -> None:
        self.root = Path(root or Path.cwd()).resolve(strict=False)

    def get_current_integrity_status(self, policy: str | None = None, *, force_live: bool = True, consumer: str = "wrapper") -> WrapperIntegrityStatus:
        selected_policy = default_wrapper_policy(policy)
        if bool(getattr(sys, "frozen", False)):
            from mac_audit_agent.integrity.bundle_integrity import (
                current_bundle_contents_root,
                verify_bundle_integrity,
            )

            # Never trust a caller-provided resource subdirectory for a frozen
            # process; derive Contents from the executing app bundle.
            bundle_root = current_bundle_contents_root()
            result = verify_bundle_integrity(bundle_root)
            modified = list(result.modified_files)
            missing = list(result.missing_files)
            unexpected = list(result.unexpected_files)
            trust_state = "bundle_hashes_verified" if result.status == "verified" else "bundle_integrity_failed"
            return WrapperIntegrityStatus(
                consumer=consumer,
                policy=selected_policy,
                status=result.status,
                trust_state=trust_state,
                result_code=result.result_code,
                failure_code="" if result.status == "verified" else result.result_code,
                manifest_path=result.manifest_path,
                signature_path=str(bundle_root / "_CodeSignature" / "CodeResources"),
                manifest_sha256=result.manifest_sha256,
                signature_valid=result.code_signature_valid,
                build_id=result.build_id,
                source_modified_files=modified,
                missing_files=missing,
                extra_files=unexpected,
                pre_uat_compatible=False,
                recommended_action="No action required." if result.status == "verified" else "Reinstall this application from a trusted build; do not rebaseline it on the endpoint.",
                reason=result.reason,
                module_path=__name__,
                source_file=__file__,
                cache_status="live",
                cache_stale=False,
                authority={
                    **result.to_dict(),
                    "canonical_manifest_used": True,
                    "source_type": "pyinstaller_app",
                    "trust_qualification": "Bundle hashes establish consistency; publisher authenticity requires Developer ID signing and notarization.",
                },
            )
        authority = IntegrityAuthority(self.root, selected_policy)
        live = authority.verify(strict=True) if force_live else authority.status()
        current = build_current_integrity_status(live, root=self.root)
        cached = read_current_integrity_status()
        stale = cache_is_stale(cached, current.manifest_sha256)
        signer = (live.signer_status or [{}])[0]
        return WrapperIntegrityStatus(
            consumer=consumer,
            policy=selected_policy,
            status=live.status,
            trust_state=live.trust_state,
            result_code=live.result_code,
            failure_code=live.failure_code,
            manifest_path=live.canonical_manifest_path or live.manifest_path,
            signature_path=live.signature_path,
            manifest_sha256=current.manifest_sha256,
            signature_valid=live.signature_valid,
            release_id=live.release_id,
            build_id=live.build_id,
            git_commit=live.git_commit,
            signing_key_fingerprint=live.signing_key_fingerprint,
            developer_machine_id=str(signer.get("developer_machine_id", "")) if isinstance(signer, dict) else "",
            source_modified_files=live.source_modified_files,
            missing_files=live.missing_files,
            extra_files=live.extra_files,
            generated_modified_files=live.generated_modified_files,
            pre_uat_compatible=live.pre_uat_compatible,
            recommended_action=live.recommended_action,
            reason=live.reason,
            module_path=__name__,
            source_file=__file__,
            cache_status="fresh" if cached and not stale else "stale" if cached else "missing",
            cache_stale=stale,
            cache=cached.to_dict() if cached else {},
            authority=live.to_dict(),
        )

    def get_integrity_status_for_ui(self, policy: str | None = None) -> WrapperIntegrityStatus:
        return self.get_current_integrity_status(policy, consumer="integrity_health_ui")

    def get_integrity_status_for_dashboard(self, policy: str | None = None) -> WrapperIntegrityStatus:
        return self.get_current_integrity_status(policy, consumer="dashboard")

    def get_integrity_status_for_operational_health(self, policy: str | None = None) -> WrapperIntegrityStatus:
        return self.get_current_integrity_status(policy, consumer="operational_health")

    def get_integrity_status_for_release_readiness(self, policy: str | None = None) -> WrapperIntegrityStatus:
        return self.get_current_integrity_status(policy, consumer="release_readiness")

    def get_integrity_status_for_pre_uat(self, policy: str | None = None) -> WrapperIntegrityStatus:
        return self.get_current_integrity_status(policy, consumer="pre_uat")


__all__ = ["IntegrityWrapperAdapter", "WrapperIntegrityStatus", "default_wrapper_policy"]
