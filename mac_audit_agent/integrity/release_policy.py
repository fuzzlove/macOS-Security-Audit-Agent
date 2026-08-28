from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ReleasePolicy:
    mode: str
    signed_manifest_required: bool
    signed_artifacts_required: bool
    release_evidence_required: bool
    clean_install_required: bool
    macos_codesign_required: bool = False


POLICIES = {
    "dev": ReleasePolicy("dev", False, False, False, False),
    "pre_release": ReleasePolicy("pre_release", True, True, True, False),
    "public_release": ReleasePolicy("public_release", True, True, True, True),
    "release": ReleasePolicy("release", True, True, True, False),
}


def release_policy(mode: str) -> ReleasePolicy:
    return POLICIES.get(str(mode or "dev"), POLICIES["dev"])


__all__ = ["ReleasePolicy", "release_policy"]
