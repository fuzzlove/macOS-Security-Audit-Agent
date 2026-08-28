"""Privacy-safe challenge identifiers for harmless live ransomware fixtures."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

FIXTURE_PREFIX = "msaa-ar-safe-"
STAGE_MARKER_PREFIX = ".msaa-ar-stage-"
LIVE_FIXTURE_STAGES = (
    "rapid-file-creation",
    "entropy-rewrite-wave",
    "rapid-rename",
    "extension-change-wave",
    "nested-directory-writes",
    "atomic-replacement",
    "truncate-entropy-rewrite",
    "benign-ransom-note-marker",
    "canary-modification",
    "disposable-mass-deletion",
    "hidden-file-rewrite",
    "known-test-hash",
)
_FIXTURE_DIRECTORY = re.compile(r"^msaa-ar-safe-([a-f0-9]{16})-")
_STAGE_MARKER = re.compile(r"^\.msaa-ar-stage-([a-z0-9-]{3,64})\.marker$")


def fixture_challenge(nonce: str) -> str:
    """Return the non-secret value recorded by the privileged observer."""
    return hashlib.sha256(f"msaa-live-fixture:{nonce}".encode("ascii")).hexdigest()


def fixture_directory_prefix(nonce: str) -> str:
    if not re.fullmatch(r"[a-f0-9]{16}", nonce):
        raise ValueError("live fixture nonce must be 16 lowercase hexadecimal characters")
    return f"{FIXTURE_PREFIX}{nonce}-"


def stage_marker_name(stage_id: str) -> str:
    if stage_id not in LIVE_FIXTURE_STAGES:
        raise ValueError(f"unknown live fixture stage: {stage_id}")
    return f"{STAGE_MARKER_PREFIX}{stage_id}.marker"


def parse_fixture_receipt(path: str | Path) -> dict[str, str] | None:
    """Extract only a random challenge hash and known stage from a fixture path."""
    candidate = Path(path)
    nonce = ""
    for component in candidate.parts:
        match = _FIXTURE_DIRECTORY.match(component)
        if match:
            nonce = match.group(1)
            break
    if not nonce:
        return None
    marker = _STAGE_MARKER.fullmatch(candidate.name)
    stage = marker.group(1) if marker and marker.group(1) in LIVE_FIXTURE_STAGES else "filesystem-activity"
    return {"challenge": fixture_challenge(nonce), "stage": stage}


__all__ = [
    "FIXTURE_PREFIX",
    "LIVE_FIXTURE_STAGES",
    "STAGE_MARKER_PREFIX",
    "fixture_challenge",
    "fixture_directory_prefix",
    "parse_fixture_receipt",
    "stage_marker_name",
]
