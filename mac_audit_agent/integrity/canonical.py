from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path
from typing import Any


CANONICALIZATION_VERSION = "msaa-integrity-payload-json-v2"
SIGNED_PAYLOAD_FIELDS = {
    "manifest_schema_version",
    "payload_schema_version",
    "project",
    "policy_mode",
    "source_type",
    "hash_algorithm",
    "author",
    "reason",
    "build_id",
    "release_id",
    "generated_at",
    "git_commit",
    "protected_scope",
    "excluded_runtime_scope",
    "files",
}
UNSIGNED_TOP_LEVEL_FIELDS = {
    "metadata",
    "signature",
    "signatures",
    "signature_algorithm",
    "public_key",
    "public_key_id",
    "signed_at",
    "verification_status",
    "last_verified_at",
    "transient_error",
    "signature_status",
}


def normalize_relative_path(path: str | Path) -> str:
    value = str(path).replace("\\", "/")
    while value.startswith("./"):
        value = value[2:]
    if value.startswith("/") or "/../" in f"/{value}/" or value in {"", ".", ".."}:
        raise ValueError(f"invalid manifest relative path: {path!r}")
    return value


def canonical_json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def signed_payload_from_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    if isinstance(manifest.get("payload"), dict):
        shadowed = sorted(key for key in SIGNED_PAYLOAD_FIELDS if key in manifest and key != "manifest_schema_version")
        if shadowed:
            raise ValueError(f"trusted signed fields must live under payload, not top level: {', '.join(shadowed)}")
        payload = deepcopy(manifest["payload"])
    else:
        payload = {key: deepcopy(value) for key, value in manifest.items() if key not in UNSIGNED_TOP_LEVEL_FIELDS}
    files = []
    for item in payload.get("files", []):
        if not isinstance(item, dict):
            continue
        entry = deepcopy(item)
        rel = normalize_relative_path(str(entry.get("relative_path") or entry.get("path") or ""))
        entry.pop("path", None)
        entry["relative_path"] = rel
        files.append(entry)
    payload["files"] = sorted(files, key=lambda item: item["relative_path"])
    if "protected_scope" in payload:
        payload["protected_scope"] = sorted(str(item).replace("\\", "/") for item in payload.get("protected_scope", []))
    if "excluded_runtime_scope" in payload:
        payload["excluded_runtime_scope"] = sorted(str(item).replace("\\", "/") for item in payload.get("excluded_runtime_scope", []))
    return payload


def canonical_payload_bytes(manifest: dict[str, Any]) -> bytes:
    return canonical_json_bytes(signed_payload_from_manifest(manifest))


def canonical_payload_sha256(manifest: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_payload_bytes(manifest)).hexdigest()


def manifest_files(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    return list(signed_payload_from_manifest(manifest).get("files", []))


def manifest_metadata(manifest: dict[str, Any]) -> dict[str, Any]:
    if isinstance(manifest.get("metadata"), dict):
        return dict(manifest["metadata"])
    return {
        key: manifest.get(key, "")
        for key in (
            "generated_at",
            "generator_version",
            "author",
            "reason",
            "build_id",
            "release_id",
            "git_commit",
            "platform",
            "python_version",
        )
        if key in manifest
    }


__all__ = [
    "CANONICALIZATION_VERSION",
    "SIGNED_PAYLOAD_FIELDS",
    "UNSIGNED_TOP_LEVEL_FIELDS",
    "canonical_json_bytes",
    "canonical_payload_bytes",
    "canonical_payload_sha256",
    "manifest_files",
    "manifest_metadata",
    "normalize_relative_path",
    "signed_payload_from_manifest",
]
