"""Immutable definition bundles with detached signatures and atomic activation."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
import stat
import tempfile
import zipfile
from collections import Counter
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as package_version
from pathlib import Path, PurePosixPath
from typing import Any, Callable

from packaging.version import InvalidVersion, Version

from .intelligence import MalwareIntelligenceDatabase, build_release_database
from .models import (
    DefinitionAction,
    DefinitionLifecycle,
    DefinitionProvenance,
    DefinitionType,
    Severity,
    SourcePolicy,
    ThreatDefinition,
    TrustClass,
    ValidationState,
    utc_now,
)
from .normalization import NormalizationError, normalize_value
from .signing import ManifestSigner, ManifestTrustStore, SignatureError, canonical_json
from .validation import split_yara_rules

DEFAULT_DEFINITION_ROOT = Path("/Library/Application Support/MSAA/definitions")
LEGACY_DEFINITION_ROOT = Path("/Library/Application Support/MacAuditAgent/definitions")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")


class BundleError(ValueError):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def _definition_from_dict(document: dict[str, Any]) -> ThreatDefinition:
    provenance = tuple(
        DefinitionProvenance(
            source_id=str(item["source_id"]), source_reference=item.get("source_reference"),
            retrieved_at=_parse_time(item.get("retrieved_at")) or utc_now(), original_value=item.get("original_value"),
            source_confidence=float(item.get("source_confidence", 0.5)),
            trust_class=TrustClass(str(item.get("trust_class", "COMMUNITY"))),
            dependency_group=item.get("dependency_group"),
        )
        for item in document.get("provenance", []) if isinstance(item, dict)
    )
    return ThreatDefinition(
        definition_id=str(document["definition_id"]), definition_type=DefinitionType(str(document["definition_type"])),
        value=str(document["value"]), confidence=float(document.get("confidence", 0.5)),
        severity=Severity(str(document.get("severity", "MEDIUM"))), malware_family=document.get("malware_family"),
        first_seen=_parse_time(document.get("first_seen")), last_seen=_parse_time(document.get("last_seen")),
        created_at=_parse_time(document.get("created_at")) or utc_now(), imported_at=_parse_time(document.get("imported_at")) or utc_now(),
        expires_at=_parse_time(document.get("expires_at")), tags=tuple(str(item) for item in document.get("tags", [])),
        action=DefinitionAction(str(document.get("action", "CORRELATE"))),
        lifecycle=DefinitionLifecycle(str(document.get("lifecycle", "NEW"))), provenance=provenance,
        metadata=document.get("metadata", {}) if isinstance(document.get("metadata", {}), dict) else {},
    )


class DefinitionStore:
    def __init__(self, root: Path = DEFAULT_DEFINITION_ROOT, *, trust_store: ManifestTrustStore | None = None, require_signatures: bool | None = None) -> None:
        self.root = Path(root)
        self.active_dir = self.root / "active"
        self.staging_dir = self.root / "staging"
        self.staged_dir = self.staging_dir  # compatibility with the existing manager API
        self.previous_dir = self.root / "previous"
        self.quarantine_dir = self.root / "quarantine"
        self.metadata_dir = self.root / "metadata"
        self.releases_dir = self.root / "releases"
        self.bundle_dir = self.releases_dir  # compatibility with signed-bundle callers
        self.custom_dir = self.root / "custom"
        self.cache_dir = self.root / "cache"
        self.manifests_dir = self.root / "manifests"
        self.logs_dir = self.root / "logs"
        self.trust_store = trust_store or ManifestTrustStore(self.root / "trusted_keys")
        self.require_signatures = (
            os.environ.get("MSAA_REQUIRE_SIGNED_DEFINITIONS", "0") == "1"
            if require_signatures is None else bool(require_signatures)
        )

    def initialize(self) -> None:
        for directory in (
            self.active_dir, self.staging_dir, self.previous_dir, self.quarantine_dir,
            self.metadata_dir, self.releases_dir, self.custom_dir, self.cache_dir,
            self.manifests_dir, self.logs_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)
            os.chmod(directory, 0o700)
        self._recover_abandoned_staging()

    def _recover_abandoned_staging(self) -> None:
        """Quarantine incomplete dot-prefixed builds left by a crash or reboot."""
        for candidate in self.staging_dir.glob(".*"):
            if not candidate.is_dir() or candidate.is_symlink():
                continue
            if candidate.name.startswith(f".download-{os.getpid()}-"):
                # The current updater may re-enter initialize while building
                # the immutable release from this staged download.
                continue
            destination = self.quarantine_dir / f"abandoned-{utc_now().strftime('%Y%m%dT%H%M%S%fZ')}-{candidate.name.lstrip('.')[:80]}"
            try:
                os.replace(candidate, destination)
                self._record("DEF_STAGING_RECOVERED", candidate.name[:128], "Abandoned staging content was quarantined before update processing.")
            except OSError:
                continue

    def stage_download_artifact(self, source_id: str, payload: bytes) -> Path:
        """Persist a bounded provider artifact before parsing or validation."""
        self.initialize()
        safe_source = re.sub(r"[^A-Za-z0-9_.-]", "_", str(source_id))[:80] or "unknown"
        workspace = Path(tempfile.mkdtemp(prefix=f".download-{os.getpid()}-{safe_source}-", dir=self.staging_dir))
        os.chmod(workspace, 0o700)
        artifact = workspace / "source.download"
        with artifact.open("wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(artifact, 0o600)
        self._atomic_json(workspace / "artifact.json", {
            "source_id": safe_source,
            "downloaded_at": utc_now().isoformat(),
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        })
        return workspace

    def discard_download_artifact(self, workspace: Path) -> None:
        workspace = Path(workspace)
        try:
            resolved_parent = workspace.parent.resolve(strict=True)
        except OSError:
            return
        if resolved_parent != self.staging_dir.resolve(strict=True) or not workspace.name.startswith(f".download-{os.getpid()}-"):
            raise BundleError("refusing to remove an unrecognized staging workspace")
        if workspace.is_dir() and not workspace.is_symlink():
            shutil.rmtree(workspace)

    @staticmethod
    def _version(value: str) -> str:
        if not _VERSION.fullmatch(value):
            raise BundleError("bundle version contains unsafe characters")
        return value

    @staticmethod
    def _atomic_json(path: Path, document: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(canonical_json(document) + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def stage(
        self, version: str, definitions: Iterable[ThreatDefinition], *, minimum_msaa_version: str = "1.0b0",
        source_versions: dict[str, str] | None = None, source_hashes: dict[str, str] | None = None,
        source_policies: dict[str, SourcePolicy] | None = None, signer: ManifestSigner | None = None,
    ) -> dict[str, Any]:
        self.initialize()
        version = self._version(version)
        destination = self.staged_dir / version
        if destination.exists() or (self.bundle_dir / version).exists():
            raise BundleError("bundle version already exists")
        items = list(definitions)
        if not items:
            raise BundleError("empty definition bundles are rejected")
        temp = Path(tempfile.mkdtemp(prefix=f".{version}.", dir=self.staged_dir))
        try:
            definition_path = temp / "definitions.jsonl"
            with definition_path.open("w", encoding="utf-8", newline="\n") as handle:
                for item in sorted(items, key=lambda entry: entry.canonical_key):
                    handle.write(json.dumps(item.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(definition_path, 0o600)
            grouped: dict[DefinitionType, list[ThreatDefinition]] = {}
            for item in items:
                grouped.setdefault(item.definition_type, []).append(item)
            for kind, entries in grouped.items():
                if kind == DefinitionType.YARA_RULE:
                    for item in entries:
                        provenance = item.provenance[0] if item.provenance else None
                        namespace = re.sub(r"[^A-Za-z0-9_]", "_", str(item.metadata.get("namespace") or (provenance.source_id if provenance else "community")))[:96]
                        output_dir = temp / "yara" / "macos" / (namespace or "community")
                        output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
                        rules = split_yara_rules(item.value) or [(item.definition_id, item.value)]
                        for rule_name, rule_source in rules:
                            safe_rule = re.sub(r"[^A-Za-z0-9_.-]", "_", rule_name)[:128] or item.definition_id
                            path = output_dir / f"{safe_rule}-{item.definition_id[-8:]}.yar"
                            path.write_text(rule_source, encoding="utf-8", newline="\n")
                            os.chmod(path, 0o600)
                    continue
                category = (
                    "hashes" if kind in {DefinitionType.MD5, DefinitionType.SHA1, DefinitionType.SHA256}
                    else "domains" if kind in {DefinitionType.DOMAIN, DefinitionType.HOSTNAME}
                    else "urls" if kind == DefinitionType.URL
                    else "network" if kind in {DefinitionType.IPV4, DefinitionType.IPV6, DefinitionType.CIDR}
                    else "certificates" if kind in {DefinitionType.CERTIFICATE_HASH, DefinitionType.CERTIFICATE_IDENTITY}
                    else "behavior" if kind in {DefinitionType.BEHAVIOR_RULE, DefinitionType.DETECTION_RULE}
                    else "metadata"
                )
                output_dir = temp / category
                output_dir.mkdir(mode=0o700, exist_ok=True)
                path = output_dir / f"{kind.value.lower()}.jsonl"
                with path.open("w", encoding="utf-8", newline="\n") as handle:
                    for item in sorted(entries, key=lambda entry: entry.value):
                        handle.write(json.dumps({
                            "definition_id": item.definition_id, "value": item.value,
                            "action": item.action.value, "confidence": item.confidence,
                            "lifecycle": item.lifecycle.value,
                        }, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                os.chmod(path, 0o600)
            hash_dir = temp / "hashes"
            hash_dir.mkdir(mode=0o700, exist_ok=True)
            for kind, filename in (
                (DefinitionType.SHA256, "sha256.txt"),
                (DefinitionType.SHA1, "sha1.txt"),
                (DefinitionType.MD5, "md5.txt"),
            ):
                values = {item.value for item in grouped.get(kind, ())}
                metadata_key = kind.value.lower()
                for item in items:
                    if item.definition_type not in {DefinitionType.SHA256, DefinitionType.SHA1, DefinitionType.MD5}:
                        continue
                    candidate = item.metadata.get(metadata_key) if isinstance(item.metadata, dict) else None
                    if candidate:
                        try:
                            values.add(normalize_value(kind, str(candidate)))
                        except NormalizationError:
                            continue
                path = hash_dir / filename
                path.write_text("".join(f"{value}\n" for value in sorted(values)), encoding="ascii", newline="\n")
                os.chmod(path, 0o600)
            database_dir = temp / "databases"
            database_dir.mkdir(mode=0o700)
            database_metrics = build_release_database(
                database_dir / "threat_intelligence.sqlite3", items,
                source_policies=source_policies, source_versions=source_versions,
            )
            release_metadata = temp / "metadata"
            release_metadata.mkdir(mode=0o700, exist_ok=True)
            source_document = {
                "sources": [
                    {
                        **policy.to_dict(),
                        "version": (source_versions or {}).get(source_id),
                        "artifact_sha256": (source_hashes or {}).get(source_id),
                    }
                    for source_id, policy in sorted((source_policies or {}).items())
                ]
            }
            self._atomic_json(release_metadata / "sources.json", source_document)
            counts = dict(sorted(Counter(item.definition_type.value for item in items).items()))
            payload_files = sorted(path for path in temp.rglob("*") if path.is_file())
            file_manifest = {
                path.relative_to(temp).as_posix(): {"sha256": _sha256(path), "size": path.stat().st_size}
                for path in payload_files
            }
            manifest = {
                "schema_version": 1, "release_id": version, "bundle_version": version, "created_at": utc_now().isoformat(),
                "minimum_msaa_version": minimum_msaa_version,
                "definition_count": len(items), "yara_rule_count": database_metrics["yara_rules"],
                "sha256_count": database_metrics["sha256"],
                "sha1_count": database_metrics["sha1"],
                "md5_count": database_metrics["md5"],
                "counts_by_type": counts,
                "sources": sorted((source_policies or {}).keys()),
                "source_versions": dict(sorted((source_versions or {}).items())),
                "source_hashes": dict(sorted((source_hashes or {}).items())),
                "files": file_manifest,
                "file_hashes": {name: record["sha256"] for name, record in file_manifest.items()},
                "validation_result": "VALIDATED",
                "updater_version": running_updater_version(),
                "database_metrics": database_metrics,
            }
            self._atomic_json(temp / "manifest.json", manifest)
            if signer is not None:
                signature_document = signer.sign(manifest).to_dict()
                self._atomic_json(temp / "manifest.sig", signature_document)
                self._atomic_json(temp / "manifest.signature.json", signature_document)
            os.replace(temp, destination)
            self._record("DEF_RELEASE_BUILT", version, f"Validated staged release contains {len(items)} definitions.")
            return manifest
        except Exception:
            shutil.rmtree(temp, ignore_errors=True)
            raise

    def verify_bundle(self, directory: Path, *, require_signature: bool | None = None) -> dict[str, Any]:
        directory = Path(directory)
        if directory.is_symlink() or not directory.is_dir():
            raise BundleError("bundle is not a regular directory")
        manifest_path = directory / "manifest.json"
        if not manifest_path.is_file() or manifest_path.is_symlink() or manifest_path.stat().st_size > 1024 * 1024:
            raise BundleError("bundle manifest is missing or oversized")
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BundleError("bundle manifest is invalid") from exc
        if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
            raise BundleError("unsupported bundle schema")
        try:
            running_version = package_version("macos-security-audit-agent")
        except PackageNotFoundError:
            running_version = "1.0b0"
        try:
            if Version(running_version) < Version(str(manifest.get("minimum_msaa_version", "0"))):
                raise BundleError("definition bundle requires a newer MSAA version")
        except InvalidVersion as exc:
            raise BundleError("bundle compatibility version is invalid") from exc
        created_at = _parse_time(manifest.get("created_at"))
        if created_at is None or created_at > utc_now() + timedelta(days=1):
            raise BundleError("bundle creation timestamp is invalid")
        version = self._version(str(manifest.get("bundle_version", "")))
        if directory.name != version:
            raise BundleError("bundle directory and manifest versions differ")
        files = manifest.get("files")
        if not isinstance(files, dict) or not files:
            raise BundleError("bundle file manifest is empty")
        for relative, expected in files.items():
            pure = PurePosixPath(str(relative))
            if pure.is_absolute() or ".." in pure.parts or len(pure.parts) > 8 or not isinstance(expected, dict):
                raise BundleError("bundle manifest contains an unsafe path")
            path = directory.joinpath(*pure.parts)
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 512 * 1024 * 1024:
                raise BundleError(f"bundle file is missing or unsafe: {relative}")
            if _sha256(path) != expected.get("sha256") or path.stat().st_size != int(expected.get("size", -1)):
                raise BundleError(f"bundle integrity mismatch: {relative}")
        counts_by_type = manifest.get("counts_by_type")
        if not isinstance(counts_by_type, dict):
            raise BundleError("bundle definition counts are missing")
        try:
            declared_count = int(manifest.get("definition_count", -1))
            counts_total = sum(int(value) for value in counts_by_type.values())
        except (TypeError, ValueError) as exc:
            raise BundleError("bundle definition counts are invalid") from exc
        if declared_count <= 0 or counts_total != declared_count:
            raise BundleError("bundle definition counts are inconsistent")
        definitions_path = directory / "definitions.jsonl"
        if definitions_path.is_file():
            with definitions_path.open("rb") as handle:
                actual_count = sum(1 for line in handle if line.strip())
            if actual_count != declared_count:
                raise BundleError("bundle definition payload count does not match the manifest")
        intelligence_path = directory / "databases" / "threat_intelligence.sqlite3"
        if intelligence_path.is_file():
            try:
                database_status = MalwareIntelligenceDatabase(intelligence_path, release_id=version).verify()
            except (OSError, sqlite3.DatabaseError) as exc:
                raise BundleError("release threat-intelligence database is invalid") from exc
            hash_count = sum(int(manifest.get(key, 0)) for key in ("sha256_count", "sha1_count", "md5_count"))
            if int(database_status.get("indicator_count", -1)) != hash_count:
                raise BundleError("release threat-intelligence database hash count differs from manifest")
            if int(database_status.get("yara_rule_count", -1)) != int(manifest.get("yara_rule_count", -1)):
                raise BundleError("release threat-intelligence database YARA count differs from manifest")
        expected_names = {"manifest.json", "manifest.sig", "manifest.signature.json", *files.keys()}
        for path in directory.rglob("*"):
            if path.is_symlink():
                raise BundleError("bundle contains a symbolic link")
            if path.is_file() and path.relative_to(directory).as_posix() not in expected_names:
                raise BundleError(f"bundle contains an unmanifested file: {path.name}")
        signature_required = self.require_signatures if require_signature is None else require_signature
        signature_path = directory / "manifest.sig"
        if not signature_path.is_file():
            signature_path = directory / "manifest.signature.json"
        if signature_path.is_file() and not signature_path.is_symlink() and signature_path.stat().st_size <= 64 * 1024:
            try:
                self.trust_store.verify(manifest, json.loads(signature_path.read_text(encoding="utf-8")))
            except (OSError, json.JSONDecodeError, SignatureError) as exc:
                raise BundleError(str(exc)) from exc
        elif signature_required:
            raise BundleError("bundle signature is required")
        return manifest

    def definitions(self, version: str | None = None) -> list[ThreatDefinition]:
        directory = self.bundle_path(version) if version else self.active_bundle_path()
        if directory is None:
            return []
        self.verify_bundle(directory)
        path = directory / "definitions.jsonl"
        if path.stat().st_size > 512 * 1024 * 1024:
            raise BundleError("definition payload exceeds the configured bound")
        output: list[ThreatDefinition] = []
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                if len(line.encode("utf-8")) > 65 * 1024 * 1024:
                    raise BundleError(f"definition line {line_number} is oversized")
                try:
                    document = json.loads(line)
                    if not isinstance(document, dict):
                        raise TypeError
                    output.append(_definition_from_dict(document))
                except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                    raise BundleError(f"definition line {line_number} is invalid") from exc
        return output

    def bundle_path(self, version: str) -> Path:
        version = self._version(version)
        for root in (self.bundle_dir, self.staged_dir):
            candidate = root / version
            if candidate.is_dir() and not candidate.is_symlink():
                return candidate
        raise BundleError("definition bundle version is unavailable")

    def _pointer(self, directory: Path) -> dict[str, Any]:
        path = directory / "current.json"
        if not path.is_file() or path.is_symlink() or path.stat().st_size > 64 * 1024:
            return {}
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
            return document if isinstance(document, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    def active_bundle_path(self) -> Path | None:
        version = str(self._pointer(self.active_dir).get("version", ""))
        if not version:
            return None
        try:
            path = self.bundle_dir / self._version(version)
        except BundleError:
            return None
        return path if path.is_dir() and not path.is_symlink() else None

    def activate(self, version: str, *, reload_callback: Callable[[Path], bool] | None = None) -> dict[str, Any]:
        self.initialize()
        version = self._version(version)
        staged = self.staged_dir / version
        try:
            manifest = self.verify_bundle(staged)
        except (BundleError, OSError, ValueError) as exc:
            if staged.is_dir() and not staged.is_symlink():
                quarantine = self.quarantine_dir / f"{version}-activation-rejected-{utc_now().strftime('%Y%m%dT%H%M%S%fZ')}"
                os.replace(staged, quarantine)
            self._record("DEF_UPDATE_FAILURE", version, f"Pre-activation integrity rejection: {type(exc).__name__}")
            raise
        immutable = self.bundle_dir / version
        if immutable.exists():
            raise BundleError("immutable bundle version already exists")
        os.replace(staged, immutable)
        previous = self._pointer(self.active_dir)
        pointer = {"version": version, "activated_at": utc_now().isoformat(), "manifest_sha256": _sha256(immutable / "manifest.json"), "validation_state": ValidationState.VALID.value}
        if previous:
            self._atomic_json(self.previous_dir / "current.json", previous)
        self._atomic_json(self.active_dir / "current.json", pointer)
        try:
            if reload_callback is not None and not bool(reload_callback(immutable)):
                raise BundleError("sensor reload validation failed")
        except Exception as exc:
            if previous:
                self._atomic_json(self.active_dir / "current.json", previous)
            else:
                (self.active_dir / "current.json").unlink(missing_ok=True)
            quarantine = self.quarantine_dir / f"{version}-reload-failed-{utc_now().strftime('%Y%m%dT%H%M%S%fZ')}"
            if immutable.exists():
                os.replace(immutable, quarantine)
            self._record("DEF_UPDATE_ROLLBACK", version, str(exc))
            raise BundleError("activation was rolled back because sensor reload validation failed") from exc
        self._record("DEF_RELEASE_ACTIVATED", version, "Definition release activated after integrity and sensor-load validation.")
        return {"status": "ACTIVATED", "version": version, "previous_version": previous.get("version"), "manifest": manifest}

    def rollback(self, *, reload_callback: Callable[[Path], bool] | None = None) -> dict[str, Any]:
        previous = self._pointer(self.previous_dir)
        if not previous.get("version"):
            raise BundleError("no previous known-good definition bundle is available")
        path = self.bundle_dir / self._version(str(previous["version"]))
        self.verify_bundle(path)
        current = self._pointer(self.active_dir)
        self._atomic_json(self.active_dir / "current.json", {**previous, "activated_at": utc_now().isoformat(), "rollback_from": current.get("version")})
        if reload_callback is not None and not bool(reload_callback(path)):
            self._atomic_json(self.active_dir / "current.json", current)
            raise BundleError("rollback reload validation failed; original active pointer was restored")
        self._record("DEF_UPDATE_ROLLBACK", str(previous["version"]), f"Rolled back from {current.get('version', 'unknown')}.")
        return {"status": "ROLLED_BACK", "version": previous["version"], "replaced_version": current.get("version")}

    def prune_releases(self, retain: int) -> list[str]:
        """Remove only old, inactive immutable releases after activation succeeds."""
        self.initialize()
        keep_count = max(2, int(retain))
        protected = {
            str(self._pointer(self.active_dir).get("version", "")),
            str(self._pointer(self.previous_dir).get("version", "")),
        }
        releases = sorted(
            (path for path in self.releases_dir.iterdir() if path.is_dir() and not path.is_symlink()),
            key=lambda path: path.stat().st_mtime_ns,
            reverse=True,
        )
        keep = protected | {path.name for path in releases[:keep_count]}
        removed: list[str] = []
        for path in releases:
            if path.name in keep or not _VERSION.fullmatch(path.name):
                continue
            shutil.rmtree(path)
            removed.append(path.name)
            self._record("DEF_RELEASE_PRUNED", path.name, "Inactive release removed by the configured retention policy.")
        return removed

    def import_bundle(self, archive: Path) -> dict[str, Any]:
        self.initialize()
        archive = Path(archive)
        if not archive.exists():
            raise BundleError(f"offline definition bundle was not found: {archive}")
        if archive.is_symlink():
            raise BundleError(f"offline definition bundle must not be a symbolic link: {archive}")
        if not archive.is_file():
            raise BundleError(f"offline definition bundle is not a regular file: {archive}")
        if archive.stat().st_size > 512 * 1024 * 1024:
            raise BundleError(f"offline definition bundle exceeds the 512 MiB import limit: {archive}")
        temporary = Path(tempfile.mkdtemp(prefix=".import.", dir=self.staged_dir))
        try:
            with zipfile.ZipFile(archive) as bundle:
                infos = bundle.infolist()
                if not infos or len(infos) > 10_000 or sum(item.file_size for item in infos) > 512 * 1024 * 1024:
                    raise BundleError("offline bundle entry count or expanded size exceeds limits")
                if len({item.filename for item in infos}) != len(infos):
                    raise BundleError("offline bundle contains duplicate archive paths")
                roots: set[str] = set()
                expanded_bytes = 0
                for info in infos:
                    if "\\" in info.filename or info.flag_bits & 0x1:
                        raise BundleError("offline bundle contains an unsafe or encrypted entry")
                    if not info.is_dir() and info.file_size > max(1024 * 1024, info.compress_size * 200):
                        raise BundleError("offline bundle contains a decompression bomb candidate")
                    path = PurePosixPath(info.filename)
                    if path.is_absolute() or ".." in path.parts or not path.parts or len(path.parts) > 10:
                        raise BundleError("offline bundle contains an unsafe path")
                    if stat.S_ISLNK(info.external_attr >> 16):
                        raise BundleError("offline bundle contains a symbolic link")
                    roots.add(path.parts[0])
                    target = temporary.joinpath(*path.parts)
                    if info.is_dir():
                        target.mkdir(parents=True, exist_ok=True)
                    else:
                        target.parent.mkdir(parents=True, exist_ok=True)
                        with bundle.open(info) as source, target.open("wb") as destination:
                            while True:
                                chunk = source.read(1024 * 1024)
                                if not chunk:
                                    break
                                expanded_bytes += len(chunk)
                                if expanded_bytes > 512 * 1024 * 1024:
                                    raise BundleError("offline bundle expanded size exceeds its bound")
                                destination.write(chunk)
                if len(roots) != 1:
                    raise BundleError("offline bundle must contain exactly one version directory")
            extracted = temporary / next(iter(roots))
            for path in extracted.rglob("*"):
                os.chmod(path, 0o700 if path.is_dir() else 0o600)
            manifest = self.verify_bundle(extracted, require_signature=True)
            version = self._version(str(manifest["bundle_version"]))
            destination = self.staged_dir / version
            if destination.exists() or (self.bundle_dir / version).exists():
                raise BundleError("imported bundle version already exists")
            os.replace(extracted, destination)
            self._record("DEF_SOURCE_DOWNLOAD", version, "Signed offline bundle passed integrity validation and was staged.")
            return {"status": "STAGED", "version": version, "manifest": manifest}
        except Exception as exc:
            quarantine = self.quarantine_dir / f"rejected-{utc_now().strftime('%Y%m%dT%H%M%S%fZ')}"
            if temporary.exists():
                os.replace(temporary, quarantine)
            self._record("DEF_UPDATE_FAILURE", archive.name[:128], type(exc).__name__)
            raise
        finally:
            if temporary.exists():
                shutil.rmtree(temporary, ignore_errors=True)

    def reject_staged(self, version: str, reason: str) -> Path:
        self.initialize()
        version = self._version(version)
        source = self.staged_dir / version
        if not source.is_dir() or source.is_symlink():
            raise BundleError("staged bundle is unavailable for quarantine")
        destination = self.quarantine_dir / f"{version}-{utc_now().strftime('%Y%m%dT%H%M%S%fZ')}"
        os.replace(source, destination)
        self._record("STAGED_BUNDLE_REJECTED", version, reason)
        return destination

    def quarantine_yara(self, source_id: str, rule_name: str, source: str, error: str, *, release: str = "staging") -> Path:
        """Preserve a bounded invalid rule for diagnostics without loading it."""
        self.initialize()
        safe_source = re.sub(r"[^A-Za-z0-9_.-]", "_", source_id)[:80] or "unknown"
        safe_rule = re.sub(r"[^A-Za-z0-9_.-]", "_", rule_name)[:80] or "unknown_rule"
        directory = self.quarantine_dir / f"yara-{utc_now().strftime('%Y%m%dT%H%M%S%fZ')}-{safe_source}"
        directory.mkdir(mode=0o700)
        rule_path = directory / f"{safe_rule}.yar"
        encoded = source.encode("utf-8", errors="replace")[: self._bounded_yara_quarantine_bytes()]
        rule_path.write_bytes(encoded)
        os.chmod(rule_path, 0o600)
        self._atomic_json(directory / "rejection.json", {
            "source": source_id[:128], "filename": rule_path.name, "rule_identifier": rule_name[:128],
            "error": error[:1024], "timestamp": utc_now().isoformat(), "release": release[:128],
        })
        self._record("DEF_YARA_COMPILE_FAILURE", release, f"{safe_source}:{safe_rule}")
        return directory

    @staticmethod
    def _bounded_yara_quarantine_bytes() -> int:
        return 4 * 1024 * 1024

    def export_bundle(self, version: str, destination: Path) -> Path:
        source = self.bundle_path(version)
        self.verify_bundle(source)
        destination = Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(source.rglob("*")):
                if path.is_file() and not path.is_symlink():
                    archive.write(path, arcname=f"{source.name}/{path.relative_to(source).as_posix()}")
        return destination

    def _record(self, event: str, version: str, message: str) -> None:
        self.metadata_dir.mkdir(parents=True, exist_ok=True)
        path = self.metadata_dir / "history.jsonl"
        record = {"event": event, "version": version, "message": message[:512], "timestamp": utc_now().isoformat()}
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(descriptor, canonical_json(record) + b"\n")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def history(self, limit: int = 100) -> list[dict[str, Any]]:
        path = self.metadata_dir / "history.jsonl"
        if not path.is_file() or path.is_symlink() or path.stat().st_size > 64 * 1024 * 1024:
            return []
        output: list[dict[str, Any]] = []
        for line in path.read_text(encoding="utf-8").splitlines()[-max(1, min(limit, 1000)):]:
            try:
                item = json.loads(line)
                if isinstance(item, dict):
                    output.append(item)
            except json.JSONDecodeError:
                continue
        return output


def running_updater_version() -> str:
    try:
        return package_version("macos-security-audit-agent")
    except PackageNotFoundError:
        return "1.0b0"


__all__ = ["DEFAULT_DEFINITION_ROOT", "LEGACY_DEFINITION_ROOT", "BundleError", "DefinitionStore"]
