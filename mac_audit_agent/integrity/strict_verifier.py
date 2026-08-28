from __future__ import annotations

import json
import logging
import stat
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

from mac_audit_agent.compat.datetime_compat import utc_now
from mac_audit_agent.integrity.hasher import calculate_sha256, is_excluded, iter_integrity_files
from mac_audit_agent.integrity.manifest_paths import integrity_manifest_paths
from mac_audit_agent.integrity.signed_manifest_validator import validate_signed_manifest
from mac_audit_agent.integrity.signed_manifest import SignedManifest, SignedManifestFileEntry, load_signed_manifest, verify_manifest_signature

LOGGER = logging.getLogger(__name__)

FileChangeType = Literal["UNCHANGED", "MODIFIED_HASH", "MISSING", "EXTRA_FILE", "PERMISSION_CHANGED", "SIGNATURE_CHANGED"]


@dataclass(frozen=True)
class FileIntegrityChange:
    file_path: str
    change_type: FileChangeType
    expected_hash: str = ""
    actual_hash: str = ""
    expected_mode: str = ""
    actual_mode: str = ""
    expected_signature: str = ""
    actual_signature: str = ""
    severity: str = "INFO"
    risk_explanation: str = ""
    category: str = "core"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class IntegrityDiffReport:
    run_id: str
    timestamp: str
    status: str
    changed_files: list[FileIntegrityChange] = field(default_factory=list)
    missing_files: list[FileIntegrityChange] = field(default_factory=list)
    extra_files: list[FileIntegrityChange] = field(default_factory=list)
    unchanged_files: list[FileIntegrityChange] = field(default_factory=list)
    hash_mismatches: list[FileIntegrityChange] = field(default_factory=list)
    permission_changes: list[FileIntegrityChange] = field(default_factory=list)
    signature_changes: list[FileIntegrityChange] = field(default_factory=list)
    severity_level: str = "INFO"
    requires_user_acknowledgement: bool = False
    explanation_summary: str = ""
    manifest_path: str = ""
    manifest_id: str = ""
    manifest_signature_valid: bool = False

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        for key in [
            "changed_files",
            "missing_files",
            "extra_files",
            "unchanged_files",
            "hash_mismatches",
            "permission_changes",
            "signature_changes",
        ]:
            payload[key] = [item.to_dict() if hasattr(item, "to_dict") else item for item in getattr(self, key)]
        return payload

    @property
    def all_changes(self) -> list[FileIntegrityChange]:
        return [*self.hash_mismatches, *self.missing_files, *self.extra_files, *self.permission_changes, *self.signature_changes]


class StrictIntegrityVerifier:
    def __init__(self, root: Path, manifest_path: Path, *, logs_dir: Path | None = None) -> None:
        self.root = Path(root).resolve(strict=False)
        self.manifest_path = Path(manifest_path).expanduser().resolve(strict=False)
        self.logs_dir = logs_dir or (Path.home() / "Library" / "Logs" / "MacAuditAgent")
        self._canonical_manifest_mode = False

    def verify(self) -> IntegrityDiffReport:
        timestamp = _utc_now_iso()
        run_id = f"strict-integrity-{uuid.uuid4().hex}"
        try:
            manifest, signature_valid = self._load_manifest_for_strict_verification()
        except Exception as exc:
            report = IntegrityDiffReport(
                run_id=run_id,
                timestamp=timestamp,
                status="failed",
                severity_level="CRITICAL",
                requires_user_acknowledgement=True,
                explanation_summary=f"Trusted signed manifest could not be loaded: {exc}",
                manifest_path=str(self.manifest_path),
            )
            self.log_report(report, user_action_taken="manifest_load_failed")
            return report

        report = IntegrityDiffReport(
            run_id=run_id,
            timestamp=timestamp,
            status="verifying",
            manifest_path=str(self.manifest_path),
            manifest_id=manifest.manifest_id,
            manifest_signature_valid=signature_valid,
        )
        if not signature_valid:
            report.status = "failed"
            report.severity_level = "CRITICAL"
            report.requires_user_acknowledgement = True
            report.explanation_summary = "SIGNATURE_INVALID: canonical manifest signature is missing, invalid, or no longer matches the signed payload."
            self.log_report(report, user_action_taken="invalid_manifest_signature")
            return report

        expected = {entry.path: entry for entry in manifest.file_entries}
        observed = self._observed_paths(manifest)
        for rel_path, entry in expected.items():
            path = self.root / rel_path
            if rel_path not in observed or (not path.exists() and not path.is_symlink()):
                change = self._change(entry, "MISSING", severity=self._severity_for("MISSING", entry), risk="A required tracked file is missing from the application install.")
                report.missing_files.append(change)
                report.changed_files.append(change)
                continue
            actual_hash = calculate_sha256(path) if path.is_file() else ""
            actual_mode = self._mode(path)
            actual_signature = self._file_signature(path)
            file_changed = False
            if entry.sha256 and actual_hash != entry.sha256:
                change = self._change(entry, "MODIFIED_HASH", actual_hash=actual_hash, actual_mode=actual_mode, actual_signature=actual_signature, severity=self._severity_for("MODIFIED_HASH", entry), risk="The file content hash no longer matches the trusted manifest.")
                report.hash_mismatches.append(change)
                report.changed_files.append(change)
                file_changed = True
            if entry.mode and actual_mode != entry.mode:
                change = self._change(entry, "PERMISSION_CHANGED", actual_hash=actual_hash, actual_mode=actual_mode, actual_signature=actual_signature, severity=self._severity_for("PERMISSION_CHANGED", entry), risk="The file permission bits changed from the trusted baseline.")
                report.permission_changes.append(change)
                report.changed_files.append(change)
                file_changed = True
            if entry.signature and actual_signature != entry.signature:
                change = self._change(entry, "SIGNATURE_CHANGED", actual_hash=actual_hash, actual_mode=actual_mode, actual_signature=actual_signature, severity="CRITICAL", risk="The file signature changed from the trusted signed manifest.")
                report.signature_changes.append(change)
                report.changed_files.append(change)
                file_changed = True
            if not file_changed:
                report.unchanged_files.append(self._change(entry, "UNCHANGED", actual_hash=actual_hash, actual_mode=actual_mode, actual_signature=actual_signature, severity="INFO", risk="File matches the signed trusted manifest."))

        if not self._canonical_manifest_mode:
            for rel_path in sorted(observed - set(expected)):
                if is_excluded(rel_path, manifest.excluded_patterns):
                    continue
                path = self.root / rel_path
                entry = SignedManifestFileEntry(path=rel_path, sha256="", required=False, category=_category_for_extra(path), mode=self._mode(path), executable=_is_executable(path))
                change = self._change(entry, "EXTRA_FILE", actual_hash=calculate_sha256(path) if path.is_file() else "", actual_mode=self._mode(path), severity=self._severity_for("EXTRA_FILE", entry), risk="A file exists in the application tree but is not listed in the signed trusted manifest.")
                report.extra_files.append(change)
                report.changed_files.append(change)

        self._finalize(report)
        self.log_report(report, user_action_taken="verification_only")
        return report

    def _load_manifest_for_strict_verification(self) -> tuple[SignedManifest, bool]:
        raw = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        if isinstance(raw.get("files"), list) or isinstance(raw.get("payload", {}).get("files"), list):
            self._canonical_manifest_mode = True
            manifest = self._canonical_manifest_to_strict_manifest(raw)
            signature_valid = self._canonical_signature_valid()
            return manifest, signature_valid

        self._canonical_manifest_mode = False
        manifest = load_signed_manifest(self.manifest_path)
        return manifest, verify_manifest_signature(manifest)

    def _canonical_manifest_to_strict_manifest(self, raw: dict[str, Any]) -> SignedManifest:
        entries: list[SignedManifestFileEntry] = []
        payload = raw.get("payload") if isinstance(raw.get("payload"), dict) else raw
        for item in payload.get("files", []):
            if not isinstance(item, dict):
                continue
            rel = str(item.get("relative_path") or item.get("path") or "")
            if not rel:
                continue
            entries.append(
                SignedManifestFileEntry(
                    path=rel,
                    sha256=str(item.get("sha256", "")),
                    required=bool(item.get("required", True)),
                    category=str(item.get("category") or item.get("source_category") or "core"),
                    mode=str(item.get("mode", "")),
                    size_bytes=int(item.get("file_size") or item.get("size_bytes") or item.get("size") or 0),
                    executable=bool(item.get("executable", False)),
                    signature=str(item.get("signature", "")),
                )
            )
        return SignedManifest(
            manifest_id=str(raw.get("manifest_id", "")),
            app_version=str(raw.get("app_version", "")),
            build_id=str(payload.get("build_id", "")),
            git_commit=str(payload.get("git_commit", "")),
            created_at=str(payload.get("generated_at") or raw.get("created_at") or ""),
            signature="",
            signer_identity=str(raw.get("signed_by") or raw.get("author") or ""),
            file_entries=entries,
            signature_algorithm=str(raw.get("signature_algorithm", "")),
            source_type=str(raw.get("source_type", "source_tree")),
            excluded_patterns=list(raw.get("excluded_runtime_scope") or raw.get("excluded_patterns") or []),
        )

    def _canonical_signature_valid(self) -> bool:
        paths = integrity_manifest_paths(self.root)
        if self.manifest_path.resolve(strict=False) != paths.canonical_manifest.resolve(strict=False):
            return False
        for policy in ("dev", "pre_release", "public_release"):
            validation = validate_signed_manifest(policy, root=self.root)
            if (
                validation.status == "verified"
                and validation.signature_valid is True
                and Path(validation.canonical_manifest_path).resolve(strict=False) == self.manifest_path.resolve(strict=False)
            ):
                return True
        return False

    def log_report(self, report: IntegrityDiffReport, *, user_action_taken: str) -> None:
        try:
            self.logs_dir.mkdir(parents=True, exist_ok=True)
            with (self.logs_dir / "integrity.log").open("a", encoding="utf-8") as handle:
                handle.write(json.dumps({"user_action_taken": user_action_taken, **report.to_dict()}, sort_keys=True) + "\n")
        except OSError:
            LOGGER.debug("Unable to write strict integrity log", exc_info=True)

    def _observed_paths(self, manifest: SignedManifest) -> set[str]:
        observed: set[str] = set()
        for path in iter_integrity_files(self.root, manifest.excluded_patterns):
            try:
                observed.add(path.relative_to(self.root).as_posix())
            except ValueError:
                continue
        return observed

    def _mode(self, path: Path) -> str:
        try:
            return oct(stat.S_IMODE(path.lstat().st_mode))
        except OSError:
            return ""

    def _file_signature(self, path: Path) -> str:
        return ""

    def _change(
        self,
        entry: SignedManifestFileEntry,
        change_type: FileChangeType,
        *,
        actual_hash: str = "",
        actual_mode: str = "",
        actual_signature: str = "",
        severity: str,
        risk: str,
    ) -> FileIntegrityChange:
        return FileIntegrityChange(
            file_path=entry.path,
            change_type=change_type,
            expected_hash=entry.sha256,
            actual_hash=actual_hash,
            expected_mode=entry.mode,
            actual_mode=actual_mode,
            expected_signature=entry.signature,
            actual_signature=actual_signature,
            severity=severity,
            risk_explanation=risk,
            category=entry.category,
        )

    def _severity_for(self, change_type: str, entry: SignedManifestFileEntry) -> str:
        path = entry.path.lower()
        if change_type == "SIGNATURE_CHANGED":
            return "CRITICAL"
        if change_type == "MISSING" and entry.category in {"core", "runtime"}:
            return "CRITICAL"
        if "daemon" in path or "strict_verifier.py" in path or "signed_manifest.py" in path:
            return "CRITICAL"
        if entry.category == "core" and path.endswith(".py"):
            return "HIGH"
        if entry.executable or path.endswith((".plist", ".sh", ".command")):
            return "HIGH"
        if entry.category in {"asset", "template"}:
            return "MEDIUM"
        if path.endswith((".md", ".txt")):
            return "LOW"
        return "MEDIUM"

    def _finalize(self, report: IntegrityDiffReport) -> None:
        severities = [change.severity for change in report.all_changes]
        report.severity_level = _max_severity(severities)
        if report.signature_changes:
            report.status = "modified"
        elif report.missing_files:
            report.status = "missing"
        elif report.extra_files and not (report.hash_mismatches or report.permission_changes):
            report.status = "extra"
        elif report.hash_mismatches or report.permission_changes:
            report.status = "modified"
        else:
            report.status = "verified"
        report.requires_user_acknowledgement = report.status != "verified"
        if report.status == "verified":
            report.explanation_summary = f"Integrity verified. {len(report.unchanged_files)} tracked files match the signed manifest."
        else:
            report.explanation_summary = (
                f"Integrity deviation detected: {len(report.hash_mismatches)} hash mismatch(es), "
                f"{len(report.missing_files)} missing file(s), {len(report.extra_files)} extra file(s), "
                f"{len(report.permission_changes)} permission change(s), and {len(report.signature_changes)} signature change(s)."
            )


def _utc_now_iso() -> str:
    return utc_now().isoformat()


def _max_severity(values: list[str]) -> str:
    order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    if not values:
        return "INFO"
    return max(values, key=lambda item: order.get(item, 0))


def _is_executable(path: Path) -> bool:
    try:
        return bool(stat.S_IMODE(path.lstat().st_mode) & 0o111)
    except OSError:
        return False


def _category_for_extra(path: Path) -> str:
    suffix = path.suffix.lower()
    if path.name in {"monitor.py", "user_notifier.py"}:
        return "runtime"
    if suffix == ".py":
        return "core"
    if suffix in {".png", ".jpg", ".jpeg", ".icns", ".ico"}:
        return "asset"
    if suffix in {".json", ".plist", ".toml", ".yaml", ".yml"}:
        return "template"
    return "core"
