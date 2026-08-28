from __future__ import annotations

import hashlib
import json
import platform
import re
import shutil
import zipfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mac_audit_agent.remediation.recommendation_engine import enrich_finding_with_recommendation


EXPORT_PROFILES = [
    "General Apple Support Evidence",
    "Apple Feedback Assistant Evidence",
    "Apple Security / Vulnerability Evidence",
    "Network / Wireless Diagnostics Evidence",
    "Crash / App Hang Evidence",
    "Hardware / Apple Diagnostics Evidence Checklist",
    "False Positive Review Package",
    "Custom Evidence Package",
]

PRIVACY_WARNING = "Apple diagnostic packages may contain sensitive system information. Review the package before sharing."


@dataclass
class CollectedArtifact:
    name: str
    path: str
    sha256: str
    size: int
    artifact_type: str
    privacy_note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AppleEvidencePackage:
    package_id: str
    created_at: str
    finding_id: str = ""
    export_profile: str = "General Apple Support Evidence"
    app_version: str = ""
    macos_version: str = ""
    hardware_model: str = ""
    serial_redacted: str = "redacted"
    user_redaction_level: str = "standard"
    collected_artifacts: list[CollectedArtifact] = field(default_factory=list)
    skipped_artifacts: list[dict[str, str]] = field(default_factory=list)
    privacy_review_required: bool = True
    manifest_path: str = ""
    manifest_hash: str = ""
    package_hash: str = ""
    archive_path: str = ""
    integrity_receipt_path: str = ""

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["collected_artifacts"] = [item.to_dict() for item in self.collected_artifacts]
        return payload


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def default_export_dir() -> Path:
    return Path.home() / "Library" / "Application Support" / "MacAuditAgent" / "apple_evidence_exports"


def export_apple_evidence_package(
    finding: dict[str, Any] | None = None,
    *,
    export_profile: str = "General Apple Support Evidence",
    output_dir: Path | None = None,
    redaction_level: str = "standard",
    app_version: str = "",
    extra_context: dict[str, Any] | None = None,
    screenshot_path: Path | None = None,
    create_archive: bool = True,
) -> AppleEvidencePackage:
    if export_profile not in EXPORT_PROFILES:
        export_profile = "Custom Evidence Package"
    finding_payload = enrich_finding_with_recommendation(finding or {}) if finding else {}
    extra_context = extra_context or {}
    package_id = f"apple-evidence-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')}-{_short_hash(finding_payload or extra_context)}"
    package_dir = (output_dir or default_export_dir()) / package_id
    package_dir.mkdir(parents=True, exist_ok=True)

    redacted_finding = redact_payload(finding_payload, redaction_level=redaction_level)
    artifacts: list[CollectedArtifact] = []
    skipped: list[dict[str, str]] = []
    _write_artifact(package_dir / "msaa_finding.json", json.dumps(redacted_finding, indent=2, sort_keys=True), artifacts, "finding_json", "Finding data is redacted according to selected privacy level.")
    _write_artifact(package_dir / "evidence_summary.md", _evidence_summary(redacted_finding, export_profile), artifacts, "report_excerpt", "Human-readable summary for manual review.")
    _write_artifact(package_dir / "reproduction_steps_template.md", _reproduction_template(export_profile), artifacts, "template", "User should complete before sharing where relevant.")
    _write_artifact(package_dir / "privacy_review.md", _privacy_review_text(redaction_level), artifacts, "privacy_review", "Review before sharing with Apple, a vendor, or internal analysts.")
    _write_artifact(package_dir / "apple_workflow_guidance.md", _apple_workflow_guidance(export_profile), artifacts, "instructions", "Instructions only; MSAA does not submit anything automatically.")
    if extra_context:
        _write_artifact(
            package_dir / "apple_diagnostic_context.json",
            json.dumps(redact_payload(extra_context, redaction_level=redaction_level), indent=2, sort_keys=True, default=str),
            artifacts,
            "diagnostic_context",
            "Read-only hardware, macOS, and collection context; privacy redaction was applied before packaging.",
        )
    if screenshot_path is not None:
        _copy_screenshot_artifact(screenshot_path, package_dir / "watermarked_screen_capture.png", artifacts)

    if export_profile == "Network / Wireless Diagnostics Evidence":
        _write_artifact(package_dir / "wireless_diagnostics_instructions.md", _wireless_diagnostics_text(), artifacts, "instructions", "Wireless Diagnostics package must be added manually by the user if collected.")
    if export_profile == "Hardware / Apple Diagnostics Evidence Checklist":
        _write_artifact(package_dir / "apple_diagnostics_checklist.md", _hardware_diagnostics_text(), artifacts, "checklist", "Includes field for user-entered Apple Diagnostics reference code.")
    if export_profile in {"Apple Security / Vulnerability Evidence", "Apple Feedback Assistant Evidence"}:
        _write_artifact(package_dir / "security_vulnerability_template.md", _security_reporting_text(redacted_finding), artifacts, "template", "No CVE or Apple verification is claimed unless present in evidence.")

    package = AppleEvidencePackage(
        package_id=package_id,
        created_at=utc_now_iso(),
        finding_id=str(finding_payload.get("id") or finding_payload.get("finding_id") or ""),
        export_profile=export_profile,
        app_version=app_version,
        macos_version=platform.mac_ver()[0] or str(extra_context.get("macos_version", "")),
        hardware_model=str(extra_context.get("hardware_model", platform.machine())),
        serial_redacted="redacted",
        user_redaction_level=redaction_level,
        collected_artifacts=artifacts,
        skipped_artifacts=skipped,
        privacy_review_required=True,
    )
    manifest_path = package_dir / "manifest.json"
    package.manifest_path = str(manifest_path)
    manifest_payload = package.to_dict()
    manifest_payload["privacy_warning"] = PRIVACY_WARNING
    manifest_payload["no_auto_submission"] = True
    manifest_payload["integrity_model"] = (
        "SHA-256 tamper-evident package with read-only local permissions. It is not immutable and does not provide an Apple or third-party timestamp. "
        "Retain the hash receipt separately to detect later changes."
    )
    manifest_payload["chain_of_custody"] = [
        {
            "timestamp": package.created_at,
            "action": "COLLECTED_AND_SEALED",
            "package_id": package.package_id,
            "artifact_count": len(artifacts),
        }
    ]
    manifest_payload["artifact_hashes"] = {Path(item.path).name: item.sha256 for item in artifacts}
    manifest_path.write_text(json.dumps(manifest_payload, indent=2, sort_keys=True), encoding="utf-8")
    package.manifest_hash = _sha256_file(manifest_path)
    manifest_receipt = manifest_path.with_suffix(".json.sha256")
    manifest_receipt.write_text(f"{package.manifest_hash}  {manifest_path.name}\n", encoding="utf-8")
    package.collected_artifacts.append(_artifact_for_path(manifest_path, "manifest", "Manifest with hashes and chain-of-custody metadata."))
    package.collected_artifacts.append(_artifact_for_path(manifest_receipt, "integrity_receipt", "Keep this SHA-256 receipt separate when stronger custody evidence is required."))
    if create_archive:
        archive_path = package_dir.with_suffix(".zip")
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(package_dir.rglob("*")):
                if path.is_file():
                    archive.write(path, path.relative_to(package_dir.parent))
        package.archive_path = str(archive_path)
        package.package_hash = _sha256_file(archive_path)
        archive_receipt = archive_path.with_suffix(".zip.sha256")
        archive_receipt.write_text(f"{package.package_hash}  {archive_path.name}\n", encoding="utf-8")
        package.integrity_receipt_path = str(archive_receipt)
        archive_path.chmod(0o400)
        archive_receipt.chmod(0o400)
    else:
        package.package_hash = _hash_directory(package_dir)
        package.integrity_receipt_path = str(manifest_receipt)
    for item in package_dir.rglob("*"):
        if item.is_file():
            item.chmod(0o400)
    package_dir.chmod(0o700)
    return package


def redact_payload(payload: Any, *, redaction_level: str = "standard") -> Any:
    if redaction_level.lower() in {"none", "full technical"}:
        return payload
    text = json.dumps(payload, sort_keys=True, default=str)
    username = Path.home().name
    if username:
        text = text.replace(f"/Users/{username}", "/Users/<redacted>")
        text = text.replace(username, "<redacted-user>")
    text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<redacted-ip>", text)
    text = re.sub(r"\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\b", "<redacted-mac>", text)
    text = re.sub(r'"serial(?:_number)?"\s*:\s*"[^"]+"', '"serial": "<redacted-serial>"', text, flags=re.IGNORECASE)
    text = re.sub(r'"environment"\s*:\s*\{[^{}]*\}', '"environment": "<redacted-environment>"', text, flags=re.IGNORECASE)
    if redaction_level.lower() == "minimal":
        text = re.sub(r'"/Users/<redacted>/[^"]+"', '"/Users/<redacted>/<path-redacted>"', text)
    return json.loads(text)


def _write_artifact(path: Path, content: str, artifacts: list[CollectedArtifact], artifact_type: str, privacy_note: str) -> None:
    path.write_text(content, encoding="utf-8")
    artifacts.append(_artifact_for_path(path, artifact_type, privacy_note))


def _copy_screenshot_artifact(source: Path, destination: Path, artifacts: list[CollectedArtifact]) -> None:
    source = Path(source)
    if source.is_symlink() or not source.is_file():
        raise ValueError("Screenshot evidence must be a regular local file.")
    if source.stat().st_size > 64 * 1024 * 1024:
        raise ValueError("Screenshot evidence exceeds the 64 MiB limit.")
    with source.open("rb") as handle:
        if handle.read(8) != b"\x89PNG\r\n\x1a\n":
            raise ValueError("Screenshot evidence must be a PNG image.")
    shutil.copyfile(source, destination)
    artifacts.append(
        _artifact_for_path(
            destination,
            "watermarked_screen_capture",
            "User-approved primary-display capture with a red MSAA evidence watermark; review visible content before sharing.",
        )
    )


def verify_apple_evidence_package(package_or_manifest: AppleEvidencePackage | str | Path) -> dict[str, Any]:
    package = package_or_manifest if isinstance(package_or_manifest, AppleEvidencePackage) else None
    manifest_path = Path(package.manifest_path) if package else Path(package_or_manifest)
    if manifest_path.is_dir():
        manifest_path = manifest_path / "manifest.json"
    checks: list[dict[str, Any]] = []
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"valid": False, "manifest_path": str(manifest_path), "checks": [], "error": str(exc)}

    receipt_path = manifest_path.with_suffix(".json.sha256")
    expected_manifest = receipt_path.read_text(encoding="utf-8").split()[0] if receipt_path.is_file() else ""
    actual_manifest = _sha256_file(manifest_path)
    checks.append({"artifact": manifest_path.name, "valid": bool(expected_manifest) and expected_manifest == actual_manifest, "expected_sha256": expected_manifest, "actual_sha256": actual_manifest})
    for name, expected in dict(manifest.get("artifact_hashes", {})).items():
        safe_name = Path(str(name)).name
        artifact_path = manifest_path.parent / safe_name
        actual = _sha256_file(artifact_path) if safe_name == str(name) and artifact_path.is_file() else "missing"
        checks.append({"artifact": safe_name, "valid": actual == str(expected), "expected_sha256": str(expected), "actual_sha256": actual})

    archive_valid: bool | None = None
    if package and package.archive_path:
        archive_path = Path(package.archive_path)
        archive_actual = _sha256_file(archive_path) if archive_path.is_file() else "missing"
        archive_valid = bool(package.package_hash) and archive_actual == package.package_hash
        checks.append({"artifact": archive_path.name, "valid": archive_valid, "expected_sha256": package.package_hash, "actual_sha256": archive_actual})
    return {
        "valid": bool(checks) and all(bool(item["valid"]) for item in checks),
        "manifest_path": str(manifest_path),
        "manifest_sha256": actual_manifest,
        "archive_valid": archive_valid,
        "checks": checks,
        "integrity_qualification": "Tamper-evident under retained-hash custody; local files are not immutable.",
    }


def _artifact_for_path(path: Path, artifact_type: str, privacy_note: str) -> CollectedArtifact:
    return CollectedArtifact(name=path.name, path=str(path), sha256=_sha256_file(path), size=path.stat().st_size, artifact_type=artifact_type, privacy_note=privacy_note)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _hash_directory(path: Path) -> str:
    digest = hashlib.sha256()
    for item in sorted(path.rglob("*")):
        if item.is_file():
            digest.update(item.relative_to(path).as_posix().encode("utf-8"))
            digest.update(_sha256_file(item).encode("utf-8"))
    return digest.hexdigest()


def _short_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:8]


def _evidence_summary(finding: dict[str, Any], profile: str) -> str:
    fix = finding.get("recommended_fix", {}) if isinstance(finding.get("recommended_fix"), dict) else {}
    return "\n".join(
        [
            "# MSAA Apple Evidence Summary",
            "",
            f"Export profile: {profile}",
            f"Finding: {finding.get('title', 'No specific finding selected')}",
            f"Severity: {finding.get('severity', '')}",
            f"Category: {finding.get('category', '')}",
            "",
            "## Technical Evidence",
            str(finding.get("evidence_summary") or finding.get("evidence") or "No finding evidence supplied."),
            "",
            "## Recommended Fix",
            str(fix.get("recommended_fix") or finding.get("remediation_suggestion") or "Manual review required."),
            "",
            "## Evidence To Collect",
            "\n".join(f"- {item}" for item in fix.get("evidence_to_collect", ["MSAA report excerpt", "macOS version/build", "reproduction notes"])),
        ]
    )


def _reproduction_template(profile: str) -> str:
    return "\n".join(
        [
            "# Reproduction Steps",
            "",
            f"Profile: {profile}",
            "",
            "1. What were you doing before the issue appeared?",
            "2. Exact steps to reproduce:",
            "3. Expected behavior:",
            "4. Actual behavior:",
            "5. Frequency:",
            "6. Date/time and timezone:",
            "7. Recent updates, installs, peripherals, or network changes:",
        ]
    )


def _privacy_review_text(redaction_level: str) -> str:
    return "\n".join(
        [
            "# Privacy Review",
            "",
            PRIVACY_WARNING,
            "",
            f"Selected redaction level: {redaction_level}",
            "",
            "Review for usernames, hostnames, IP addresses, MAC addresses, SSIDs, serial numbers, command lines, file paths, tokens, private keys, browser data, passwords, and personal files before sharing.",
            "MSAA does not upload this package or submit it to Apple.",
        ]
    )


def _apple_workflow_guidance(profile: str) -> str:
    return "\n".join(
        [
            "# Apple Workflow Guidance",
            "",
            "MSAA does not submit reports automatically.",
            "For Feedback Assistant, attach this package manually and allow Apple diagnostics collection only if you choose.",
            "For Apple Support, provide the user-facing summary and any requested diagnostics manually.",
            "For Apple Security reporting, include impact, affected versions, reproduction steps, evidence archive, and responsible disclosure context.",
            f"Selected package profile: {profile}",
        ]
    )


def _wireless_diagnostics_text() -> str:
    return "Use Apple's Wireless Diagnostics to analyze Wi-Fi issues. It does not change network settings. Add the generated diagnostics package manually after privacy review."


def _hardware_diagnostics_text() -> str:
    return "\n".join(["# Hardware / Apple Diagnostics Checklist", "", "- Hardware model:", "- Apple Diagnostics reference code:", "- Peripherals connected:", "- Symptoms:", "- Date/time run:", "- Follow-up with Apple Support:"])


def _security_reporting_text(finding: dict[str, Any]) -> str:
    cves = finding.get("cve_ids") or finding.get("cve_refs") or []
    return "\n".join(
        [
            "# Apple Security / Vulnerability Evidence",
            "",
            f"CVE status: {', '.join(str(item) for item in cves) if cves else 'No CVE assigned by MSAA.'}",
            "Impact statement:",
            "Affected versions:",
            "Reproduction steps:",
            "Exploitability evidence:",
            "Mitigation attempts:",
            "False-positive checks completed:",
            "",
            "Do not claim Apple verified this finding unless Apple has done so separately.",
        ]
    )


def remove_export_package(package: AppleEvidencePackage) -> None:
    if package.archive_path:
        archive_path = Path(package.archive_path)
        if archive_path.exists():
            archive_path.chmod(0o600)
            archive_path.unlink()
    if package.integrity_receipt_path:
        receipt_path = Path(package.integrity_receipt_path)
        if receipt_path.exists():
            receipt_path.chmod(0o600)
            receipt_path.unlink()
    if package.manifest_path:
        package_dir = Path(package.manifest_path).parent
        if package_dir.exists():
            package_dir.chmod(0o700)
            for item in package_dir.rglob("*"):
                if item.is_file():
                    item.chmod(0o600)
                elif item.is_dir():
                    item.chmod(0o700)
            shutil.rmtree(package_dir)
