from __future__ import annotations

import csv
import importlib.metadata
import hashlib
import sys
from pathlib import Path
from typing import Any

from mac_audit_agent.integrity.verifier import IntegrityVerificationResult, utc_now_iso, verify_integrity_manifest


def installed_record_rows(distribution_name: str = "mac-audit-agent") -> list[dict[str, str]]:
    try:
        dist = importlib.metadata.distribution(distribution_name)
    except importlib.metadata.PackageNotFoundError:
        return []
    record = next((file for file in dist.files or [] if str(file).endswith(".dist-info/RECORD")), None)
    if record is None:
        return []
    record_path = Path(dist.locate_file(record))
    if not record_path.exists():
        return []
    with record_path.open("r", encoding="utf-8", newline="") as handle:
        return [{"path": row[0], "hash": row[1], "size": row[2]} for row in csv.reader(handle) if row]


def verify_wheel_record(distribution_name: str = "mac-audit-agent") -> dict[str, Any]:
    rows = installed_record_rows(distribution_name)
    if not rows:
        return IntegrityVerificationResult(
            result_id="msaa-wheel-record-unavailable",
            checked_at=utc_now_iso(),
            manifest_path="dist-info/RECORD",
            source_type="pypi_wheel",
            overall_status="unknown",
            errors=["Installed package RECORD metadata is unavailable."],
            recommended_actions=["Use a trusted package manifest or reinstall from a trusted package source."],
        ).to_dict()
    matched = mismatched = missing = skipped = 0
    file_results: list[dict[str, Any]] = []
    try:
        dist = importlib.metadata.distribution(distribution_name)
    except importlib.metadata.PackageNotFoundError:
        dist = None
    for row in rows:
        rel = row.get("path", "")
        expected_hash = row.get("hash", "")
        if not dist or not rel or not expected_hash.startswith("sha256="):
            skipped += 1
            continue
        path = Path(dist.locate_file(rel))
        if not path.exists():
            missing += 1
            file_results.append({"relative_path": rel, "verification_status": "missing"})
            continue
        digest = hashlib.sha256(path.read_bytes()).digest()
        import base64

        observed = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
        expected = expected_hash.removeprefix("sha256=")
        if observed == expected:
            matched += 1
            file_results.append({"relative_path": rel, "verification_status": "match"})
        else:
            mismatched += 1
            file_results.append({"relative_path": rel, "verification_status": "mismatch"})
    status = "modified" if mismatched or missing else ("partial" if skipped else "verified")
    return IntegrityVerificationResult(
        result_id="msaa-wheel-record-verification",
        checked_at=utc_now_iso(),
        manifest_path="dist-info/RECORD",
        source_type="pypi_wheel",
        overall_status=status,
        matched_count=matched,
        mismatched_count=mismatched,
        missing_count=missing,
        skipped_count=skipped,
        file_results=file_results,
        recommended_actions=["Reinstall from a trusted package source if mismatches are unexpected."] if status != "verified" else ["Wheel RECORD entries matched."],
    ).to_dict()


def verify_pyinstaller_app(manifest_path: Path | None = None, root: Path | None = None):
    app_root = root or Path(getattr(sys, "_MEIPASS", Path(sys.executable).resolve().parent))
    manifest = manifest_path or app_root / "integrity_manifest.json"
    return verify_integrity_manifest(manifest, root=app_root, expected_source_type="pyinstaller_app")
