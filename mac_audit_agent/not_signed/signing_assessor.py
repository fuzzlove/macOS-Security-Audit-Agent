from __future__ import annotations

import plistlib
from pathlib import Path

from mac_audit_agent.performance.subprocess_runner import BoundedCommandResult, run_bounded_command

from .models import SigningAssessment, SoftwareTrustClassification


def parse_codesign(result: BoundedCommandResult) -> dict[str, object]:
    text = "\n".join((result.stdout, result.stderr))
    values: dict[str, object] = {"valid": result.returncode == 0, "raw": text[:32768]}
    authorities: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("Identifier="): values["identifier"] = line.partition("=")[2]
        elif line.startswith("TeamIdentifier="): values["team_id"] = line.partition("=")[2]
        elif line.startswith("Authority="):
            authority = line.partition("=")[2].strip()
            if authority and authority.lower() not in {"(unavailable)", "unavailable"}:
                authorities.append(authority)
        elif line.startswith("CDHash="): values["cdhash"] = line.partition("=")[2]
        elif line.startswith("Runtime Version="): values["hardened_runtime"] = True
        elif line.startswith("Signature="): values["signature_type"] = line.partition("=")[2].strip().lower()
        elif line.startswith("CodeDirectory") and "flags=" in line:
            values["code_directory"] = line
            values["platform_binary"] = "platform" in line.lower()
        elif line.startswith("Platform identifier="): values["platform_binary"] = True
        elif line.startswith("Designated =>"): values["designated_requirement"] = line.partition("=>")[2].strip()
        elif "code object is not signed" in line.lower(): values["unsigned"] = True
        elif "resource envelope is obsolete" in line.lower() or "modified" in line.lower(): values["modified"] = True
    values["authorities"] = tuple(authorities)
    values["ad_hoc"] = values.get("signature_type") == "adhoc"
    requirement = str(values.get("designated_requirement") or "").lower()
    authority_text = " ".join(authorities).lower()
    values["apple_requirement"] = "anchor apple" in requirement and "generic" not in requirement
    values["apple_authority"] = any(
        marker in authority_text
        for marker in ("apple code signing certification authority", "apple root ca", "software signing")
    )
    return values


def parse_spctl(result: BoundedCommandResult) -> dict[str, object]:
    text = "\n".join((result.stdout, result.stderr))
    lower = text.lower()
    source = next((line.partition("=")[2].strip() for line in text.splitlines() if line.strip().lower().startswith("source=")), "")
    return {
        "accepted": True if result.returncode == 0 and "accepted" in lower else (False if "rejected" in lower or result.returncode else None),
        "source": source,
        "notarized": True if "notarized developer id" in source.lower() else None,
        "revoked": "revoked" in lower,
        "raw": text[:32768],
    }


class SigningAssessor:
    def assess(self, path: Path) -> SigningAssessment:
        if path.is_symlink() or not path.exists():
            return SigningAssessment(SoftwareTrustClassification.UNKNOWN, None, None, None, assessment_errors=("inaccessible_or_symlink",))
        verify = run_bounded_command(["/usr/bin/codesign", "--verify", "--deep", "--strict", "--verbose=4", str(path)], timeout_seconds=12, max_output_bytes=65536, env={"LC_ALL": "C", "LANG": "C"})
        detail = run_bounded_command(["/usr/bin/codesign", "-d", "--verbose=4", str(path)], timeout_seconds=8, max_output_bytes=65536, env={"LC_ALL": "C", "LANG": "C"})
        requirement = run_bounded_command(["/usr/bin/codesign", "-d", "-r-", str(path)], timeout_seconds=8, max_output_bytes=65536, env={"LC_ALL": "C", "LANG": "C"})
        gatekeeper = run_bounded_command(["/usr/sbin/spctl", "--assess", "--type", "execute", "--verbose=4", str(path)], timeout_seconds=12, max_output_bytes=65536, env={"LC_ALL": "C", "LANG": "C"})
        code = parse_codesign(detail)
        requirement_text = "\n".join((requirement.stdout, requirement.stderr))
        for line in requirement_text.splitlines():
            if line.strip().startswith("designated =>"):
                code["designated_requirement"] = line.partition("=>")[2].strip()
                code["apple_requirement"] = "anchor apple" in str(code["designated_requirement"]).lower() and "generic" not in str(code["designated_requirement"]).lower()
        code["valid"] = verify.returncode == 0
        code["verify_raw"] = "\n".join((verify.stdout, verify.stderr))[:32768]
        gate = parse_spctl(gatekeeper)
        receipt, receipt_error = self._receipt(path)
        classification = self._classify(path, code, gate, receipt)
        errors = tuple(value for value in (verify.error, detail.error, requirement.error, gatekeeper.error, receipt_error) if value)
        trust_unavailable = "cssmerr_tp_not_trusted" in str(code.get("verify_raw", "")).lower()
        signature_valid = bool(code["valid"])
        if classification == SoftwareTrustClassification.APPLE_PLATFORM and trust_unavailable:
            signature_valid = None
        return SigningAssessment(
            classification, signature_valid if code.get("raw") else None,
            gate["accepted"], gate["notarized"], "confirmed" if classification == SoftwareTrustClassification.MAC_APP_STORE else ("not_mac_app_store" if receipt is False else "unknown"),
            str(code.get("identifier") or "") or None, str(code.get("team_id") or "") or None,
            tuple(code.get("authorities", ())), str(code.get("cdhash") or "") or None,
            bool(code.get("hardened_runtime")) if "hardened_runtime" in code else None, {}, errors,
            raw_evidence={"codesign": code, "designated_requirement": requirement_text[:32768], "gatekeeper": gate, "receipt_present": receipt},
        )

    @staticmethod
    def _receipt(path: Path) -> tuple[bool | None, str]:
        bundle = path if path.suffix == ".app" else next((parent for parent in path.parents if parent.suffix == ".app"), None)
        if not bundle: return False, ""
        receipt = bundle / "Contents/_MASReceipt/receipt"
        try: return receipt.is_file() and receipt.stat().st_size > 0, ""
        except OSError as exc: return None, str(exc)

    @staticmethod
    def _classify(path: Path, code: dict[str, object], gate: dict[str, object], receipt: bool | None) -> SoftwareTrustClassification:
        raw = str(code.get("raw", "")).lower() + str(code.get("verify_raw", "")).lower()
        authorities = " ".join(code.get("authorities", ())).lower()
        if gate.get("revoked"): return SoftwareTrustClassification.REVOKED
        if code.get("unsigned") or "not signed at all" in raw: return SoftwareTrustClassification.UNSIGNED
        apple_path = str(path).startswith(("/System/", "/usr/", "/bin/", "/sbin/", "/Library/Apple/"))
        apple_identity = bool(code.get("platform_binary") or code.get("apple_requirement") or code.get("apple_authority"))
        gate_source = str(gate.get("source") or "").lower()
        integrity_failure = any(marker in raw for marker in (
            "sealed resource is missing", "resource envelope is obsolete", "code has no resources but signature indicates they must be present",
            "a sealed resource is missing or invalid", "file modified",
        ))
        if integrity_failure:
            return SoftwareTrustClassification.INVALID
        if apple_path and (apple_identity or gate_source in {"apple system", "apple internal"}):
            return SoftwareTrustClassification.APPLE_PLATFORM
        if not code.get("valid"): return SoftwareTrustClassification.INVALID if raw else SoftwareTrustClassification.UNKNOWN
        app_store_authority = "apple mac os application signing" in authorities or gate_source == "mac app store"
        if receipt and gate.get("accepted") and app_store_authority:
            return SoftwareTrustClassification.MAC_APP_STORE
        if "developer id application" in authorities:
            return SoftwareTrustClassification.DEVELOPER_ID_NOTARIZED if gate.get("notarized") is True else SoftwareTrustClassification.DEVELOPER_ID_VALID
        if code.get("ad_hoc"): return SoftwareTrustClassification.AD_HOC
        return SoftwareTrustClassification.UNKNOWN
