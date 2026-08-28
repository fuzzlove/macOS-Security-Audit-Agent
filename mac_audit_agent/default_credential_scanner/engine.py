from __future__ import annotations

import hashlib
import subprocess
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Callable
from uuid import uuid4
from xml.etree import ElementTree

from mac_audit_agent.models import utc_now_iso
from mac_audit_agent.nmap_wrapper import find_nmap_binary

from .models import CredentialFinding, CredentialScanReport, TargetResult
from .targets import AuthorizedHttpTarget

ALLOWED_CATEGORIES = {"", "web", "routers", "security", "industrial", "printer", "storage", "virtualization", "console"}
MAX_XML_BYTES = 16 * 1024 * 1024


def _elem(table: ElementTree.Element, key: str) -> str:
    node = table.find(f"./elem[@key='{key}']")
    return str(node.text or "") if node is not None else ""


def parse_default_account_xml(
    xml_text: str,
    *,
    scan_id: str,
    target: AuthorizedHttpTarget,
    category: str = "",
) -> list[CredentialFinding]:
    if len(xml_text.encode("utf-8", "replace")) > MAX_XML_BYTES:
        raise ValueError("Nmap XML exceeds the 16 MiB parser limit.")
    root = ElementTree.fromstring(xml_text)
    findings: list[CredentialFinding] = []
    for script in root.findall(".//script[@id='http-default-accounts']"):
        for product in script.findall("./table"):
            product_name = str(product.attrib.get("key", "Unknown HTTP service"))[:300]
            path = _elem(product, "path")[:512] or target.base_path
            cpe = _elem(product, "cpe")[:512]
            credentials = product.find("./table[@key='credentials']")
            if credentials is None:
                continue
            for credential in credentials.findall("./table"):
                username = _elem(credential, "username")[:1024]
                password = _elem(credential, "password")[:4096]
                findings.append(CredentialFinding.create(
                    scan_id=scan_id, target_url=target.url, host=target.host,
                    port=target.port, scheme=target.scheme, product=product_name,
                    category=category or "unspecified", path=path, cpe=cpe,
                    username=username, password=password,
                ))
    return findings


class DefaultCredentialScanner:
    def __init__(
        self,
        fingerprint_path: Path,
        *,
        nmap_path: str | None = None,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
        timeout_seconds: int = 120,
    ) -> None:
        self.fingerprint_path = Path(fingerprint_path)
        self.nmap_path = nmap_path or find_nmap_binary()
        self.runner = runner
        self.timeout_seconds = max(15, min(int(timeout_seconds), 600))

    def readiness(self) -> dict[str, object]:
        fingerprint_ok = self.fingerprint_path.is_file() and not self.fingerprint_path.is_symlink()
        return {
            "ready": bool(self.nmap_path and fingerprint_ok),
            "nmap_path": self.nmap_path or "",
            "fingerprint_path": str(self.fingerprint_path),
            "fingerprints_ready": fingerprint_ok,
        }

    def _command(self, target: AuthorizedHttpTarget, category: str) -> list[str]:
        if not self.nmap_path:
            raise FileNotFoundError("Nmap is not installed. Install with Homebrew: brew install nmap")
        if category not in ALLOWED_CATEGORIES:
            raise ValueError("Unsupported HTTP fingerprint category.")
        fingerprint = self.fingerprint_path.resolve(strict=True)
        if self.fingerprint_path.is_symlink() or not fingerprint.is_file() or fingerprint.stat().st_size > 2 * 1024 * 1024:
            raise ValueError("Fingerprint dataset is unavailable or unsafe.")
        if any(character in str(fingerprint) for character in (",", "\r", "\n")):
            raise ValueError("Fingerprint path cannot be represented safely at the NSE argument boundary.")
        arguments = [
            self.nmap_path, "-sT", "-Pn", "-n", "--max-retries", "2",
            "--host-timeout", f"{self.timeout_seconds}s", "-p", str(target.port),
            # The leading '+' forces this one named script to run on the
            # explicitly supplied port even when version detection cannot
            # label an authenticated or non-standard HTTP service.  It does
            # not select additional scripts or expand network scope.
            "--script", "+http-default-accounts",
        ]
        script_args = [
            f"http-default-accounts.fingerprintfile={fingerprint}",
            f"http-default-accounts.basepath={target.base_path}",
        ]
        if category:
            script_args.append(f"http-default-accounts.category={category}")
        arguments.extend(["--script-args", ",".join(script_args), "-oX", "-"])
        if target.is_ipv6:
            arguments.append("-6")
        arguments.append(target.nmap_host)
        return arguments

    @staticmethod
    def _redact_command(command: list[str]) -> tuple[str, ...]:
        redacted: list[str] = []
        for item in command:
            if "fingerprintfile=" in item:
                parts = []
                for part in item.split(","):
                    parts.append("http-default-accounts.fingerprintfile=<validated-local-dataset>" if "fingerprintfile=" in part else part)
                item = ",".join(parts)
            redacted.append(item)
        return tuple(redacted)

    def scan(
        self,
        targets: Iterable[AuthorizedHttpTarget],
        *,
        authorization_reference: str,
        category: str = "",
        progress: Callable[[int, int, str], None] | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> CredentialScanReport:
        if not authorization_reference.strip():
            raise PermissionError("An authorization reference is required before credential validation.")
        target_list = tuple(targets)
        if not target_list:
            raise ValueError("At least one target is required.")
        if len(target_list) > 100:
            raise ValueError("A single scan is limited to 100 explicitly supplied servers.")
        if not self.readiness()["ready"]:
            raise RuntimeError("Nmap and a validated fingerprint dataset are required.")
        scan_id = f"default-credential-scan-{uuid4().hex}"
        started_at = utc_now_iso()
        target_results: list[TargetResult] = []
        findings: list[CredentialFinding] = []
        errors: list[str] = []
        for index, target in enumerate(target_list, 1):
            if cancelled and cancelled():
                errors.append("Scan cancelled by operator; remaining targets were not tested.")
                break
            if progress:
                progress(index, len(target_list), target.url)
            command = self._command(target, category)
            started = time.monotonic()
            target_findings: list[CredentialFinding] = []
            target_errors: list[str] = []
            status = "NO_DEFAULT_CREDENTIALS_FOUND"
            try:
                completed = self.runner(
                    command, capture_output=True, text=True, check=False,
                    timeout=self.timeout_seconds + 15, shell=False,
                    env={"PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"},
                )
                if completed.returncode != 0:
                    target_errors.append((completed.stderr or f"Nmap exited with {completed.returncode}.")[-4096:])
                if completed.stdout.strip():
                    target_findings = parse_default_account_xml(
                        completed.stdout, scan_id=scan_id, target=target, category=category,
                    )
                if target_findings:
                    status = "DEFAULT_CREDENTIAL_FOUND"
                elif target_errors:
                    status = "ERROR"
            except subprocess.TimeoutExpired:
                status = "TIMEOUT"
                target_errors.append(f"Target exceeded the {self.timeout_seconds}-second timeout.")
            except (ElementTree.ParseError, OSError, ValueError) as exc:
                status = "ERROR"
                target_errors.append(f"{type(exc).__name__}: {exc}")
            duration = max(0.0, time.monotonic() - started)
            findings.extend(target_findings)
            errors.extend(f"{target.url}: {error}" for error in target_errors)
            target_results.append(TargetResult(
                target.url, status, len(target_findings), round(duration, 3),
                self._redact_command(command), tuple(target_errors),
            ))
        fingerprint_sha256 = hashlib.sha256(self.fingerprint_path.read_bytes()).hexdigest()
        version = ""
        if self.nmap_path:
            try:
                version_result = self.runner(
                    [self.nmap_path, "--version"], capture_output=True, text=True,
                    check=False, timeout=5, shell=False,
                )
                version = (version_result.stdout or "").splitlines()[0][:200]
            except Exception:  # noqa: BLE001 - optional version enrichment cannot discard base evidence
                version = "unavailable"
        return CredentialScanReport(
            scan_id, started_at, utc_now_iso(), authorization_reference.strip()[:500],
            fingerprint_sha256, version, tuple(target_results), tuple(findings), tuple(errors),
        )


__all__ = ["ALLOWED_CATEGORIES", "DefaultCredentialScanner", "parse_default_account_xml"]
