from __future__ import annotations

import hashlib
import html
import json
import os
import re
import ssl
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from .yara_backend import YaraBackend

MAX_DOWNLOAD_BYTES = 2 * 1024 * 1024
ALLOWED_OFFICIAL_HOSTS = {"cisa.gov", "www.cisa.gov"}
DEFAULT_RULE_ROOT = Path("/Library/Application Support/MacAuditAgent/yara")


@dataclass(frozen=True)
class OfficialYaraSource:
    source_id: str
    title: str
    url: str
    publisher: str
    expected_rules: tuple[str, ...]


OFFICIAL_SOURCES = (
    OfficialYaraSource("cisa_truebot_2023", "CISA Truebot Advisory AA23-187A", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-187a", "CISA", ("CISA_10445155_01",)),
    OfficialYaraSource("cisa_play_ransomware", "CISA StopRansomware: Play Ransomware AA23-352A", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a", "CISA", ("PlayForESXi",)),
)


@dataclass(frozen=True)
class RulePackageRecord:
    package_id: str
    channel: str
    publisher: str
    source_url: str
    sha256: str
    rule_names: tuple[str, ...]
    installed_at_utc: str
    approved_by: str = ""


class YaraRuleValidationError(ValueError): pass


def _validated_package_id(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value):
        raise YaraRuleValidationError("Package ID must use only letters, numbers, dot, underscore, or hyphen.")
    return value


def extract_rule_names(source: str) -> tuple[str, ...]:
    # Preserve duplicates so validation can reject collisions within one
    # package. Namespace isolation handles identical names across sources.
    return tuple(re.findall(r"(?m)^\s*(?:private\s+|global\s+)*rule\s+([A-Za-z_][A-Za-z0-9_]*)\b", source))


def validate_yara_source(source: str, *, maximum_bytes: int = 512 * 1024, maximum_rules: int = 250) -> tuple[str, ...]:
    encoded = source.encode("utf-8")
    if not encoded or len(encoded) > maximum_bytes: raise YaraRuleValidationError("YARA source is empty or exceeds the package limit.")
    if "\x00" in source: raise YaraRuleValidationError("YARA source contains a NUL byte.")
    if re.search(r"(?mi)^\s*include\s+", source): raise YaraRuleValidationError("YARA include directives are disabled; packages must be self-contained.")
    imports = re.findall(r'(?mi)^\s*import\s+"([^"]+)"', source)
    if any(module not in {"pe", "elf", "hash", "math"} for module in imports): raise YaraRuleValidationError("YARA package requests a non-allowlisted module.")
    names = extract_rule_names(source)
    if not names or len(names) > maximum_rules: raise YaraRuleValidationError("YARA package has no rules or too many rules.")
    if len(set(names)) != len(names): raise YaraRuleValidationError("YARA rule names must be unique within a package.")
    return names


def _extract_named_rule(document: str, name: str) -> str:
    # CISA pages render advisory code as HTML. Normalize it to text, then use a
    # bounded brace walk rather than executing or interpreting page content.
    text = html.unescape(re.sub(r"<[^>]{0,2048}>", " ", document))
    match = re.search(rf"\brule\s+{re.escape(name)}\b[^{{]*{{", text)
    if not match: raise YaraRuleValidationError(f"Expected official rule {name} was not present.")
    depth = 1; index = match.end()
    while index < len(text) and depth:
        if text[index] == "{": depth += 1
        elif text[index] == "}": depth -= 1
        index += 1
    if depth: raise YaraRuleValidationError(f"Official rule {name} was truncated.")
    return text[match.start():index]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        host = (urlparse(newurl).hostname or "").lower().rstrip(".")
        if urlparse(newurl).scheme != "https" or host not in ALLOWED_OFFICIAL_HOSTS: raise YaraRuleValidationError("Official rule redirect left the allowlist.")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class YaraRuleManager:
    def __init__(self, root: Path = DEFAULT_RULE_ROOT, *, backend: YaraBackend | None = None):
        self.root = Path(root); self.backend = backend or YaraBackend()
        self.test_dir = self.root / "test"; self.active_dir = self.root / "active"; self.records_dir = self.root / "records"

    def _write_package(self, source: str, record: RulePackageRecord) -> RulePackageRecord:
        _validated_package_id(record.package_id)
        destination = self.test_dir if record.channel == "test" else self.active_dir
        destination.mkdir(parents=True, exist_ok=True); self.records_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(destination, 0o700); os.chmod(self.records_dir, 0o700)
        (destination / f"{record.package_id}.yar").write_text(source, encoding="utf-8")
        (self.records_dir / f"{record.package_id}-{record.channel}.json").write_text(json.dumps(asdict(record), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.chmod(destination / f"{record.package_id}.yar", 0o600)
        return record

    def stage(self, source: str, *, package_id: str, publisher: str, source_url: str = "") -> RulePackageRecord:
        package_id = _validated_package_id(package_id)
        names = validate_yara_source(source)
        compiled = self.backend.compile({package_id: source}); compiled.match(data=b"MSAA harmless YARA validation fixture", timeout=2)
        record = RulePackageRecord(package_id, "test", publisher, source_url, hashlib.sha256(source.encode()).hexdigest(), names, datetime.now(timezone.utc).isoformat())
        return self._write_package(source, record)

    def promote(self, package_id: str, *, approved_by: str) -> RulePackageRecord:
        package_id = _validated_package_id(package_id)
        if not approved_by.strip(): raise PermissionError("Named approval is required before activating a test rule package.")
        source_path = self.test_dir / f"{package_id}.yar"
        if not source_path.is_file() or source_path.is_symlink(): raise FileNotFoundError("Staged rule package is unavailable.")
        source = source_path.read_text(encoding="utf-8"); names = validate_yara_source(source)
        compiled = self.backend.compile({package_id: source}); compiled.match(data=b"MSAA harmless YARA promotion fixture", timeout=2)
        record = RulePackageRecord(package_id, "active", "locally-reviewed", "", hashlib.sha256(source.encode()).hexdigest(), names, datetime.now(timezone.utc).isoformat(), approved_by.strip())
        return self._write_package(source, record)

    def refresh_official(self, source: OfficialYaraSource, *, opener=None) -> RulePackageRecord:
        parsed = urlparse(source.url); host = (parsed.hostname or "").lower().rstrip(".")
        if parsed.scheme != "https" or host not in ALLOWED_OFFICIAL_HOSTS: raise YaraRuleValidationError("Official source URL is not allowlisted.")
        request = urllib.request.Request(source.url, headers={"User-Agent": "MSAA-YARA-ProofOfConcept/1.0", "Accept": "text/html"})
        client = opener or urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
        with client.open(request, timeout=15) as response:
            status = int(getattr(response, "status", response.getcode()))
            if status != 200: raise YaraRuleValidationError(f"Official source returned HTTP {status}.")
            data = response.read(MAX_DOWNLOAD_BYTES + 1)
        if len(data) > MAX_DOWNLOAD_BYTES: raise YaraRuleValidationError("Official source exceeded the response limit.")
        document = data.decode("utf-8", "strict")
        rules = "\n\n".join(_extract_named_rule(document, name) for name in source.expected_rules)
        return self.stage(rules, package_id=source.source_id, publisher=source.publisher, source_url=source.url)

    def active_sources(self) -> dict[str, str]:
        if not self.active_dir.is_dir(): return {}
        sources = {}
        for path in sorted(self.active_dir.glob("*.yar"))[:250]:
            if path.is_file() and not path.is_symlink() and path.stat().st_size <= 512 * 1024:
                try:
                    source = path.read_text(encoding="utf-8")
                    validate_yara_source(source)
                    self.backend.compile({path.stem: source})
                except (OSError, UnicodeDecodeError, YaraRuleValidationError, RuntimeError, ValueError):
                    # A broken custom/legacy package must not prevent the signed
                    # core release from loading through ActiveMacOSMalwareDatabase.
                    continue
                sources[path.stem] = source
        return sources

    def compile_active(self):
        sources = self.active_sources()
        return self.backend.compile(sources) if sources else None
