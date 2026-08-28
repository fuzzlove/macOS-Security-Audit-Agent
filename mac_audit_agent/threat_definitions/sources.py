"""Isolated, policy-described source adapters for defensive intelligence feeds."""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import os
import re
import socket
import ssl
import stat
import zipfile
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, ClassVar, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from .credentials import (
    ABUSE_CH_AUTH_ENV,
    CredentialValidationError,
    load_abuse_ch_auth_key,
)
from .models import (
    DefinitionAction,
    DefinitionProvenance,
    DefinitionTrustLevel,
    DefinitionType,
    RawDefinitionPackage,
    Severity,
    SourcePolicy,
    ThreatDefinition,
    TrustClass,
    UpdateMetadata,
    utc_now,
)
from .normalization import NormalizationError, definition_id, normalize_value


class SourceAdapterError(RuntimeError):
    pass


class ThreatSourceAdapter(Protocol):
    @property
    def source_id(self) -> str: ...
    @property
    def policy(self) -> SourcePolicy: ...
    def check_for_updates(self) -> UpdateMetadata: ...
    def download(self) -> RawDefinitionPackage: ...
    def parse(self, package: RawDefinitionPackage) -> list[ThreatDefinition]: ...


Fetcher = Callable[..., tuple[bytes, str, dict[str, str]]]
ABUSE_CH_FREE_KEY_URL = "https://auth.abuse.ch/"


def _verified_tls_context() -> ssl.SSLContext:
    """Return a verified context with system and packaged CA roots when present."""

    context = ssl.create_default_context()
    try:
        import certifi

        # Some framework/Homebrew Python builds expose a partial system trust
        # store.  Loading certifi in addition to those roots avoids mistaking a
        # non-empty but incomplete store for a usable public-web PKI bundle.
        context.load_verify_locations(cafile=certifi.where())
    except (ImportError, OSError):
        # Keep verification enabled. The request will fail closed with an
        # actionable certificate error instead of silently trusting the peer.
        pass
    return context


def redact_source_url(url: str) -> str:
    """Remove provider credentials embedded in export URL path segments."""
    parsed = urlsplit(url)
    parts = parsed.path.split("/")
    if "exports" in parts:
        index = parts.index("exports")
        if len(parts) > index + 1:
            parts[index + 1] = "REDACTED"
    return urlunsplit((parsed.scheme, parsed.netloc, "/".join(parts), "", ""))


def _validate_remote_url(url: str, *, resolve: bool) -> tuple[str, int]:
    try:
        parsed = urlsplit(url)
        port = parsed.port or 443
    except ValueError as exc:
        raise SourceAdapterError("definition source URL is invalid") from exc
    if parsed.scheme.lower() != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise SourceAdapterError("definition sources require credential-free HTTPS URLs")
    hostname = parsed.hostname.rstrip(".").lower()
    if hostname in {"localhost", "localhost.localdomain"} or hostname.endswith(".localhost"):
        raise SourceAdapterError("definition sources may not target localhost")
    if resolve:
        try:
            addresses = {item[4][0] for item in socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)}
        except OSError as exc:
            raise SourceAdapterError("definition source DNS resolution failed") from exc
        if not addresses:
            raise SourceAdapterError("definition source did not resolve")
        for value in addresses:
            address = ipaddress.ip_address(value.split("%", 1)[0])
            if not address.is_global or address.is_loopback or address.is_private or address.is_link_local:
                raise SourceAdapterError("definition sources may not target local or non-global addresses")
    return hostname, port


class _BoundedRedirectHandler(HTTPRedirectHandler):
    def __init__(self, maximum_redirects: int) -> None:
        super().__init__()
        self.maximum_redirects = max(0, min(int(maximum_redirects), 10))
        self.redirects = 0

    def redirect_request(self, request, fp, code, message, headers, new_url):
        self.redirects += 1
        if self.redirects > self.maximum_redirects:
            raise SourceAdapterError("definition source exceeded the redirect limit")
        _validate_remote_url(new_url, resolve=True)
        return super().redirect_request(request, fp, code, message, headers, new_url)


def bounded_https_fetch(
    url: str,
    maximum_bytes: int,
    request_headers: dict[str, str] | None = None,
    *,
    timeout_seconds: int = 30,
    maximum_redirects: int = 5,
) -> tuple[bytes, str, dict[str, str]]:
    _validate_remote_url(url, resolve=True)
    headers = {
        "User-Agent": "MSAA-DefinitionEngine/1.0",
        "Accept": "application/json,text/csv,text/plain,application/octet-stream,application/zip",
    }
    allowed_headers = {
        "if-none-match": "If-None-Match",
        "if-modified-since": "If-Modified-Since",
        "authorization": "Authorization",
        "auth-key": "Auth-Key",
        "x-api-key": "X-API-Key",
    }
    for key, value in (request_headers or {}).items():
        normalized_key = str(key).lower()
        value = str(value)
        if normalized_key in allowed_headers and len(value) <= 4096 and "\r" not in value and "\n" not in value:
            headers[allowed_headers[normalized_key]] = value
    request = Request(url, headers=headers)
    client = build_opener(_BoundedRedirectHandler(maximum_redirects), HTTPSHandler(context=_verified_tls_context()))
    try:
        response = client.open(request, timeout=max(1, min(int(timeout_seconds), 120)))
    except HTTPError as exc:
        if exc.code == 304:
            return b"", "application/octet-stream", {"http_status": "304", "not_modified": "true"}
        raise SourceAdapterError(f"definition source returned HTTP {exc.code}") from exc
    except (URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", None)
        if isinstance(reason, ssl.SSLCertVerificationError) or isinstance(exc, ssl.SSLCertVerificationError):
            raise SourceAdapterError(
                "definition source TLS certificate verification failed; install the definitions dependencies or repair the Python CA bundle"
            ) from exc
        raise SourceAdapterError(f"definition source request failed: {type(exc).__name__}") from exc
    with response:
        final_url = str(response.geturl())
        _validate_remote_url(final_url, resolve=True)
        length_text = response.headers.get("Content-Length", "0") or "0"
        try:
            length = int(length_text)
        except ValueError as exc:
            raise SourceAdapterError("definition source returned an invalid content length") from exc
        if length < 0 or length > maximum_bytes:
            raise SourceAdapterError("source response exceeds configured size limit")
        payload = response.read(maximum_bytes + 1)
        if len(payload) > maximum_bytes:
            raise SourceAdapterError("source response exceeds configured size limit")
        content_type = response.headers.get_content_type()
        metadata = {
            key.lower(): value
            for key, value in response.headers.items()
            if key.lower() in {"etag", "last-modified"}
        }
        metadata.update({"http_status": str(getattr(response, "status", 200)), "final_url": redact_source_url(final_url)})
        return payload, content_type, metadata


def bounded_https_post_form(
    url: str,
    maximum_bytes: int,
    form: dict[str, str],
    request_headers: dict[str, str] | None = None,
    *,
    timeout_seconds: int = 30,
    maximum_redirects: int = 5,
) -> tuple[bytes, str, dict[str, str]]:
    """Perform a bounded TLS-verified form POST without exposing credentials."""
    _validate_remote_url(url, resolve=True)
    headers = {
        "User-Agent": "MSAA-DefinitionEngine/1.0",
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    for key, value in (request_headers or {}).items():
        normalized = str(key).lower()
        if normalized not in {"auth-key", "authorization", "x-api-key"}:
            continue
        value = str(value)
        if len(value) <= 4096 and "\r" not in value and "\n" not in value:
            headers[{"auth-key": "Auth-Key", "authorization": "Authorization", "x-api-key": "X-API-Key"}[normalized]] = value
    body = urlencode({str(key): str(value) for key, value in form.items()}).encode("ascii")
    request = Request(url, data=body, headers=headers, method="POST")
    client = build_opener(_BoundedRedirectHandler(maximum_redirects), HTTPSHandler(context=_verified_tls_context()))
    try:
        response = client.open(request, timeout=max(1, min(int(timeout_seconds), 120)))
    except HTTPError as exc:
        raise SourceAdapterError(f"definition source returned HTTP {exc.code}") from exc
    except (URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", None)
        if isinstance(reason, ssl.SSLCertVerificationError) or isinstance(exc, ssl.SSLCertVerificationError):
            raise SourceAdapterError(
                "definition source TLS certificate verification failed; install the definitions dependencies or repair the Python CA bundle"
            ) from exc
        raise SourceAdapterError(f"definition source request failed: {type(exc).__name__}") from exc
    with response:
        final_url = str(response.geturl())
        _validate_remote_url(final_url, resolve=True)
        try:
            length = int(response.headers.get("Content-Length", "0") or "0")
        except ValueError as exc:
            raise SourceAdapterError("definition source returned an invalid content length") from exc
        if length < 0 or length > maximum_bytes:
            raise SourceAdapterError("source response exceeds configured size limit")
        payload = response.read(maximum_bytes + 1)
        if len(payload) > maximum_bytes:
            raise SourceAdapterError("source response exceeds configured size limit")
        metadata = {
            key.lower(): value for key, value in response.headers.items()
            if key.lower() in {"etag", "last-modified"}
        }
        metadata.update({"http_status": str(getattr(response, "status", 200)), "final_url": redact_source_url(final_url)})
        return payload, response.headers.get_content_type(), metadata


def _time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        raw = str(value).strip().replace(" UTC", "+00:00").replace("Z", "+00:00")
        parsed = datetime.fromisoformat(raw)
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def _indicator_type(value: str) -> DefinitionType | None:
    normalized = value.lower().replace("-", "_")
    mapping = {
        "domain": DefinitionType.DOMAIN, "hostname": DefinitionType.HOSTNAME,
        "ip:port": DefinitionType.IPV4, "ip_port": DefinitionType.IPV4,
        "ipv4": DefinitionType.IPV4, "ipv6": DefinitionType.IPV6,
        "url": DefinitionType.URL, "sha256_hash": DefinitionType.SHA256,
        "sha256": DefinitionType.SHA256, "sha1": DefinitionType.SHA1,
        "md5": DefinitionType.MD5,
    }
    return mapping.get(normalized)


class BaseSourceAdapter(ABC):
    def __init__(self, policy: SourcePolicy, *, url: str, fetcher: Fetcher = bounded_https_fetch, maximum_bytes: int = 32 * 1024 * 1024) -> None:
        self._policy = policy
        self.url = url
        self.fetcher = fetcher
        self.maximum_bytes = maximum_bytes
        self._conditional_headers: dict[str, str] = {}

    @property
    def source_id(self) -> str:
        return self._policy.source_id

    @property
    def policy(self) -> SourcePolicy:
        return self._policy

    def check_for_updates(self) -> UpdateMetadata:
        return UpdateMetadata(self.source_id, self.policy.enabled, message="Remote metadata is evaluated during the bounded update request.")

    def setup_requirement(self) -> dict[str, str] | None:
        return None

    def download(self) -> RawDefinitionPackage:
        if not self.policy.enabled:
            raise SourceAdapterError(f"source {self.source_id} is disabled pending policy/licensing approval")
        _validate_remote_url(self.url, resolve=False)
        try:
            payload, content_type, metadata = self.fetcher(self.url, self.maximum_bytes, dict(self._conditional_headers))
        except TypeError:
            # Existing injected/test fetchers use the original two-argument contract.
            payload, content_type, metadata = self.fetcher(self.url, self.maximum_bytes)
        return RawDefinitionPackage(
            source_id=self.source_id, payload=payload, content_type=content_type,
            source_reference=redact_source_url(self.url), metadata=metadata,
        )

    def set_conditional_headers(self, *, etag: str | None = None, last_modified: str | None = None) -> None:
        self._conditional_headers = {}
        if etag:
            self._conditional_headers["If-None-Match"] = str(etag)[:1024]
        if last_modified:
            self._conditional_headers["If-Modified-Since"] = str(last_modified)[:1024]

    def _definition(
        self, definition_type: DefinitionType, value: str, *, reference: str | None = None,
        family: str | None = None, confidence: float = 0.7, tags: tuple[str, ...] = (),
        first_seen: datetime | None = None, last_seen: datetime | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ThreatDefinition:
        canonical = normalize_value(definition_type, value)
        confidence = max(0.0, min(float(confidence), 1.0))
        provenance = DefinitionProvenance(
            self.source_id, reference, utc_now(), value, self.policy.source_confidence,
            self.policy.trust_class, self.policy.dependency_group or self.source_id,
        )
        return ThreatDefinition(
            definition_id(definition_type, canonical), definition_type, canonical,
            confidence=confidence, severity=Severity.HIGH, malware_family=family,
            first_seen=first_seen, last_seen=last_seen, tags=tuple(sorted(set(tags))),
            action=self.policy.default_action, provenance=(provenance,), metadata=metadata or {},
        )

    @abstractmethod
    def parse(self, package: RawDefinitionPackage) -> list[ThreatDefinition]:
        raise NotImplementedError


class YaraForgeAdapter(BaseSourceAdapter):
    """Consumes a selected YARA Forge rules package; package selection is explicit."""

    PACKAGES: ClassVar[set[str]] = {"core", "extended", "full"}

    def __init__(self, package: str = "core", *, url: str, enabled: bool = False, fetcher: Fetcher = bounded_https_fetch) -> None:
        if package not in self.PACKAGES:
            raise ValueError("YARA Forge package must be core, extended, or full")
        self.package = package
        policy = SourcePolicy(
            "yara_forge", "YARA Forge", TrustClass.COMMUNITY, 0.75, enabled,
            trust_level=DefinitionTrustLevel.TRUST_3_ESTABLISHED_COMMUNITY,
            dependency_group="yara_forge", license_name="provider-specific/review-required",
            terms_reference="https://github.com/YARAHQ/yara-forge", commercial_use_status="PER_RULE_LICENSE_REVIEW_REQUIRED",
            expected_minimum_count=1, maximum_reduction_fraction=0.5, maximum_growth_factor=4.0,
            minimum_interval_seconds=21_600, update_interval_seconds=21_600,
            default_action=DefinitionAction.ALERT,
        )
        super().__init__(policy, url=url, fetcher=fetcher, maximum_bytes=64 * 1024 * 1024)

    def parse(self, package: RawDefinitionPackage) -> list[ThreatDefinition]:
        payload = package.payload
        if payload.startswith(b"PK\x03\x04"):
            try:
                with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                    infos = archive.infolist()
                    if len(infos) > 10_000 or sum(max(0, item.file_size) for item in infos) > 128 * 1024 * 1024:
                        raise SourceAdapterError("YARA Forge archive exceeds file-count or expanded-size limits")
                    if any(stat.S_ISLNK(item.external_attr >> 16) for item in infos):
                        raise SourceAdapterError("YARA Forge archive contains a symbolic link")
                    if any(item.file_size > max(1024 * 1024, item.compress_size * 200) for item in infos if not item.is_dir()):
                        raise SourceAdapterError("YARA Forge archive has an unsafe decompression ratio")
                    candidates = [item for item in infos if not item.is_dir() and item.filename.endswith(f"yara-rules-{self.package}.yar")]
                    if len(candidates) != 1 or candidates[0].file_size > 64 * 1024 * 1024:
                        raise SourceAdapterError("YARA Forge archive has no unique bounded selected package")
                    if candidates[0].filename.startswith(("/", "\\")) or "\\" in candidates[0].filename or ".." in candidates[0].filename.split("/"):
                        raise SourceAdapterError("YARA Forge archive contains an unsafe selected path")
                    payload = archive.read(candidates[0], pwd=None)
            except (zipfile.BadZipFile, RuntimeError) as exc:
                raise SourceAdapterError("YARA Forge archive is invalid") from exc
        try:
            rules = payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SourceAdapterError("YARA package is not UTF-8") from exc
        if not rules.strip():
            return []
        return [self._definition(DefinitionType.YARA_RULE, rules, reference=package.source_reference, tags=("yara", self.package, "classification:unreviewed"), metadata={"package": self.package})]


class CISAKEVAdapter(BaseSourceAdapter):
    """Consumes CISA's public Known Exploited Vulnerabilities catalog."""

    DEFAULT_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    _CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

    def __init__(self, *, url: str = DEFAULT_URL, enabled: bool = True, fetcher: Fetcher = bounded_https_fetch) -> None:
        super().__init__(SourcePolicy(
            "cisa_kev", "CISA Known Exploited Vulnerabilities", TrustClass.AUTHORITATIVE, 0.98, enabled,
            trust_level=DefinitionTrustLevel.TRUST_4_VENDOR_VERIFIED,
            dependency_group="cisa_kev", license_name="official U.S. government public catalog",
            terms_reference="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            redistribution_allowed=None, commercial_use_status="PUBLIC_SOURCE_NO_ACCEPTANCE_REQUIRED",
            attribution_required="CISA Known Exploited Vulnerabilities Catalog",
            expected_minimum_count=100, maximum_reduction_fraction=0.5, maximum_growth_factor=4.0,
            default_action=DefinitionAction.CORRELATE,
        ), url=url, fetcher=fetcher)

    def parse(self, package: RawDefinitionPackage) -> list[ThreatDefinition]:
        try:
            document = json.loads(package.payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SourceAdapterError("CISA KEV response is not valid JSON") from exc
        rows = document.get("vulnerabilities") if isinstance(document, dict) else None
        if not isinstance(rows, list):
            raise SourceAdapterError("CISA KEV vulnerabilities must be a list")
        output: list[ThreatDefinition] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            cve = str(row.get("cveID") or "").strip().upper()
            if not self._CVE_PATTERN.fullmatch(cve):
                continue
            ransomware_use = str(row.get("knownRansomwareCampaignUse") or "").strip()
            tags = ["cisa-kev", "known-exploited"]
            if ransomware_use.lower() in {"yes", "known"}:
                tags.append("known-ransomware-use")
            metadata = {
                key: str(value).strip()
                for key, value in {
                    "vendor_project": row.get("vendorProject"),
                    "product": row.get("product"),
                    "vulnerability_name": row.get("vulnerabilityName"),
                    "required_action": row.get("requiredAction"),
                    "due_date": row.get("dueDate"),
                    "known_ransomware_campaign_use": ransomware_use,
                }.items()
                if value not in (None, "")
            }
            output.append(self._definition(
                DefinitionType.IOC, cve,
                reference=f"{package.source_reference or self.url}#{cve}",
                confidence=0.98, tags=tuple(tags), first_seen=_time(row.get("dateAdded")),
                metadata=metadata,
            ))
        return output


def _abuse_ch_key() -> str:
    try:
        return load_abuse_ch_auth_key()
    except CredentialValidationError as exc:
        raise SourceAdapterError(f"{ABUSE_CH_AUTH_ENV} has an invalid format") from exc


def _abuse_ch_setup_requirement(url: str, *, key_in_url: bool = True) -> dict[str, str] | None:
    if key_in_url and "AUTH-KEY-REQUIRED" not in url:
        return None
    if _abuse_ch_key():
        return None
    return {
        "status": "SETUP_REQUIRED_FREE",
        "reason": "A free abuse.ch Community API Auth-Key is required. Save it in MSAA Malware Definitions or provide a temporary environment key.",
        "setup_url": ABUSE_CH_FREE_KEY_URL,
        "terms": "Community access is free under provider fair-use terms; commercial/for-profit use requires provider terms review.",
    }


def _download_abuse_ch_export(adapter: BaseSourceAdapter, configured_url: str) -> RawDefinitionPackage:
    if not adapter.policy.enabled:
        raise SourceAdapterError(f"source {adapter.source_id} is disabled pending policy/licensing approval")
    url = configured_url
    if "AUTH-KEY-REQUIRED" in url:
        key = _abuse_ch_key()
        if not key:
            raise SourceAdapterError(f"free abuse.ch Auth-Key required; configure {ABUSE_CH_AUTH_ENV}")
        url = url.replace("AUTH-KEY-REQUIRED", key)
    _validate_remote_url(url, resolve=False)
    try:
        payload, content_type, metadata = adapter.fetcher(url, adapter.maximum_bytes, dict(adapter._conditional_headers))
    except TypeError:
        payload, content_type, metadata = adapter.fetcher(url, adapter.maximum_bytes)
    return RawDefinitionPackage(
        source_id=adapter.source_id, payload=payload, content_type=content_type,
        source_reference=redact_source_url(url), metadata=metadata,
    )


class ThreatFoxAdapter(BaseSourceAdapter):
    def __init__(self, *, url: str, enabled: bool = False, fetcher: Fetcher = bounded_https_fetch) -> None:
        super().__init__(SourcePolicy(
            "threatfox", "abuse.ch ThreatFox", TrustClass.TRUSTED, 0.85, enabled,
            trust_level=DefinitionTrustLevel.TRUST_3_ESTABLISHED_COMMUNITY,
            dependency_group="abuse_ch", license_name="provider-specific/review-required",
            terms_reference="https://threatfox.abuse.ch/api/", commercial_use_status="FREE_COMMUNITY_FAIR_USE_COMMERCIAL_REVIEW_REQUIRED",
            expected_minimum_count=10, default_action=DefinitionAction.CORRELATE,
            minimum_interval_seconds=21_600, update_interval_seconds=21_600,
        ), url=url, fetcher=fetcher)

    def setup_requirement(self) -> dict[str, str] | None:
        return _abuse_ch_setup_requirement(self.url)

    def download(self) -> RawDefinitionPackage:
        return _download_abuse_ch_export(self, self.url)

    def parse(self, package: RawDefinitionPackage) -> list[ThreatDefinition]:
        try:
            document = json.loads(package.payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SourceAdapterError("ThreatFox response is not valid JSON") from exc
        if isinstance(document, dict) and isinstance(document.get("data"), list):
            rows = document["data"]
        elif isinstance(document, dict) and all(isinstance(value, dict) for value in document.values()):
            rows = list(document.values())
        else:
            rows = document
        if not isinstance(rows, list):
            raise SourceAdapterError("ThreatFox data must be a list")
        output: list[ThreatDefinition] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            dtype = _indicator_type(str(row.get("ioc_type", "")))
            value = str(row.get("ioc", ""))
            if dtype is None:
                continue
            if str(row.get("ioc_type", "")).lower() in {"ip:port", "ip_port"}:
                value = value.rsplit(":", 1)[0]
            try:
                output.append(self._definition(
                    dtype, value, reference=str(row.get("id") or package.source_reference or ""),
                    family=str(row.get("malware_printable") or row.get("malware") or "") or None,
                    confidence=float(row.get("confidence_level", 70)) / 100.0,
                    tags=tuple(str(item) for item in row.get("tags", []) if item),
                    first_seen=_time(row.get("first_seen")), last_seen=_time(row.get("last_seen")),
                ))
            except (NormalizationError, TypeError, ValueError):
                continue
        return output


class URLhausAdapter(BaseSourceAdapter):
    def __init__(self, *, url: str, enabled: bool = False, fetcher: Fetcher = bounded_https_fetch) -> None:
        super().__init__(SourcePolicy(
            "urlhaus", "abuse.ch URLhaus", TrustClass.TRUSTED, 0.85, enabled,
            trust_level=DefinitionTrustLevel.TRUST_3_ESTABLISHED_COMMUNITY,
            dependency_group="abuse_ch", license_name="provider-specific/review-required",
            terms_reference="https://urlhaus.abuse.ch/api/", commercial_use_status="FREE_COMMUNITY_FAIR_USE_COMMERCIAL_REVIEW_REQUIRED",
            expected_minimum_count=10, default_action=DefinitionAction.CORRELATE,
            minimum_interval_seconds=21_600, update_interval_seconds=21_600,
        ), url=url, fetcher=fetcher)

    def setup_requirement(self) -> dict[str, str] | None:
        return _abuse_ch_setup_requirement(self.url)

    def download(self) -> RawDefinitionPackage:
        return _download_abuse_ch_export(self, self.url)

    def parse(self, package: RawDefinitionPackage) -> list[ThreatDefinition]:
        try:
            text = package.payload.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise SourceAdapterError("URLhaus response is not UTF-8") from exc
        rows: list[dict[str, Any]]
        if text.lstrip().startswith(("{", "[")):
            document = json.loads(text)
            data = document.get("urls", document.get("data", [])) if isinstance(document, dict) else document
            rows = data if isinstance(data, list) else []
        else:
            lines = text.splitlines()
            header = next((line.lstrip("# ") for line in reversed(lines) if line.startswith("#") and "url" in line.lower() and "," in line), "")
            data_lines = [line for line in lines if line and not line.startswith("#")]
            if header:
                content = "\n".join((header, *data_lines))
            else:
                content = "\n".join(data_lines)
            rows = list(csv.DictReader(io.StringIO(content)))
        output: list[ThreatDefinition] = []
        for row in rows:
            value = str(row.get("url") or row.get("URL") or "")
            if not value:
                continue
            try:
                output.append(self._definition(
                    DefinitionType.URL, value, reference=str(row.get("id") or row.get("url_id") or package.source_reference or ""),
                    family=str(row.get("threat") or row.get("signature") or "") or None,
                    tags=tuple(filter(None, (str(row.get("tags") or "").split(",")))),
                    first_seen=_time(row.get("dateadded") or row.get("date_added")),
                ))
            except NormalizationError:
                continue
        return output


class MalwareBazaarAdapter(BaseSourceAdapter):
    """Consumes metadata only. Malware binaries are deliberately out of scope."""

    def __init__(
        self, *, url: str, enabled: bool = False, fetcher: Fetcher = bounded_https_fetch,
        post_fetcher: Callable[..., tuple[bytes, str, dict[str, str]]] = bounded_https_post_form,
    ) -> None:
        super().__init__(SourcePolicy(
            "malwarebazaar", "abuse.ch MalwareBazaar", TrustClass.TRUSTED, 0.9, enabled,
            trust_level=DefinitionTrustLevel.TRUST_3_ESTABLISHED_COMMUNITY,
            dependency_group="abuse_ch", license_name="provider-specific/review-required",
            terms_reference="https://bazaar.abuse.ch/api/", commercial_use_status="FREE_COMMUNITY_FAIR_USE_COMMERCIAL_REVIEW_REQUIRED",
            expected_minimum_count=10, default_action=DefinitionAction.ALERT,
            minimum_interval_seconds=21_600, update_interval_seconds=21_600,
        ), url=url, fetcher=fetcher)
        self.post_fetcher = post_fetcher

    def setup_requirement(self) -> dict[str, str] | None:
        return _abuse_ch_setup_requirement(self.url, key_in_url=False)

    def download(self) -> RawDefinitionPackage:
        if not self.policy.enabled:
            raise SourceAdapterError(f"source {self.source_id} is disabled pending policy/licensing approval")
        key = _abuse_ch_key()
        if not key:
            raise SourceAdapterError(f"free abuse.ch Auth-Key required; configure {ABUSE_CH_AUTH_ENV}")
        _validate_remote_url(self.url, resolve=False)
        try:
            payload, content_type, metadata = self.post_fetcher(
                self.url, self.maximum_bytes, {"query": "get_recent", "selector": "100"}, {"Auth-Key": key},
            )
        except TypeError:
            payload, content_type, metadata = self.post_fetcher(
                self.url, self.maximum_bytes, {"query": "get_recent", "selector": "100"},
            )
        return RawDefinitionPackage(
            source_id=self.source_id, payload=payload, content_type=content_type,
            source_reference=redact_source_url(self.url), metadata=metadata,
        )

    def parse(self, package: RawDefinitionPackage) -> list[ThreatDefinition]:
        try:
            document = json.loads(package.payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SourceAdapterError("MalwareBazaar response is not valid JSON") from exc
        rows = document.get("data", []) if isinstance(document, dict) else []
        output: list[ThreatDefinition] = []
        for row in rows if isinstance(rows, list) else []:
            if not isinstance(row, dict):
                continue
            family = str(row.get("signature") or "") or None
            tags = tuple(str(item) for item in row.get("tags", []) if item)
            linked_hashes = {
                key.removesuffix("_hash"): str(row[key])
                for key in ("sha256_hash", "sha1_hash", "md5_hash")
                if row.get(key)
            }
            for field, dtype in (("sha256_hash", DefinitionType.SHA256), ("sha1_hash", DefinitionType.SHA1), ("md5_hash", DefinitionType.MD5)):
                if not row.get(field):
                    continue
                try:
                    output.append(self._definition(
                        dtype, str(row[field]), reference=str(row.get("sha256_hash") or package.source_reference or ""),
                        family=family, confidence=0.9, tags=tags,
                        first_seen=_time(row.get("first_seen")), last_seen=_time(row.get("last_seen")),
                        metadata={
                            "metadata_only": True, "classification": "malware_indicator",
                            "malware_name": family, **linked_hashes,
                        },
                    ))
                except NormalizationError:
                    continue
        return output


class LocalDefinitionAdapter(BaseSourceAdapter):
    """Adapter for organization-owned JSON definitions supplied by an administrator."""

    def __init__(self, *, url: str = "https://localhost.invalid/not-used", enabled: bool = True, fetcher: Fetcher = bounded_https_fetch) -> None:
        super().__init__(SourcePolicy(
            "local_admin", "Local Administrator", TrustClass.LOCAL_ADMIN, 0.95, enabled,
            trust_level=DefinitionTrustLevel.TRUST_4_VENDOR_VERIFIED,
            dependency_group="local_admin", license_name="organization-owned", redistribution_allowed=False,
            commercial_use_status="LOCAL_POLICY", default_action=DefinitionAction.CORRELATE,
        ), url=url, fetcher=fetcher)

    def parse(self, package: RawDefinitionPackage) -> list[ThreatDefinition]:
        try:
            rows = json.loads(package.payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SourceAdapterError("local definitions must be valid JSON") from exc
        if not isinstance(rows, list):
            raise SourceAdapterError("local definition document must be a list")
        output: list[ThreatDefinition] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            try:
                dtype = DefinitionType(str(row["definition_type"]).upper())
                item = self._definition(dtype, str(row["value"]), reference=str(row.get("reference") or "local"), confidence=float(row.get("confidence", 0.8)), tags=tuple(row.get("tags", ())))
                requested = DefinitionAction(str(row.get("action", self.policy.default_action.value)).upper())
                output.append(ThreatDefinition(**{**item.__dict__, "action": requested}))
            except (KeyError, TypeError, ValueError, NormalizationError):
                continue
        return output


class SignedBundleAdapter(BaseSourceAdapter):
    """Downloads prebuilt MSAA bundles; endpoints verify but never possess release keys."""

    bundle_package = True

    def __init__(self, *, url: str, enabled: bool = False, fetcher: Fetcher = bounded_https_fetch) -> None:
        super().__init__(SourcePolicy(
            "msaa_signed_bundle", "MSAA Signed Definition Release", TrustClass.AUTHORITATIVE, 1.0, enabled,
            trust_level=DefinitionTrustLevel.TRUST_5_MSAA_VERIFIED,
            dependency_group="msaa_release", license_name="bundle-manifest-governed",
            terms_reference="locally-managed update policy", redistribution_allowed=None,
            commercial_use_status="LOCAL_POLICY", expected_minimum_count=1,
            maximum_reduction_fraction=0.95, maximum_growth_factor=100.0,
            minimum_interval_seconds=3_600, update_interval_seconds=3_600,
            default_action=DefinitionAction.CORRELATE,
        ), url=url, fetcher=fetcher, maximum_bytes=512 * 1024 * 1024)

    def download(self) -> RawDefinitionPackage:
        package = super().download()
        return RawDefinitionPackage(
            source_id=package.source_id, payload=package.payload,
            retrieved_at=package.retrieved_at,
            content_type="application/vnd.msaa.definition-bundle+zip",
            source_reference=package.source_reference,
            metadata={**package.metadata, "signed_bundle": True},
        )

    def parse(self, package: RawDefinitionPackage) -> list[ThreatDefinition]:
        raise SourceAdapterError("signed bundles are imported through the bundle verification pipeline, not parsed as raw feed data")


_CONFIG_SOURCE_TYPES = {"yara", "sha256", "sha1", "md5", "mixed_hash", "json_intelligence", "csv_intelligence"}
_SOURCE_ID = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")


def _trust_class(level: DefinitionTrustLevel) -> TrustClass:
    return {
        DefinitionTrustLevel.TRUST_5_MSAA_VERIFIED: TrustClass.AUTHORITATIVE,
        DefinitionTrustLevel.TRUST_4_VENDOR_VERIFIED: TrustClass.TRUSTED,
        DefinitionTrustLevel.TRUST_3_ESTABLISHED_COMMUNITY: TrustClass.COMMUNITY,
        DefinitionTrustLevel.TRUST_2_RESEARCH: TrustClass.EXPERIMENTAL,
        DefinitionTrustLevel.TRUST_1_UNVERIFIED: TrustClass.UNTRUSTED,
    }[level]


class ConfiguredDefinitionSource(BaseSourceAdapter):
    """Strict generic adapter driven by an administrator-reviewed source registry."""

    def __init__(self, document: dict[str, Any], *, fetcher: Fetcher = bounded_https_fetch) -> None:
        source_id = str(document.get("id", "")).strip()
        source_type = str(document.get("type", "")).strip().lower()
        url = str(document.get("url", "")).strip()
        if not _SOURCE_ID.fullmatch(source_id):
            raise SourceAdapterError("configured definition source has an invalid id")
        if source_type not in _CONFIG_SOURCE_TYPES:
            raise SourceAdapterError(f"configured definition source {source_id} has an unsupported type")
        _validate_remote_url(url, resolve=False)
        try:
            trust_level = DefinitionTrustLevel(int(document.get("trust_level", 3)))
        except (TypeError, ValueError) as exc:
            raise SourceAdapterError(f"configured definition source {source_id} has an invalid trust level") from exc
        maximum_bytes = max(1_024, min(int(document.get("max_download_bytes", 100 * 1024 * 1024)), 512 * 1024 * 1024))
        interval = max(300, min(int(document.get("update_interval_seconds", 21_600)), 30 * 24 * 3600))
        timeout = max(1, min(int(document.get("timeout_seconds", 30)), 120))
        enabled = bool(document.get("enabled", False))
        policy = SourcePolicy(
            source_id, str(document.get("name") or source_id), _trust_class(trust_level),
            max(0.0, min(float(document.get("source_confidence", int(trust_level) / 5.0)), 1.0)),
            enabled=enabled, trust_level=trust_level,
            dependency_group=str(document.get("dependency_group") or source_id),
            license_name=str(document.get("license", "review-required")),
            terms_reference=str(document.get("terms_reference", "")),
            commercial_use_status=str(document.get("commercial_use_status", "REVIEW_REQUIRED")),
            minimum_interval_seconds=interval,
            update_interval_seconds=interval,
            timeout_seconds=timeout,
            maximum_download_bytes=maximum_bytes,
            expected_minimum_count=max(1, int(document.get("expected_minimum_count", 1))),
            maximum_reduction_fraction=max(0.0, min(float(document.get("maximum_reduction_fraction", 0.75)), 1.0)),
            maximum_growth_factor=max(1.0, float(document.get("maximum_growth_factor", 20.0))),
            required=bool(document.get("required", False)),
            default_action=DefinitionAction.ALERT if source_type in {"yara", "sha256", "sha1", "md5", "mixed_hash"} else DefinitionAction.CORRELATE,
        )
        super().__init__(policy, url=url, fetcher=fetcher, maximum_bytes=maximum_bytes)
        self.source_type = source_type
        self.timeout_seconds = timeout
        auth_header = str(document.get("auth_header", "")).strip()
        auth_env = str(document.get("auth_env", "")).strip()
        if bool(auth_header) != bool(auth_env):
            raise SourceAdapterError(f"configured definition source {source_id} requires both auth_header and auth_env")
        if auth_header and auth_header.lower() not in {"authorization", "auth-key", "x-api-key"}:
            raise SourceAdapterError(f"configured definition source {source_id} has an unsupported authentication header")
        if auth_env and not re.fullmatch(r"MSAA_[A-Z0-9_]{1,120}", auth_env):
            raise SourceAdapterError(f"configured definition source {source_id} has an unsafe authentication environment name")
        self.auth_header = auth_header
        self.auth_env = auth_env
        expected = str(document.get("expected_sha256", "")).strip().lower()
        if expected and not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise SourceAdapterError(f"configured definition source {source_id} has an invalid expected SHA-256")
        self.expected_sha256 = expected or None

    def download(self) -> RawDefinitionPackage:
        headers = dict(self._conditional_headers)
        if self.auth_env:
            secret = os.environ.get(self.auth_env, "")
            if not secret or len(secret) > 4096 or "\r" in secret or "\n" in secret:
                raise SourceAdapterError(f"source {self.source_id} authentication is unavailable or invalid")
            headers[self.auth_header] = secret
        if self.fetcher is bounded_https_fetch:
            if not self.policy.enabled:
                raise SourceAdapterError(f"source {self.source_id} is disabled pending policy/licensing approval")
            payload, content_type, metadata = bounded_https_fetch(
                self.url, self.maximum_bytes, headers, timeout_seconds=self.timeout_seconds,
            )
            package = RawDefinitionPackage(
                self.source_id, payload, content_type=content_type,
                source_reference=redact_source_url(self.url), metadata=metadata,
            )
        else:
            try:
                payload, content_type, metadata = self.fetcher(self.url, self.maximum_bytes, headers)
            except TypeError:
                payload, content_type, metadata = self.fetcher(self.url, self.maximum_bytes)
            package = RawDefinitionPackage(
                self.source_id, payload, content_type=content_type,
                source_reference=redact_source_url(self.url), metadata=metadata,
            )
        return RawDefinitionPackage(
            package.source_id, package.payload, package.retrieved_at, package.content_type,
            package.source_reference, self.expected_sha256 or package.expected_sha256, package.signature,
            {**package.metadata, "source_type": self.source_type},
        )

    def parse(self, package: RawDefinitionPackage) -> list[ThreatDefinition]:
        if package.metadata.get("not_modified") == "true":
            return []
        if self.source_type == "yara":
            try:
                source = package.payload.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise SourceAdapterError("YARA source is not UTF-8") from exc
            if not source.strip():
                return []
            namespace = re.sub(r"[^A-Za-z0-9_]", "_", self.source_id)
            return [self._definition(
                DefinitionType.YARA_RULE, source, reference=package.source_reference,
                tags=("yara", "configured-source"), metadata={"namespace": namespace},
            )]
        if self.source_type in {"sha256", "sha1", "md5", "mixed_hash"}:
            return self._parse_hash_lines(package)
        if self.source_type == "json_intelligence":
            try:
                document = json.loads(package.payload)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise SourceAdapterError("JSON intelligence feed is invalid") from exc
            rows = document.get("data", document.get("indicators", [])) if isinstance(document, dict) else document
            if not isinstance(rows, list):
                raise SourceAdapterError("JSON intelligence feed must contain an array")
            output, received, rejected = self._parse_records(item for item in rows if isinstance(item, dict))
            package.metadata.update({"records_received": received, "records_rejected": rejected})
            return output
        try:
            text = package.payload.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise SourceAdapterError("CSV intelligence feed is not UTF-8") from exc
        output, received, rejected = self._parse_records(csv.DictReader(io.StringIO(text)))
        package.metadata.update({"records_received": received, "records_rejected": rejected})
        return output

    def _parse_hash_lines(self, package: RawDefinitionPackage) -> list[ThreatDefinition]:
        try:
            text = package.payload.decode("ascii")
        except UnicodeDecodeError as exc:
            raise SourceAdapterError("hash feed must be ASCII") from exc
        fixed = {
            "sha256": DefinitionType.SHA256,
            "sha1": DefinitionType.SHA1,
            "md5": DefinitionType.MD5,
        }.get(self.source_type)
        output: list[ThreatDefinition] = []
        rejected = 0
        for raw_line in text.splitlines():
            if not raw_line or raw_line.startswith("#"):
                continue
            token = raw_line.split(",", 1)[0]
            if token != token.strip() or any(character.isspace() for character in token):
                rejected += 1
                continue
            kind = fixed or {32: DefinitionType.MD5, 40: DefinitionType.SHA1, 64: DefinitionType.SHA256}.get(len(token))
            if kind is None:
                rejected += 1
                continue
            try:
                output.append(self._definition(kind, token, reference=package.source_reference, metadata={"classification": "malware_indicator"}))
            except NormalizationError:
                rejected += 1
        package.metadata["records_rejected"] = rejected
        package.metadata["records_received"] = len(output) + rejected
        return output

    def _parse_records(self, rows) -> tuple[list[ThreatDefinition], int, int]:
        output: list[ThreatDefinition] = []
        received = 0
        rejected = 0
        for row in rows:
            lowered = {str(key).lower(): value for key, value in row.items()}
            metadata = {
                key: lowered.get(key)
                for key in ("sha256", "sha1", "md5", "malware_name", "platform", "architecture", "classification")
                if lowered.get(key)
            }
            family = str(lowered.get("family") or lowered.get("malware_family") or "") or None
            row_hashes = 0
            for field, kind in (("sha256", DefinitionType.SHA256), ("sha1", DefinitionType.SHA1), ("md5", DefinitionType.MD5)):
                if not lowered.get(field):
                    continue
                received += 1
                row_hashes += 1
                try:
                    output.append(self._definition(kind, str(lowered[field]), family=family, metadata=metadata))
                except NormalizationError:
                    rejected += 1
            if not row_hashes:
                received += 1
                rejected += 1
        return output, received, rejected


def load_source_registry(path: Path, *, fetcher: Fetcher = bounded_https_fetch) -> SourceRegistry:
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
        raise SourceAdapterError("definition source registry is missing or unsafe")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceAdapterError("definition source registry is invalid JSON") from exc
    rows = document.get("sources") if isinstance(document, dict) else None
    if not isinstance(rows, list) or len(rows) > 100:
        raise SourceAdapterError("definition source registry must contain at most 100 sources")
    registry = SourceRegistry()
    for row in rows:
        if not isinstance(row, dict):
            raise SourceAdapterError("definition source registry contains a non-object entry")
        registry.register(ConfiguredDefinitionSource(row, fetcher=fetcher))
    return registry


class SourceRegistry:
    def __init__(self) -> None:
        self._adapters: dict[str, ThreatSourceAdapter] = {}

    def register(self, adapter: ThreatSourceAdapter) -> None:
        if not adapter.source_id or adapter.source_id in self._adapters:
            raise ValueError(f"invalid or duplicate source id: {adapter.source_id!r}")
        self._adapters[adapter.source_id] = adapter

    def get(self, source_id: str) -> ThreatSourceAdapter:
        try:
            return self._adapters[source_id]
        except KeyError as exc:
            raise KeyError(f"unknown threat source: {source_id}") from exc

    def all(self) -> tuple[ThreatSourceAdapter, ...]:
        return tuple(self._adapters[key] for key in sorted(self._adapters))


__all__ = [
    "BaseSourceAdapter",
    "CISAKEVAdapter",
    "ConfiguredDefinitionSource",
    "LocalDefinitionAdapter",
    "MalwareBazaarAdapter",
    "SignedBundleAdapter",
    "SourceAdapterError",
    "SourceRegistry",
    "ThreatFoxAdapter",
    "ThreatSourceAdapter",
    "URLhausAdapter",
    "YaraForgeAdapter",
    "bounded_https_fetch",
    "load_source_registry",
    "redact_source_url",
]
