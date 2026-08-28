from __future__ import annotations

import json
import asyncio
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Dict, Optional, Protocol

from .models import LookupStatus, ProviderCapabilities


@dataclass(frozen=True)
class ProviderResult:
    status: LookupStatus
    provider: str
    evidence: Dict[str, object]
    message: str


@dataclass(frozen=True)
class LookupContext:
    online_consent: bool = False
    private: bool = False
    private_patterns: str = ""


class RegistryProviderProtocol(Protocol):
    capabilities: ProviderCapabilities
    def lookup(self, name: str) -> ProviderResult: ...
    async def lookup_exact(self, name: str, context: LookupContext) -> ProviderResult: ...


class RegistryProvider:
    allowed_hosts: frozenset = frozenset()
    timeout: float = 8.0
    max_response_bytes: int = 1_000_000
    capabilities = ProviderCapabilities()

    async def lookup_exact(self, name: str, context: LookupContext) -> ProviderResult:
        if not context.online_consent:
            return ProviderResult(LookupStatus.NOT_REQUESTED, self.__class__.__name__, {}, "Online registry lookup requires explicit consent.")
        return await asyncio.to_thread(self.lookup, name)

    def _json(self, url: str) -> ProviderResult:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https" or parsed.hostname not in self.allowed_hosts:
            return ProviderResult(LookupStatus.ERROR, self.__class__.__name__, {}, "Provider destination was not allowlisted.")
        request = urllib.request.Request(url, headers={"User-Agent": "MSAA-Anti-Typosquatting/1.0", "Accept": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                final = urllib.parse.urlsplit(response.geturl())
                if final.scheme != "https" or final.hostname not in self.allowed_hosts:
                    return ProviderResult(LookupStatus.ERROR, self.__class__.__name__, {}, "Provider redirected outside the allowlist.")
                length = int(response.headers.get("Content-Length", "0") or 0)
                if length > self.max_response_bytes:
                    return ProviderResult(LookupStatus.ERROR, self.__class__.__name__, {}, "Provider response exceeded the safe size limit.")
                raw = response.read(self.max_response_bytes + 1)
                if len(raw) > self.max_response_bytes:
                    return ProviderResult(LookupStatus.ERROR, self.__class__.__name__, {}, "Provider response exceeded the safe size limit.")
                payload = json.loads(raw.decode("utf-8"))
                if not isinstance(payload, dict):
                    raise ValueError("expected JSON object")
                return ProviderResult(LookupStatus.PUBLISHED, self.__class__.__name__, _sanitize(payload), "Registry metadata found.")
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return ProviderResult(LookupStatus.NOT_PUBLISHED, self.__class__.__name__, {"http_status": 404}, "No currently published package was found. Registry policy may still apply.")
            if exc.code == 429:
                return ProviderResult(LookupStatus.RATE_LIMITED, self.__class__.__name__, {"http_status": 429}, "Provider rate limit reached.")
            return ProviderResult(LookupStatus.ERROR, self.__class__.__name__, {"http_status": exc.code}, "Provider returned an HTTP error.")
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            return ProviderResult(LookupStatus.PROVIDER_UNAVAILABLE, self.__class__.__name__, {"error_type": type(exc).__name__}, "Provider unavailable or returned malformed data.")


class NpmProvider(RegistryProvider):
    allowed_hosts = frozenset({"registry.npmjs.org"})
    def lookup(self, name: str) -> ProviderResult:
        return self._json("https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@"))


class PyPIProvider(RegistryProvider):
    allowed_hosts = frozenset({"pypi.org"})
    def lookup(self, name: str) -> ProviderResult:
        return self._json("https://pypi.org/pypi/" + urllib.parse.quote(name, safe="") + "/json")


class CratesIoProvider(RegistryProvider):
    allowed_hosts = frozenset({"crates.io"})
    capabilities = ProviderCapabilities(owner_metadata=True, publication_time=True, version_history=True, yank_or_unlist=True, download_count=True)
    def lookup(self, name): return self._json("https://crates.io/api/v1/crates/" + urllib.parse.quote(name, safe=""))


class RubyGemsProvider(RegistryProvider):
    allowed_hosts = frozenset({"rubygems.org"})
    capabilities = ProviderCapabilities(owner_metadata=False, publication_time=True, version_history=True, yank_or_unlist=True, download_count=True)
    def lookup(self, name): return self._json("https://rubygems.org/api/v1/gems/" + urllib.parse.quote(name, safe="") + ".json")


class NuGetProvider(RegistryProvider):
    allowed_hosts = frozenset({"api.nuget.org"})
    capabilities = ProviderCapabilities(similar_search=True, owner_metadata=True, verified_identity=True, version_history=True, yank_or_unlist=True, deprecation=True, abuse_workflow=True)
    service_index = "https://api.nuget.org/v3/index.json"
    def lookup(self, name):
        key = name.casefold()
        # The registration resource is the documented nuget.org service-index
        # resource. A future custom-feed adapter must discover it dynamically.
        return self._json("https://api.nuget.org/v3/registration5-gz-semver2/" + urllib.parse.quote(key, safe="") + "/index.json")


class MavenCentralProvider(RegistryProvider):
    allowed_hosts = frozenset({"search.maven.org"})
    capabilities = ProviderCapabilities(similar_search=True, publication_time=True, version_history=True)
    def lookup(self, name):
        group, artifact = name.split(":", 1)
        query = 'g:"%s" AND a:"%s"' % (group, artifact)
        return self._json("https://search.maven.org/solrsearch/select?" + urllib.parse.urlencode({"q": query, "rows": 5, "wt": "json"}))


class GoModuleProvider(RegistryProvider):
    allowed_hosts = frozenset({"proxy.golang.org"})
    capabilities = ProviderCapabilities(publication_time=True, version_history=True, network_privacy_sensitive=True)
    def lookup(self, name, *, private=False, private_patterns=""):
        from .namespaces import matches_private, proxy_escape
        if private or matches_private(name, private_patterns):
            return ProviderResult(LookupStatus.POLICY_UNKNOWN, self.__class__.__name__, {"redacted_module": "<private-module>"}, "Private Go module path was not sent to a public service.")
        return self._json("https://proxy.golang.org/" + urllib.parse.quote(proxy_escape(name), safe="!/") + "/@latest")

    async def lookup_exact(self, name: str, context: LookupContext) -> ProviderResult:
        if context.private or _go_private(name, context.private_patterns):
            return self.lookup(name, private=True, private_patterns=context.private_patterns)
        return await super().lookup_exact(name, context)


class PackagistProvider(RegistryProvider):
    allowed_hosts = frozenset({"repo.packagist.org"})
    capabilities = ProviderCapabilities(owner_metadata=True, publication_time=True, version_history=True, deprecation=True, download_count=True)
    def lookup(self, name): return self._json("https://repo.packagist.org/p2/" + urllib.parse.quote(name, safe="/") + ".json")


class RDAPProvider(RegistryProvider):
    """Small pinned bootstrap subset; unsupported TLDs remain explicitly unknown."""
    BOOTSTRAP = {
        "com": ("https://rdap.verisign.com/com/v1/domain/", "rdap.verisign.com"),
        "net": ("https://rdap.verisign.com/net/v1/domain/", "rdap.verisign.com"),
        "org": ("https://rdap.publicinterestregistry.org/rdap/domain/", "rdap.publicinterestregistry.org"),
    }
    allowed_hosts = frozenset({item[1] for item in BOOTSTRAP.values()})

    def lookup(self, name: str) -> ProviderResult:
        tld = name.rsplit(".", 1)[-1].lower()
        service = self.BOOTSTRAP.get(tld)
        if not service:
            return ProviderResult(LookupStatus.POLICY_UNKNOWN, self.__class__.__name__, {"tld": tld}, "No configured authoritative RDAP service is available for this namespace.")
        result = self._json(service[0] + urllib.parse.quote(name, safe=""))
        if result.status == LookupStatus.PUBLISHED:
            return ProviderResult(LookupStatus.REGISTERED, result.provider, result.evidence, "RDAP registration data was found; ownership and intent remain unverified.")
        if result.status == LookupStatus.NOT_PUBLISHED:
            return ProviderResult(LookupStatus.NO_REGISTRATION_DATA, result.provider, result.evidence, "No registration data was found. This does not guarantee purchase availability; confirm through an authorized registrar.")
        return result


class DomainNameSystemMetadataProvider(RegistryProvider):
    """Deliberately passive placeholder capability for injected DNS resolvers.

    The default implementation does not resolve names: DNS failure cannot prove
    registration state and UI code must never perform blocking resolver work.
    """
    capabilities = ProviderCapabilities(exact_lookup=True)

    def lookup(self, name: str) -> ProviderResult:
        return ProviderResult(LookupStatus.POLICY_UNKNOWN, self.__class__.__name__, {"name": name}, "DNS metadata lookup requires an approved injected resolver; no availability conclusion was made.")


def _go_private(name: str, patterns: str) -> bool:
    from .namespaces import matches_private
    return matches_private(name, patterns)


def _sanitize(payload: Dict[str, object]) -> Dict[str, object]:
    # Deliberately retain no maintainer email, registration contact, scripts,
    # package content, URLs, or arbitrary nested provider response.
    output = {}
    for key in ("name", "version", "time", "statusCode"):
        value = payload.get(key)
        if isinstance(value, (str, int, float, bool)):
            output[key] = value
    info = payload.get("info")
    if isinstance(info, dict):
        for key in ("name", "version"):
            if isinstance(info.get(key), str):
                output[key] = info[key]
    return output


# Descriptive compatibility names used by the architecture and documentation.
NpmRegistryProvider = NpmProvider
PythonPackageIndexProvider = PyPIProvider
RdapDomainProvider = RDAPProvider
