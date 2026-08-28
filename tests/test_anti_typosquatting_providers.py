from __future__ import annotations

import io
import urllib.error

from mac_audit_agent.anti_typosquatting.models import LookupStatus
from mac_audit_agent.anti_typosquatting.providers import CratesIoProvider, GoModuleProvider, MavenCentralProvider, NpmProvider, NuGetProvider, PackagistProvider, PyPIProvider, RDAPProvider, RubyGemsProvider


class Response:
    def __init__(self, url, data=b'{"name":"acme-widget","version":"1.0.0","private":"discard"}'):
        self.url, self.data, self.headers = url, data, {"Content-Length": str(len(data))}
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def geturl(self): return self.url
    def read(self, amount): return self.data[:amount]


def test_npm_metadata_only_and_no_download(monkeypatch):
    monkeypatch.setattr("urllib.request.urlopen", lambda request, timeout: Response(request.full_url))
    result = NpmProvider().lookup("acme-widget")
    assert result.status == LookupStatus.PUBLISHED
    assert result.evidence == {"name": "acme-widget", "version": "1.0.0"}


def test_package_not_found_is_not_availability_claim(monkeypatch):
    def missing(request, timeout):
        raise urllib.error.HTTPError(request.full_url, 404, "missing", {}, None)
    monkeypatch.setattr("urllib.request.urlopen", missing)
    result = PyPIProvider().lookup("acme-security-client")
    assert result.status == LookupStatus.NOT_PUBLISHED
    assert "policy" in result.message.lower()


def test_rdap_not_found_uses_qualified_language(monkeypatch):
    def missing(request, timeout):
        raise urllib.error.HTTPError(request.full_url, 404, "missing", {}, None)
    monkeypatch.setattr("urllib.request.urlopen", missing)
    result = RDAPProvider().lookup("examplebrand.com")
    assert result.status == LookupStatus.NO_REGISTRATION_DATA
    assert "does not guarantee" in result.message


def test_unexpected_redirect_is_rejected(monkeypatch):
    monkeypatch.setattr("urllib.request.urlopen", lambda request, timeout: Response("https://untrusted.invalid/value"))
    assert NpmProvider().lookup("acme-widget").status == LookupStatus.ERROR


def test_oversized_and_malformed_responses_are_structured(monkeypatch):
    monkeypatch.setattr("urllib.request.urlopen", lambda request, timeout: Response(request.full_url, b"x" * 1_000_001))
    assert NpmProvider().lookup("acme-widget").status == LookupStatus.ERROR
    monkeypatch.setattr("urllib.request.urlopen", lambda request, timeout: Response(request.full_url, b"not-json"))
    assert NpmProvider().lookup("acme-widget").status == LookupStatus.PROVIDER_UNAVAILABLE


def test_unsupported_rdap_namespace_is_explicit():
    result = RDAPProvider().lookup("examplebrand.test")
    assert result.status == LookupStatus.POLICY_UNKNOWN


def test_every_registry_has_dedicated_allowlisted_provider(monkeypatch):
    seen=[]
    def response(request, timeout):
        seen.append(request.full_url); return Response(request.full_url)
    monkeypatch.setattr("urllib.request.urlopen",response)
    matrix=[(CratesIoProvider(),"acme-widget","crates.io"),(RubyGemsProvider(),"acme-widget","rubygems.org"),(NuGetProvider(),"Acme.Widget","api.nuget.org"),(MavenCentralProvider(),"com.example:acme-widget","search.maven.org"),(GoModuleProvider(),"example.com/acme/widget","proxy.golang.org"),(PackagistProvider(),"example/acme-widget","repo.packagist.org")]
    for provider,name,host in matrix:
        result=provider.lookup(name)
        assert result.status==LookupStatus.PUBLISHED and host in seen[-1]
        assert provider.capabilities.exact_lookup
