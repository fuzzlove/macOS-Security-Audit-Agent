from __future__ import annotations

import fnmatch
import re
from typing import Dict, Iterable, Protocol, Tuple

from .models import NamespaceComponent, PackageEcosystem, ParsedIdentifier
from .normalization import normalize_npm, normalize_pypi, parse_npm


class NamespaceAdapter(Protocol):
    ecosystem: PackageEcosystem
    def parse_identifier(self, raw: str, private: bool = False) -> ParsedIdentifier: ...
    def validate_identifier(self, parsed: ParsedIdentifier) -> bool: ...
    def canonicalize(self, parsed: ParsedIdentifier) -> str: ...
    def normalize_for_lookup(self, parsed: ParsedIdentifier) -> str: ...
    def normalize_for_comparison(self, parsed: ParsedIdentifier) -> str: ...
    def split_components(self, parsed: ParsedIdentifier) -> Tuple[NamespaceComponent, ...]: ...


class _AdapterOperations:
    """Common operations over an already registry-specific parsed identity."""
    def validate_identifier(self, parsed: ParsedIdentifier) -> bool:
        return parsed.ecosystem == self.ecosystem

    def canonicalize(self, parsed: ParsedIdentifier) -> str:
        return parsed.canonical

    def normalize_for_lookup(self, parsed: ParsedIdentifier) -> str:
        return parsed.lookup_key

    def normalize_for_comparison(self, parsed: ParsedIdentifier) -> str:
        return parsed.comparison_key

    def split_components(self, parsed: ParsedIdentifier) -> Tuple[NamespaceComponent, ...]:
        return tuple(parsed.components)


def _component(name, value, role="identity"):
    return NamespaceComponent(name, value, role)


class NpmNamespaceAdapter(_AdapterOperations):
    ecosystem = PackageEcosystem.NPM
    def parse_identifier(self, raw, private=False):
        scope, package = parse_npm(raw)
        canonical = (scope + "/" if scope else "") + package
        return ParsedIdentifier(self.ecosystem, raw, canonical, normalize_npm(canonical), canonical, tuple(filter(None, [_component("scope", scope, "owner namespace") if scope else None, _component("package", package)])), private=private)


class PythonPackageIndexNamespaceAdapter(_AdapterOperations):
    ecosystem = PackageEcosystem.PYPI
    def parse_identifier(self, raw, private=False):
        from .normalization import PYPI_NAME
        if not PYPI_NAME.fullmatch(raw): raise ValueError("Invalid Python distribution name.")
        normalized = normalize_pypi(raw)
        return ParsedIdentifier(self.ecosystem, raw, raw, normalized, normalized, (_component("distribution", raw),), (normalized.replace("-", "_"),), private)


class CratesIoNamespaceAdapter(_AdapterOperations):
    ecosystem = PackageEcosystem.CRATES_IO
    pattern = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
    def parse_identifier(self, raw, private=False):
        if not self.pattern.fullmatch(raw): raise ValueError("Invalid crates.io package name.")
        canonical = raw.lower(); projection = canonical.replace("-", "_")
        return ParsedIdentifier(self.ecosystem, raw, canonical, canonical, canonical, (_component("cargo_package", canonical),), (projection,), private)


class RubyGemsNamespaceAdapter(_AdapterOperations):
    ecosystem = PackageEcosystem.RUBYGEMS
    pattern = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
    def parse_identifier(self, raw, private=False):
        if not self.pattern.fullmatch(raw): raise ValueError("Invalid RubyGems gem name.")
        canonical = raw.lower(); projection = canonical.replace("-", "/")
        return ParsedIdentifier(self.ecosystem, raw, canonical, canonical, canonical, (_component("gem", canonical),), (projection,), private)


class NuGetNamespaceAdapter(_AdapterOperations):
    ecosystem = PackageEcosystem.NUGET
    pattern = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}\Z")
    def parse_identifier(self, raw, private=False):
        if not self.pattern.fullmatch(raw): raise ValueError("Invalid NuGet package identifier.")
        key = raw.casefold()
        prefix = raw.rsplit(".", 1)[0] if "." in raw else ""
        components = tuple(filter(None, [_component("package_id_prefix", prefix, "publisher namespace") if prefix else None, _component("package_id", raw)]))
        return ParsedIdentifier(self.ecosystem, raw, raw, key, key, components, private=private)


class MavenCentralNamespaceAdapter(_AdapterOperations):
    ecosystem = PackageEcosystem.MAVEN_CENTRAL
    part = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*\Z")
    def parse_identifier(self, raw, private=False):
        if raw.count(":") != 1: raise ValueError("Maven identity must be groupId:artifactId.")
        group, artifact = raw.split(":", 1)
        if not group or not artifact or not self.part.fullmatch(group) or not self.part.fullmatch(artifact): raise ValueError("Invalid Maven coordinate.")
        canonical = group + ":" + artifact
        return ParsedIdentifier(self.ecosystem, raw, canonical, canonical, canonical, (_component("group_id", group, "publisher namespace"), _component("artifact_id", artifact)), private=private)


class GoModuleNamespaceAdapter(_AdapterOperations):
    ecosystem = PackageEcosystem.GO_MODULE
    segment = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._~-]*\Z")
    def parse_identifier(self, raw, private=False):
        if "://" in raw or raw.startswith(("/", ".")): raise ValueError("Invalid Go module path.")
        parts = raw.split("/")
        if len(parts) < 2 or "." not in parts[0] or any(not self.segment.fullmatch(part) for part in parts): raise ValueError("Invalid Go module path.")
        suffix = parts[-1] if re.fullmatch(r"v[2-9][0-9]*", parts[-1]) else ""
        repository = parts[-2] if suffix else parts[-1]
        host = parts[0]
        return ParsedIdentifier(self.ecosystem, raw, raw, raw, proxy_escape(raw), (_component("host", host, "publisher namespace"), _component("repository", repository), _component("semantic_major", suffix) if suffix else _component("semantic_major", "")), private=private)


class PackagistNamespaceAdapter(_AdapterOperations):
    ecosystem = PackageEcosystem.PACKAGIST
    part = re.compile(r"^[a-z0-9](?:[_.-]?[a-z0-9]+)*\Z")
    def parse_identifier(self, raw, private=False):
        if raw.count("/") != 1: raise ValueError("Composer package must be vendor/package.")
        vendor, package = raw.split("/", 1)
        if not self.part.fullmatch(vendor) or not self.part.fullmatch(package): raise ValueError("Invalid Composer package name.")
        canonical = vendor + "/" + package
        return ParsedIdentifier(self.ecosystem, raw, canonical, canonical, canonical, (_component("vendor", vendor, "publisher namespace"), _component("package", package)), private=private)


ADAPTERS: Dict[PackageEcosystem, NamespaceAdapter] = {
    item.ecosystem: item for item in (NpmNamespaceAdapter(), PythonPackageIndexNamespaceAdapter(), CratesIoNamespaceAdapter(), RubyGemsNamespaceAdapter(), NuGetNamespaceAdapter(), MavenCentralNamespaceAdapter(), GoModuleNamespaceAdapter(), PackagistNamespaceAdapter())
}


def proxy_escape(path: str) -> str:
    output = []
    for char in path:
        if "A" <= char <= "Z": output.append("!" + char.lower())
        elif char == "!": output.append("!!")
        else: output.append(char)
    return "".join(output)


def matches_private(path: str, patterns: str) -> bool:
    for pattern in (item.strip() for item in patterns.split(",")):
        if pattern and (fnmatch.fnmatchcase(path, pattern) or path == pattern or path.startswith(pattern.rstrip("/") + "/")):
            return True
    return False


def adapter_for(ecosystem: PackageEcosystem) -> NamespaceAdapter:
    return ADAPTERS[ecosystem]
