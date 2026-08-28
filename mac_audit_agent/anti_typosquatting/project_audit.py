from __future__ import annotations

import json
import os
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterable, List

from mac_audit_agent.compat.tomllib import loads as toml_loads

from .models import LocalDependencyOccurrence, LocalProjectAudit, PackageEcosystem, ProtectedAsset
from .service import AntiTyposquattingService

MAX_FILES = 2000
MAX_FILE_BYTES = 5_000_000
NAMES = {"package.json", "package-lock.json", "npm-shrinkwrap.json", "pyproject.toml", "requirements.txt", "poetry.lock", "Pipfile", "Pipfile.lock", "uv.lock", "Cargo.toml", "Cargo.lock", "Gemfile", "Gemfile.lock", "packages.config", "packages.lock.json", "Directory.Packages.props", "NuGet.Config", "pom.xml", "go.mod", "go.sum", "go.work", "composer.json", "composer.lock", "bom.json", "spdx.json"}
SUFFIXES = {".csproj", ".fsproj", ".vbproj", ".gemspec", ".gradle", ".kts", ".lock", ".toml"}


def _occ(ecosystem, name, path, dep_type="dependency", location="", source="default registry", production=True):
    return LocalDependencyOccurrence(ecosystem, name, str(path), dep_type, location, source, production)


def scan_project(root: Path, protected_assets: Iterable[ProtectedAsset] = (), *, follow_symlinks: bool = False) -> LocalProjectAudit:
    root = root.expanduser().resolve(strict=True)
    if not root.is_dir(): raise ValueError("Project audit root must be a directory.")
    occurrences, errors, count = [], [], 0
    for current, dirs, files in os.walk(root, followlinks=False):
        base = Path(current)
        dirs[:] = [name for name in dirs if name not in {".git", "node_modules", ".venv", "vendor", "target", "bin", "obj"} and (follow_symlinks or not (base / name).is_symlink())]
        for filename in sorted(files):
            path = base / filename
            if filename not in NAMES and path.suffix not in SUFFIXES: continue
            if path.is_symlink() and not follow_symlinks: continue
            try:
                resolved = path.resolve(strict=True)
                if root not in resolved.parents: continue
                if path.stat().st_size > MAX_FILE_BYTES:
                    errors.append({"path": str(path), "error": "file_size_limit"}); continue
                occurrences.extend(parse_manifest(path))
            except (OSError, ValueError, json.JSONDecodeError, ET.ParseError) as exc:
                errors.append({"path": str(path), "error": type(exc).__name__})
            count += 1
            if count >= MAX_FILES: break
        if count >= MAX_FILES: break
    findings = correlate(occurrences, list(protected_assets))
    return LocalProjectAudit("1.0", str(root), occurrences, findings, errors, count)


def parse_manifest(path: Path) -> List[LocalDependencyOccurrence]:
    name = path.name
    text = path.read_text(encoding="utf-8", errors="strict")
    if name in {"package.json", "package-lock.json", "npm-shrinkwrap.json"}:
        data = json.loads(text); out = []
        for section, production in (("dependencies", True), ("devDependencies", False), ("optionalDependencies", True)):
            for dep, value in (data.get(section, {}) or {}).items(): out.append(_occ(PackageEcosystem.NPM, dep, path, section, section + "." + dep, str(value) if str(value).startswith(("http", "git")) else "default registry", production))
        return out
    if name == "pyproject.toml":
        data = toml_loads(text); out=[]
        for item in data.get("project", {}).get("dependencies", []) or []:
            dep = re.split(r"[ <>=!~\[]", str(item), maxsplit=1)[0]; out.append(_occ(PackageEcosystem.PYPI, dep, path, "dependency", "project.dependencies"))
        return out
    if name.startswith("requirements") or name in {"Pipfile", "Pipfile.lock", "poetry.lock", "uv.lock"}:
        return [_occ(PackageEcosystem.PYPI, match.group(1), path, "dependency", "line:%d" % index) for index, line in enumerate(text.splitlines(), 1) if (match := re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:[<>=!~]|$)", line))]
    if name in {"Cargo.toml", "Cargo.lock"}:
        data = toml_loads(text); out=[]
        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            for alias, value in (data.get(section, {}) or {}).items():
                package = value.get("package", alias) if isinstance(value, dict) else alias
                out.append(_occ(PackageEcosystem.CRATES_IO, package, path, section, section + "." + alias, "alternate registry" if isinstance(value, dict) and ("registry" in value or "git" in value) else "crates.io", section == "dependencies"))
        return out
    if name in {"Gemfile", "Gemfile.lock"} or path.suffix == ".gemspec":
        return [_occ(PackageEcosystem.RUBYGEMS, match.group(1), path, "gem", "line:%d" % index) for index, line in enumerate(text.splitlines(), 1) if (match := re.search(r"(?:gem\s+['\"]|^\s{4})([A-Za-z0-9_.-]+)", line))]
    if name in {"packages.lock.json"}:
        data=json.loads(text); return [_occ(PackageEcosystem.NUGET, dep, path, "package-reference", "dependencies."+dep) for framework in (data.get("dependencies", {}) or {}).values() if isinstance(framework, dict) for dep in framework]
    if name in {"packages.config", "Directory.Packages.props"} or path.suffix in {".csproj", ".fsproj", ".vbproj"}:
        tree=ET.fromstring(text); return [_occ(PackageEcosystem.NUGET, node.attrib.get("Include") or node.attrib.get("id"), path, "package-reference", node.tag) for node in tree.iter() if node.tag.split("}")[-1] in {"PackageReference", "PackageVersion", "package"} and (node.attrib.get("Include") or node.attrib.get("id"))]
    if name == "pom.xml":
        tree=ET.fromstring(text); out=[]
        for node in tree.iter():
            if node.tag.split("}")[-1] == "dependency":
                values={child.tag.split("}")[-1]: child.text for child in node}; group,artifact=values.get("groupId"),values.get("artifactId")
                if group and artifact: out.append(_occ(PackageEcosystem.MAVEN_CENTRAL, group+":"+artifact, path, "dependency", "dependency"))
        return out
    if path.suffix in {".gradle", ".kts"} or name.endswith("versions.toml"):
        return [_occ(PackageEcosystem.MAVEN_CENTRAL, m.group(1)+":"+m.group(2), path, "dependency", "line") for m in re.finditer(r"['\"]([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):", text)]
    if name in {"go.mod", "go.work"}:
        return [_occ(PackageEcosystem.GO_MODULE, m.group(1), path, "module", "line:%d" % index) for index,line in enumerate(text.splitlines(),1) if (m:=re.match(r"\s*(?:require|use)?\s*([^\s()]+)\s+v\d", line))]
    if name in {"composer.json", "composer.lock"}:
        data=json.loads(text); out=[]
        for section, production in (("require", True), ("require-dev", False)):
            for dep in (data.get(section,{}) or {}):
                if "/" in dep and dep != "php": out.append(_occ(PackageEcosystem.PACKAGIST, dep, path, section, section+"."+dep, "custom repository" if data.get("repositories") else "packagist", production))
        for package in data.get("packages",[]) or []:
            if isinstance(package,dict) and package.get("name"): out.append(_occ(PackageEcosystem.PACKAGIST, package["name"], path, "locked", "packages"))
        return out
    if name in {"bom.json", "spdx.json"}:
        data=json.loads(text); out=[]
        for component in data.get("components",[]) or []:
            purl=str(component.get("purl", "")); match=re.match(r"pkg/([^/]+)/([^@?]+)",purl)
            if match:
                mapping={"npm":PackageEcosystem.NPM,"pypi":PackageEcosystem.PYPI,"cargo":PackageEcosystem.CRATES_IO,"gem":PackageEcosystem.RUBYGEMS,"nuget":PackageEcosystem.NUGET,"maven":PackageEcosystem.MAVEN_CENTRAL,"golang":PackageEcosystem.GO_MODULE,"composer":PackageEcosystem.PACKAGIST}
                if match.group(1) in mapping: out.append(_occ(mapping[match.group(1)], match.group(2), path, "sbom", "components"))
        return out
    return []


def correlate(occurrences, assets):
    findings=[]
    service=AntiTyposquattingService()
    for asset in assets:
        try: candidates=service.analyze(asset).candidates
        except ValueError: continue
        keys={item.normalized_name:item for item in candidates}
        for occurrence in occurrences:
            if occurrence.ecosystem != asset.ecosystem: continue
            try:
                from .namespaces import adapter_for
                key=adapter_for(occurrence.ecosystem).parse_identifier(occurrence.declared_identifier).comparison_key
            except ValueError: continue
            if key in keys:
                findings.append({"finding_id":"dependency-lookalike", "protected_asset":asset.canonical_name, "dependency":occurrence.declared_identifier, "manifest_path":occurrence.manifest_path, "production":occurrence.production, "rule_ids":[r.rule_id for r in keys[key].reasons], "supply_chain_reachability":80 if occurrence.production else 50, "classification":"requires_human_investigation"})
    return findings
