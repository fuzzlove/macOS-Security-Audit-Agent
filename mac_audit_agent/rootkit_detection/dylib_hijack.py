from __future__ import annotations

import os
import stat
import struct
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from mac_audit_agent.process_explorer import collect_process_snapshot
from mac_audit_agent.rootkit_detection.models import RootkitSuspectFinding, stable_id


MH_MAGIC = 0xFEEDFACE
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM = 0xCEFAEDFE
MH_CIGAM_64 = 0xCFFAEDFE
FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF
LC_REQ_DYLD = 0x80000000
LC_LOAD_DYLIB = 0xC
LC_LOAD_WEAK_DYLIB = 0x18 | LC_REQ_DYLD
LC_RPATH = 0x1C | LC_REQ_DYLD
LC_REEXPORT_DYLIB = 0x1F | LC_REQ_DYLD
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_LOAD_COMMANDS = 8192


@dataclass
class MachOLoadInfo:
    executable: bool = False
    architectures: int = 0
    rpaths: list[str] = field(default_factory=list)
    dylibs: list[str] = field(default_factory=list)
    weak_dylibs: list[str] = field(default_factory=list)
    reexports: list[str] = field(default_factory=list)


@dataclass
class DylibHijackCandidate:
    binary_path: str
    imported_name: str
    candidate_path: str
    intended_path: str
    issue_type: str
    severity: str
    confidence: str
    reasons: list[str]
    running: bool = False
    binary_signing: dict[str, Any] = field(default_factory=dict)
    library_signing: dict[str, Any] = field(default_factory=dict)


def _bounded_unique(values: list[str], limit: int = 2048) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))[:limit]


def parse_macho_load_commands(path: Path) -> tuple[MachOLoadInfo | None, str]:
    try:
        size = path.stat().st_size
        if size < 28 or size > MAX_FILE_BYTES:
            return None, "not a bounded Mach-O candidate"
        data = path.read_bytes()
    except OSError as exc:
        return None, str(exc)
    offsets: list[int] = []
    if len(data) < 4:
        return None, "truncated file"
    magic_be = struct.unpack_from(">I", data, 0)[0]
    if magic_be in {FAT_MAGIC, FAT_MAGIC_64}:
        if len(data) < 8:
            return None, "truncated fat header"
        count = min(struct.unpack_from(">I", data, 4)[0], 64)
        arch_size = 32 if magic_be == FAT_MAGIC_64 else 20
        for index in range(count):
            base = 8 + index * arch_size
            if base + arch_size > len(data):
                return None, "truncated fat architecture table"
            offset = struct.unpack_from(">Q" if arch_size == 32 else ">I", data, base + 8)[0]
            if offset < len(data):
                offsets.append(int(offset))
    else:
        offsets = [0]
    info = MachOLoadInfo()
    for offset in offsets:
        if offset + 28 > len(data):
            continue
        raw_magic = struct.unpack_from("<I", data, offset)[0]
        if raw_magic in {MH_MAGIC, MH_MAGIC_64}:
            endian = "<"
            is_64 = raw_magic == MH_MAGIC_64
        elif raw_magic in {MH_CIGAM, MH_CIGAM_64}:
            endian = ">"
            is_64 = raw_magic == MH_CIGAM_64
        else:
            continue
        header_size = 32 if is_64 else 28
        if offset + header_size > len(data):
            continue
        filetype = struct.unpack_from(endian + "I", data, offset + 12)[0]
        ncmds, sizeofcmds = struct.unpack_from(endian + "II", data, offset + 16)
        if ncmds > MAX_LOAD_COMMANDS or offset + header_size + sizeofcmds > len(data):
            return None, "invalid or excessive Mach-O load commands"
        info.architectures += 1
        info.executable = info.executable or filetype == 2
        cursor = offset + header_size
        command_end = cursor + sizeofcmds
        for _index in range(ncmds):
            if cursor + 8 > command_end:
                return None, "truncated load command"
            command, command_size = struct.unpack_from(endian + "II", data, cursor)
            if command_size < 12 or cursor + command_size > command_end:
                return None, "invalid load command size"
            normalized = command
            if normalized in {LC_RPATH, LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB}:
                name_offset = struct.unpack_from(endian + "I", data, cursor + 8)[0]
                if 0 < name_offset < command_size:
                    start = cursor + name_offset
                    end = data.find(b"\0", start, cursor + command_size)
                    if end != -1:
                        value = data[start:end].decode("utf-8", errors="replace")
                        target = info.rpaths if normalized == LC_RPATH else info.weak_dylibs if normalized == LC_LOAD_WEAK_DYLIB else info.reexports if normalized == LC_REEXPORT_DYLIB else info.dylibs
                        target.append(value)
            cursor += command_size
    if not info.architectures:
        return None, "not a supported Mach-O"
    info.rpaths = _bounded_unique(info.rpaths)
    info.dylibs = _bounded_unique(info.dylibs)
    info.weak_dylibs = _bounded_unique(info.weak_dylibs)
    info.reexports = _bounded_unique(info.reexports)
    return info, "available"


def resolve_special_path(value: str, binary_path: Path) -> str:
    directory = str(binary_path.parent)
    if value == "@executable_path" or value == "@loader_path":
        return directory
    if value.startswith("@executable_path/"):
        return os.path.normpath(os.path.join(directory, value[len("@executable_path/") :]))
    if value.startswith("@loader_path/"):
        return os.path.normpath(os.path.join(directory, value[len("@loader_path/") :]))
    return os.path.normpath(value) if value.startswith("/") else value


def path_is_writable_slot(path: Path) -> bool:
    current = path if path.exists() else path.parent
    while not current.exists() and current != current.parent:
        current = current.parent
    try:
        metadata = current.stat()
    except OSError:
        return False
    mode = metadata.st_mode
    if mode & stat.S_IWOTH:
        return True
    if mode & stat.S_IWGRP and metadata.st_gid in {os.getegid(), *os.getgroups()}:
        return True
    return os.geteuid() != 0 and metadata.st_uid == os.geteuid() and bool(mode & stat.S_IWUSR)


def codesign_metadata(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"valid": False, "team_id": "", "identifier": "", "hardened_runtime": False, "disable_library_validation": False, "status": "missing"}
    try:
        verify = subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(path)], capture_output=True, text=True, timeout=10)
        detail = subprocess.run(["/usr/bin/codesign", "-d", "--verbose=4", "--entitlements", ":-", str(path)], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError) as exc:
        return {"valid": False, "team_id": "", "identifier": "", "hardened_runtime": False, "disable_library_validation": False, "status": str(exc)}
    text = detail.stderr + detail.stdout
    team_id = next((line.split("=", 1)[1].strip() for line in text.splitlines() if line.startswith("TeamIdentifier=")), "")
    identifier = next((line.split("=", 1)[1].strip() for line in text.splitlines() if line.startswith("Identifier=")), "")
    lowered = text.lower()
    return {
        "valid": verify.returncode == 0,
        "team_id": team_id,
        "identifier": identifier,
        "hardened_runtime": "runtime" in lowered,
        "disable_library_validation": "com.apple.security.cs.disable-library-validation" in text,
        "status": (verify.stderr or "valid").strip(),
    }


class DylibHijackScanner:
    def __init__(self, *, parser=parse_macho_load_commands, signing_provider=codesign_metadata) -> None:
        self.parser = parser
        self.signing_provider = signing_provider

    def scan_binary(self, binary_path: Path, *, running: bool = False) -> tuple[list[DylibHijackCandidate], list[str]]:
        info, status = self.parser(binary_path)
        if info is None or not info.executable:
            return [], [] if status.startswith("not a") else [f"{binary_path}: {status}"]
        rpaths = [resolve_special_path(item, binary_path) for item in info.rpaths]
        binary_signing = self.signing_provider(binary_path)
        if binary_signing.get("valid") and binary_signing.get("hardened_runtime") and not binary_signing.get("disable_library_validation"):
            return [], []
        findings: list[DylibHijackCandidate] = []
        for imported in info.dylibs:
            if not imported.startswith("@rpath/"):
                continue
            suffix = imported[len("@rpath/") :]
            candidates = [Path(runpath) / suffix for runpath in rpaths if runpath.startswith("/")]
            existing = [path for path in candidates if path.is_file()]
            if len(existing) >= 2:
                loaded, intended = existing[0], existing[-1]
                loaded_signing = self.signing_provider(loaded)
                same_team = bool(binary_signing.get("team_id") and binary_signing.get("team_id") == loaded_signing.get("team_id"))
                if not same_team:
                    reasons = ["multiple existing libraries match one @rpath import", "dyld search order selects the earlier library"]
                    if not loaded_signing.get("valid"):
                        reasons.append("selected library has an invalid or missing signature")
                    if path_is_writable_slot(loaded):
                        reasons.append("selected library is in a user-writable location")
                    severity = "critical" if running and (not loaded_signing.get("valid") or path_is_writable_slot(loaded)) else "high"
                    findings.append(DylibHijackCandidate(str(binary_path), imported, str(loaded), str(intended), "loaded_rpath_shadow", severity, "high", reasons, running, binary_signing, loaded_signing))
            elif existing:
                intended = existing[0]
                for earlier in candidates[: candidates.index(intended)]:
                    if not earlier.exists() and path_is_writable_slot(earlier):
                        findings.append(DylibHijackCandidate(str(binary_path), imported, str(earlier), str(intended), "writable_rpath_slot", "medium", "medium", ["a writable earlier @rpath location could shadow the intended library", "no hijacking library currently exists at this path"], running, binary_signing, {}))
                        break
        for imported in info.weak_dylibs:
            paths = []
            if imported.startswith("@rpath/"):
                paths = [Path(runpath) / imported[len("@rpath/") :] for runpath in rpaths if runpath.startswith("/")]
            else:
                resolved = resolve_special_path(imported, binary_path)
                if resolved.startswith("/"):
                    paths = [Path(resolved)]
            for weak_path in paths:
                if not weak_path.is_file():
                    continue
                library_signing = self.signing_provider(weak_path)
                same_team = bool(binary_signing.get("team_id") and binary_signing.get("team_id") == library_signing.get("team_id"))
                if not same_team and (not library_signing.get("valid") or path_is_writable_slot(weak_path)):
                    findings.append(DylibHijackCandidate(str(binary_path), imported, str(weak_path), "", "suspicious_weak_import", "high" if running else "medium", "medium", ["optional weak library exists and can be loaded", "library trust does not match the executable"], running, binary_signing, library_signing))
                    break
        return findings, []

    def scan_running(self, *, max_binaries: int = 512) -> tuple[list[DylibHijackCandidate], list[str]]:
        records, coverage = collect_process_snapshot()
        if not coverage.startswith("available"):
            return [], [f"Running-process dylib coverage {coverage}"]
        paths = list(dict.fromkeys(record.path for record in records if record.path))[:max_binaries]
        findings: list[DylibHijackCandidate] = []
        limitations: list[str] = []
        for value in paths:
            current, warnings = self.scan_binary(Path(value), running=True)
            findings.extend(current)
            limitations.extend(warnings[:5])
        return findings, limitations[:100]


def rootkit_findings_from_dylibs(candidates: list[DylibHijackCandidate]) -> list[RootkitSuspectFinding]:
    findings: list[RootkitSuspectFinding] = []
    for item in candidates:
        active = item.issue_type in {"loaded_rpath_shadow", "suspicious_weak_import"}
        wording = "A Mach-O executable resolves a library through a suspicious search-path condition." if active else "A Mach-O executable has a writable search-path slot that could permit library shadowing. No hijacking library was found in that slot."
        findings.append(
            RootkitSuspectFinding(
                finding_id=stable_id("dylib-hijack", item.binary_path, item.imported_name, item.candidate_path),
                title="Possible Dynamic Library Hijack" if active else "Dynamic Library Hijack Exposure",
                severity=item.severity,
                confidence=item.confidence,
                category="dynamic_library_hijack",
                description=wording + " This is an advanced persistence or execution-hijack indicator, not confirmation of a rootkit.",
                evidence=[f"Executable: {item.binary_path}", f"Import: {item.imported_name}", f"Candidate: {item.candidate_path}", f"Intended: {item.intended_path or 'not established'}", *item.reasons],
                why_it_matters="A library loaded before the intended dependency can execute inside a trusted application's process context.",
                rootkit_relevance="User-space rootkits and malware can abuse dyld search order for stealthy execution or persistence.",
                false_positive_notes=["Development builds, plug-in hosts, compatibility frameworks, and applications that intentionally disable library validation can have unusual rpaths.", "A writable missing slot is exposure only; it is not an active hijack."],
                recommended_fix="Preserve the executable and library metadata, verify publishers and hashes, then reinstall the affected application from a trusted source if the loaded library is unauthorized.",
                examine_further_steps=["Inspect code signatures and Team IDs for both files.", "Review the executable's entitlements and hardened-runtime/library-validation posture.", "Correlate the library with process execution, persistence, quarantine, and network events."],
                apple_evidence_export_recommended=item.severity in {"high", "critical"},
                mitre_mappings=["T1574.006"],
            )
        )
    return findings
