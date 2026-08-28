from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import shlex
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from uuid import uuid4

from mac_audit_agent.performance.subprocess_runner import BoundedCommandResult, run_bounded_command

from .errors import FirewallError

SAFE_POLICY = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
PF_TABLE_NAME_MAX = 31


def _table_name(policy_id: str, family: str) -> str:
    """Return a stable PF table identifier within pfctl's 31-byte limit."""
    candidate = f"msaa_{policy_id}_{family}"
    if len(candidate.encode("ascii")) <= PF_TABLE_NAME_MAX:
        return candidate
    digest = hashlib.sha256(candidate.encode("ascii")).hexdigest()[:8]
    suffix = f"_{family}_{digest}"
    prefix_length = PF_TABLE_NAME_MAX - len("msaa_") - len(suffix)
    return f"msaa_{policy_id[:prefix_length]}{suffix}"


@dataclass(frozen=True)
class IPListImport:
    total_lines: int
    ipv4: tuple[str, ...]
    ipv6: tuple[str, ...]
    duplicates: int
    invalid: tuple[str, ...]
    comments: int
    source_hash: str

    def to_dict(self) -> dict[str, object]: return asdict(self)


@dataclass(frozen=True)
class AnchorCandidate:
    policy_id: str
    anchor_name: str
    path: Path
    content_hash: str
    content: str
    import_summary: IPListImport | None
    validation: BoundedCommandResult | None = None


def parse_ip_list(text: str, *, max_entries: int = 100_000) -> IPListImport:
    v4: list[ipaddress.IPv4Network] = []
    v6: list[ipaddress.IPv6Network] = []
    invalid: list[str] = []
    comments = 0
    raw_count = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"): comments += int(bool(line)); continue
        token = line.split("#", 1)[0].strip()
        # Permit a single address/CIDR plus an optional trailing human comment,
        # but never reinterpret hosts-file/domain input as an address.
        token = token.split()[0]
        raw_count += 1
        if raw_count > max_entries:
            invalid.append("<FW023 table entry limit exceeded>"); break
        try: network = ipaddress.ip_network(token, strict=False)
        except ValueError: invalid.append(token); continue
        (v4 if network.version == 4 else v6).append(network)
    unique_count = len(set(v4)) + len(set(v6))
    collapsed4 = tuple(str(value) for value in ipaddress.collapse_addresses(v4))
    collapsed6 = tuple(str(value) for value in ipaddress.collapse_addresses(v6))
    return IPListImport(len(text.splitlines()), collapsed4, collapsed6, raw_count - unique_count, tuple(invalid), comments, hashlib.sha256(text.encode()).hexdigest())


def render_ip_anchor(policy_id: str, imported: IPListImport, *, action: str = "block", direction: str = "out", log: bool = False) -> str:
    if not SAFE_POLICY.fullmatch(policy_id): raise FirewallError("FW006", "Unsafe policy identifier.")
    if action not in {"block", "pass"} or direction not in {"in", "out"}: raise FirewallError("FW006", "Unsupported IP-list policy action or direction.")
    table4, table6 = _table_name(policy_id, "ipv4"), _table_name(policy_id, "ipv6")
    lines = [f"# MSAA managed IP-list policy {policy_id}", f"# source-sha256 {imported.source_hash}"]
    if imported.ipv4:
        lines.append(f"table <{table4}> persist {{ {', '.join(imported.ipv4)} }}")
        lines.append(f"{action} {direction}{' log' if log else ''} quick inet to <{table4}> label \"MSAA:{policy_id}:ipv4\"")
    if imported.ipv6:
        lines.append(f"table <{table6}> persist {{ {', '.join(imported.ipv6)} }}")
        lines.append(f"{action} {direction}{' log' if log else ''} quick inet6 to <{table6}> label \"MSAA:{policy_id}:ipv6\"")
    if not imported.ipv4 and not imported.ipv6: raise FirewallError("FW006", "The imported list contains no valid IP addresses or subnets.")
    body = "\n".join(lines) + "\n"
    return f"# content-sha256 {hashlib.sha256(body.encode()).hexdigest()}\n{body}"


def create_candidate(policy_id: str, imported: IPListImport, *, root: Path | None = None, action: str = "block", direction: str = "out", log: bool = False) -> AnchorCandidate:
    content = render_ip_anchor(policy_id, imported, action=action, direction=direction, log=log)
    return create_content_candidate(policy_id, content, root=root, import_summary=imported)


def create_content_candidate(policy_id: str, content: str, *, root: Path | None = None, import_summary: IPListImport | None = None) -> AnchorCandidate:
    if not SAFE_POLICY.fullmatch(policy_id): raise FirewallError("FW006", "Unsafe policy identifier.")
    root = Path(root or (Path.home() / "Library/Application Support/MSAA/Firewall/generated")).expanduser()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if root.is_symlink(): raise FirewallError("FW006", "Candidate directory must not be a symbolic link.")
    path = root / f"com.liquidsky.msaa.firewall.{policy_id}.{uuid4().hex}.conf"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try: os.write(descriptor, content.encode())
    finally: os.close(descriptor)
    return AnchorCandidate(policy_id, f"com.liquidsky.msaa.firewall.{policy_id}", path, hashlib.sha256(content.encode()).hexdigest(), content, import_summary)


def validate_candidate(candidate: AnchorCandidate) -> AnchorCandidate:
    if candidate.path.is_symlink() or candidate.path.resolve(strict=True) != candidate.path: raise FirewallError("FW006", "Candidate path failed canonical or symlink validation.")
    result = run_bounded_command(["/sbin/pfctl", "-n", "-a", candidate.anchor_name, "-f", str(candidate.path)], timeout_seconds=15, max_output_bytes=262144, env={"LC_ALL": "C", "LANG": "C"})
    fatal_stderr = "\n".join(line for line in result.stderr.splitlines() if "ALTQ" not in line)
    if result.returncode != 0: raise FirewallError("FW005", fatal_stderr or result.error or "PF syntax validation failed; active networking was not changed.")
    return AnchorCandidate(candidate.policy_id, candidate.anchor_name, candidate.path, candidate.content_hash, candidate.content, candidate.import_summary, result)


def sudo_install_command(candidate: AnchorCandidate) -> str:
    return shlex.join([
        "sudo",
        sys.executable,
        "-m",
        "mac_audit_agent.firewall.sudo_pf",
        "--candidate",
        str(candidate.path),
        "--anchor",
        candidate.anchor_name,
        "--sha256",
        candidate.content_hash,
    ])
