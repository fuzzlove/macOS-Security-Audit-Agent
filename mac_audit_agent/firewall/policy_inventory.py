from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass
from pathlib import Path

ANCHOR_PREFIX = "com.liquidsky.msaa.firewall."
POLICY_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
VERSION = re.compile(r"\bversion=(\d+)\b")

@dataclass(frozen=True)
class PolicyInventoryItem:
    policy_id: str
    version: int
    state: str
    rules: int
    allow_rules: int
    block_rules: int
    anchor: str
    validation: str
    content_hash: str
    drift: str
    candidate_path: str = ""
    installed_path: str = ""
    def to_dict(self): return asdict(self)

def _read_regular(path: Path) -> str | None:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 10_000_000: return None
        return path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError): return None

def _policy_id(path: Path, *, generated: bool) -> str | None:
    name=path.name
    if not name.startswith(ANCHOR_PREFIX): return None
    remainder=name[len(ANCHOR_PREFIX):]
    if generated:
        if not remainder.endswith(".conf"): return None
        remainder=remainder[:-5]
        parts=remainder.rsplit(".",1)
        if len(parts)!=2 or not re.fullmatch(r"[0-9a-f]{32}",parts[1]): return None
        remainder=parts[0]
    return remainder if POLICY_ID.fullmatch(remainder) else None

def _facts(text: str) -> tuple[int,int,int,int,str]:
    lines=[line.strip() for line in text.splitlines()]
    rules=[line for line in lines if line.startswith(("pass ","block "))]
    allow=sum(line.startswith("pass ") for line in rules); block=sum(line.startswith("block ") for line in rules)
    version=1
    for line in lines:
        match=VERSION.search(line)
        if match: version=int(match.group(1)); break
    return version,len(rules),allow,block,hashlib.sha256(text.encode()).hexdigest()

def inventory_policies(*, generated_root: Path | None = None, anchor_root: Path = Path("/etc/pf.anchors")) -> tuple[PolicyInventoryItem,...]:
    generated_root=Path(generated_root or (Path.home()/"Library/Application Support/MSAA/Firewall/generated")).expanduser()
    candidates: dict[str,tuple[Path,str]]={}
    try: generated_paths=sorted(generated_root.glob(f"{ANCHOR_PREFIX}*.conf"),key=lambda path:path.stat().st_mtime,reverse=True)
    except OSError: generated_paths=[]
    for path in generated_paths:
        policy_id=_policy_id(path,generated=True); text=_read_regular(path)
        if policy_id and text is not None and policy_id not in candidates: candidates[policy_id]=(path,text)
    installed: dict[str,tuple[Path,str]]={}
    try: installed_paths=tuple(anchor_root.glob(f"{ANCHOR_PREFIX}*"))
    except OSError: installed_paths=()
    for path in installed_paths:
        policy_id=_policy_id(path,generated=False); text=_read_regular(path)
        if policy_id and text is not None: installed[policy_id]=(path,text)
    items=[]
    for policy_id in sorted(set(candidates)|set(installed)):
        candidate=candidates.get(policy_id); active=installed.get(policy_id); selected=active or candidate
        assert selected is not None
        version,rules,allow,block,digest=_facts(selected[1])
        if active and candidate: drift="No" if _facts(active[1])[4]==_facts(candidate[1])[4] else "Candidate differs"
        else: drift="—"
        items.append(PolicyInventoryItem(policy_id,version,"Installed" if active else "Candidate",rules,allow,block,f"{ANCHOR_PREFIX}{policy_id}","Installed" if active else "Generated; load to validate",digest,drift,str(candidate[0]) if candidate else "",str(active[0]) if active else ""))
    return tuple(items)
