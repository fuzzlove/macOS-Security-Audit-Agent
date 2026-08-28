from __future__ import annotations

import hashlib, json, os, secrets
from pathlib import Path

MARKER=".msaa-canary-manifest.json"

def deploy_canaries(root: Path, *, count: int=2, authorized: bool=False):
    if not authorized: raise PermissionError("canary deployment requires explicit authorization")
    root=Path(root).expanduser().resolve(strict=True)
    if not root.is_dir() or root.is_symlink() or not 1<=count<=10: raise ValueError("invalid canary root or count")
    records=[]
    for index in range(count):
        path=root/(".msaa-protection-canary-%02d.txt"%index)
        if path.exists() or path.is_symlink(): raise FileExistsError(path)
        content=("MSAA harmless protection canary\nToken: %s\n"%secrets.token_hex(16)).encode()
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,"wb") as handle: handle.write(content); handle.flush(); os.fsync(handle.fileno())
        records.append({"name":path.name,"sha256":hashlib.sha256(content).hexdigest()})
    manifest=root/MARKER; manifest.write_text(json.dumps({"schema_version":"1.0","files":records},sort_keys=True,indent=2),encoding="utf-8"); os.chmod(manifest,0o600)
    return records

def remove_canaries(root: Path, *, authorized: bool=False):
    if not authorized: raise PermissionError("canary removal requires explicit authorization")
    root=Path(root).resolve(strict=True); manifest=root/MARKER
    data=json.loads(manifest.read_text(encoding="utf-8")); removed=[]
    for record in data.get("files",[]):
        path=(root/record["name"]).resolve(strict=False)
        if path.parent != root or path.is_symlink(): raise PermissionError("canary path escaped root")
        if path.exists() and hashlib.sha256(path.read_bytes()).hexdigest()==record["sha256"]: path.unlink(); removed.append(path.name)
    manifest.unlink(); return removed
