from __future__ import annotations

import hashlib, json, os, shutil, stat
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


class QuarantineManager:
    def __init__(self, root: Path, *, production: bool=True):
        self.root=Path(root)
        self.root.mkdir(parents=True,exist_ok=True,mode=0o700)
        os.chmod(self.root,0o700)
        if production and (os.geteuid()!=0 or self.root.stat().st_uid!=0): raise PermissionError("production quarantine must be root-owned")

    @staticmethod
    def _hash(path):
        digest=hashlib.sha256()
        with path.open("rb") as handle:
            while chunk:=handle.read(1024*1024): digest.update(chunk)
        return digest.hexdigest()

    def quarantine(self, source: Path, *, incident_id: str, reason: str, authorized: bool, maximum_bytes: int=256*1024*1024):
        if not authorized or not incident_id or not reason: raise PermissionError("authorized incident and rationale required")
        source=Path(source); info=source.lstat()
        if not stat.S_ISREG(info.st_mode) or source.is_symlink() or info.st_nlink!=1 or info.st_size>maximum_bytes: raise ValueError("unsafe quarantine source")
        item_id=str(uuid4()); destination=self.root/(item_id+".quarantined"); original_hash=self._hash(source)
        try: os.replace(source,destination)
        except OSError:
            temporary=self.root/(item_id+".tmp"); shutil.copy2(source,temporary,follow_symlinks=False)
            if self._hash(temporary)!=original_hash: temporary.unlink(missing_ok=True); raise IOError("cross-volume quarantine verification failed")
            os.replace(temporary,destination); source.unlink()
        os.chmod(destination,0o600)
        manifest={"schema_version":"1.0","item_id":item_id,"incident_id":incident_id,"original_path":str(source.resolve(strict=False)),"original_uid":info.st_uid,"original_gid":info.st_gid,"original_mode":stat.S_IMODE(info.st_mode),"sha256":original_hash,"bytes":info.st_size,"reason":reason,"quarantined_at":datetime.now(timezone.utc).isoformat(),"signature_state":"unsigned_hash_manifest"}
        encoded=json.dumps(manifest,sort_keys=True,separators=(",",":")).encode(); manifest["manifest_sha256"]=hashlib.sha256(encoded).hexdigest()
        path=self.root/(item_id+".manifest.json"); path.write_text(json.dumps(manifest,sort_keys=True,indent=2),encoding="utf-8"); os.chmod(path,0o600)
        return manifest

    def restore(self, item_id: str, *, destination: Path|None=None, authorized: bool=False):
        if not authorized: raise PermissionError("restore requires explicit authorization")
        manifest_path=self.root/(item_id+".manifest.json"); manifest=json.loads(manifest_path.read_text(encoding="utf-8")); source=self.root/(item_id+".quarantined")
        if manifest.get("item_id")!=item_id or self._hash(source)!=manifest.get("sha256"): raise ValueError("quarantine integrity verification failed")
        target=Path(destination or manifest["original_path"]).expanduser()
        if target.exists() or target.is_symlink(): raise FileExistsError("restore destination already exists")
        target.parent.mkdir(parents=True,exist_ok=True); os.replace(source,target); os.chmod(target,int(manifest["original_mode"])); manifest["restored_at"]=datetime.now(timezone.utc).isoformat(); manifest["restore_path"]=str(target)
        manifest_path.write_text(json.dumps(manifest,sort_keys=True,indent=2),encoding="utf-8"); return manifest
