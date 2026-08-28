"""Evidence-preserving SQLite recovery for the MSAA system monitor database."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path

from .storage import AuditDatabase, SYSTEM_MONITOR_DB_PATH

LABEL = "com.mac-audit-agent.monitor"
PLIST = Path("/Library/LaunchDaemons/com.mac-audit-agent.monitor.plist")


@dataclass(frozen=True)
class RecoveryReceipt:
    schema: str
    started_at: str
    completed_at: str
    source_path: str
    source_sha256: str
    source_bytes: int
    evidence_directory: str
    recovered_path: str
    recovered_sha256: str
    recovered_bytes: int
    integrity_check: str
    table_count: int
    launchd_restarted: bool


def _sha256(path: Path) -> str:
    digest=hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda:handle.read(1024*1024),b""):digest.update(block)
    return digest.hexdigest()


def quick_check(path: Path) -> str:
    connection=sqlite3.connect(f"file:{path}?mode=ro",uri=True)
    try:return str(connection.execute("PRAGMA quick_check").fetchone()[0])
    finally:connection.close()


def immutable_quick_check(path: Path) -> str:
    """Check only the main image, deliberately ignoring WAL/SHM sidecars."""
    connection=sqlite3.connect(f"file:{path}?mode=ro&immutable=1",uri=True)
    try:return str(connection.execute("PRAGMA quick_check").fetchone()[0])
    finally:connection.close()


def _launchctl(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["/bin/launchctl",*arguments],capture_output=True,text=True,timeout=30,check=check)


def recover_system_monitor_database(*, source: Path = SYSTEM_MONITOR_DB_PATH, evidence_root: Path | None = None, manage_launchd: bool = True) -> RecoveryReceipt:
    if os.geteuid()!=0:raise PermissionError("System monitor database recovery requires explicit administrator authorization.")
    source=source.resolve();started=datetime.now(timezone.utc);stamp=started.strftime("%Y%m%dT%H%M%SZ")
    evidence=(evidence_root or source.parent/"recovery-evidence")/stamp;evidence.mkdir(parents=True,mode=0o700)
    if manage_launchd:
        _launchctl("bootout",f"system/{LABEL}",check=False)
    source_digest=_sha256(source);source_size=source.stat().st_size
    for suffix in ("","-wal","-shm","-journal"):
        candidate=Path(str(source)+suffix)
        if candidate.exists():shutil.copy2(candidate,evidence/candidate.name)
    # A clean main image paired with a damaged WAL is recoverable without
    # reconstructing tables. This state is important: immutable SQLite reads
    # succeed while ordinary reads fail. Detach and preserve only the sidecars,
    # then validate ordinary access before allowing launchd to start again.
    try:
        live_integrity=quick_check(source)
    except sqlite3.Error:
        live_integrity="failed"
    try:
        main_integrity=immutable_quick_check(source)
    except sqlite3.Error:
        main_integrity="failed"
    sidecars=[Path(str(source)+suffix) for suffix in ("-wal","-shm","-journal")]
    if live_integrity!="ok" and main_integrity=="ok" and any(path.exists() for path in sidecars):
        for sidecar in sidecars:
            if sidecar.exists():os.replace(sidecar,evidence/(sidecar.name+".detached"))
        integrity=quick_check(source)
        if integrity!="ok":raise RuntimeError("sidecar_detach_integrity_failed:"+integrity[:200])
        connection=sqlite3.connect(f"file:{source}?mode=ro",uri=True)
        try:table_count=int(connection.execute("SELECT count(*) FROM sqlite_master WHERE type='table'").fetchone()[0])
        finally:connection.close()
        restarted=False
        if manage_launchd:
            bootstrap=_launchctl("bootstrap","system",str(PLIST),check=False)
            if bootstrap.returncode!=0 and "already" not in bootstrap.stderr.lower():raise RuntimeError("launchd_bootstrap_failed:"+bootstrap.stderr[:300])
            _launchctl("kickstart","-k",f"system/{LABEL}",check=True);restarted=True
        completed=datetime.now(timezone.utc)
        receipt=RecoveryReceipt("msaa.database.recovery.v1",started.isoformat(),completed.isoformat(),str(source),source_digest,source_size,str(evidence),str(source),_sha256(source),source.stat().st_size,integrity,table_count,restarted)
        receipt_path=evidence/"recovery-receipt.json";receipt_path.write_text(json.dumps({**asdict(receipt),"recovery_mode":"detached_corrupt_sidecars"},indent=2,sort_keys=True)+"\n",encoding="utf-8");os.chmod(receipt_path,0o600)
        return receipt
    recovered=evidence/(source.name+".recovered")
    sql_dump=evidence/"sqlite-recover.sql"
    with sql_dump.open("wb") as output:
        result=subprocess.run(["/usr/bin/sqlite3",str(source),".recover"],stdout=output,stderr=subprocess.PIPE,timeout=900,check=False)
    if result.returncode!=0:raise RuntimeError("sqlite_recover_failed:"+result.stderr.decode("utf-8","replace")[:500])
    with sql_dump.open("rb") as input_file:
        # A recovered dump can contain SQLite CLI directives that write status
        # text. Keep the repair command's stdout a single machine-readable JSON
        # document; only a bounded stderr excerpt is surfaced on failure.
        result=subprocess.run(
            ["/usr/bin/sqlite3",str(recovered)],
            stdin=input_file,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=900,
            check=False,
        )
    if result.returncode!=0:raise RuntimeError("sqlite_import_failed:"+result.stderr.decode("utf-8","replace")[:500])
    # Apply current schema migrations only after recovery has produced a separate database.
    with AuditDatabase(recovered):pass
    integrity=quick_check(recovered)
    if integrity!="ok":raise RuntimeError("recovered_database_integrity_failed:"+integrity[:200])
    connection=sqlite3.connect(f"file:{recovered}?mode=ro",uri=True)
    try:table_count=int(connection.execute("SELECT count(*) FROM sqlite_master WHERE type='table'").fetchone()[0])
    finally:connection.close()
    quarantined=source.with_name(source.name+f".corrupt-{stamp}")
    os.replace(source,quarantined)
    # WAL and shared-memory files belong to the old database generation. They
    # must never be attached to the newly recovered main image. Preserve them
    # beside the quarantined original before the atomic replacement.
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar=Path(str(source)+suffix)
        if sidecar.exists():
            os.replace(sidecar,Path(str(quarantined)+suffix))
    os.replace(recovered,source)
    os.chown(source,0,80);os.chmod(source,0o660)
    integrity_key=source.with_name(source.name+".audit-integrity.key")
    if integrity_key.exists():os.chown(integrity_key,0,80);os.chmod(integrity_key,0o640)
    restarted=False
    if manage_launchd:
        bootstrap=_launchctl("bootstrap","system",str(PLIST),check=False)
        if bootstrap.returncode!=0 and "already" not in bootstrap.stderr.lower():raise RuntimeError("launchd_bootstrap_failed:"+bootstrap.stderr[:300])
        _launchctl("kickstart","-k",f"system/{LABEL}",check=True);restarted=True
    completed=datetime.now(timezone.utc)
    receipt=RecoveryReceipt("msaa.database.recovery.v1",started.isoformat(),completed.isoformat(),str(source),source_digest,source_size,str(evidence),str(source),_sha256(source),source.stat().st_size,integrity,table_count,restarted)
    receipt_path=evidence/"recovery-receipt.json";receipt_path.write_text(json.dumps(asdict(receipt),indent=2,sort_keys=True)+"\n",encoding="utf-8");os.chmod(receipt_path,0o600)
    return receipt


__all__=["RecoveryReceipt","quick_check","immutable_quick_check","recover_system_monitor_database"]
