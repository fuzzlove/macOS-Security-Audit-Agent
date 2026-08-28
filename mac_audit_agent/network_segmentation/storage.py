from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .models import EgressRun


class EgressEvidenceStore:
    def __init__(self,path:Path)->None:
        self.path=path.expanduser();self.path.parent.mkdir(parents=True,exist_ok=True)
        self.connection=sqlite3.connect(self.path)
        self.connection.execute("PRAGMA journal_mode=WAL");self.connection.execute("PRAGMA synchronous=FULL")
        self.connection.executescript("""
        CREATE TABLE IF NOT EXISTS egress_runs(run_id TEXT PRIMARY KEY,started_at TEXT NOT NULL,completed_at TEXT NOT NULL,provider_id TEXT NOT NULL,authorization_reference TEXT NOT NULL,target_scope TEXT NOT NULL,report_json TEXT NOT NULL,report_sha256 TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS egress_results(probe_id TEXT PRIMARY KEY,run_id TEXT NOT NULL REFERENCES egress_runs(run_id),port INTEGER NOT NULL,protocol TEXT NOT NULL,status TEXT NOT NULL,latency_ms REAL,error_code TEXT NOT NULL,evidence_sha256 TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_egress_results_run ON egress_results(run_id,port);
        """);self.connection.commit()
        try:self.path.chmod(0o600)
        except OSError:pass

    def save(self,run:EgressRun)->str:
        import hashlib
        payload=json.dumps(run.to_dict(),sort_keys=True,separators=(",",":"));digest=hashlib.sha256(payload.encode()).hexdigest()
        with self.connection:
            self.connection.execute("INSERT INTO egress_runs VALUES(?,?,?,?,?,?,?,?)",(run.run_id,run.started_at,run.completed_at,run.provider.provider_id,run.authorization_reference,run.target_scope,payload,digest))
            self.connection.executemany("INSERT INTO egress_results VALUES(?,?,?,?,?,?,?,?)",[(item.probe_id,run.run_id,item.port,item.protocol,item.status,item.latency_ms,item.error_code,item.evidence_sha256) for item in run.results])
        return digest

    def load(self,run_id:str)->dict:
        row=self.connection.execute("SELECT report_json FROM egress_runs WHERE run_id=?",(run_id,)).fetchone()
        if row is None:raise KeyError(run_id)
        return json.loads(row[0])

    def close(self)->None:self.connection.close()
