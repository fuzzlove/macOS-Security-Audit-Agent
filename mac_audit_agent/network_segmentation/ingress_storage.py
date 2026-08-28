from __future__ import annotations
import hashlib,json
from datetime import datetime,timezone
from uuid import uuid4

MIGRATION_VERSION=1
TABLES=("authorizations","zones","assets","probes","probe_capabilities","expected_flows","test_plans","test_cases","test_attempts","sender_observations","receiver_observations","path_inferences","findings","evidence_artifacts","remediations","retests","compliance_mappings")

def migrate(conn)->None:
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        conn.execute("CREATE TABLE IF NOT EXISTS segmentation_schema_migrations(version INTEGER PRIMARY KEY,applied_at TEXT NOT NULL,migration_sha256 TEXT NOT NULL)")
        conn.execute("CREATE TABLE IF NOT EXISTS segmentation_engagements(engagement_id TEXT PRIMARY KEY,created_at TEXT NOT NULL,payload_json TEXT NOT NULL)")
        for name in TABLES:
            conn.execute(f"CREATE TABLE IF NOT EXISTS segmentation_{name}(record_id TEXT PRIMARY KEY,engagement_id TEXT NOT NULL REFERENCES segmentation_engagements(engagement_id) ON DELETE RESTRICT,created_at TEXT NOT NULL,payload_json TEXT NOT NULL)")
        conn.execute("CREATE TABLE IF NOT EXISTS segmentation_audit_events(event_id TEXT PRIMARY KEY,engagement_id TEXT REFERENCES segmentation_engagements(engagement_id) ON DELETE RESTRICT,created_at TEXT NOT NULL,event_type TEXT NOT NULL,payload_json TEXT NOT NULL,previous_hash TEXT NOT NULL,event_hash TEXT NOT NULL)")
        digest=hashlib.sha256(("segmentation-ingress-v1:"+",".join(TABLES)).encode()).hexdigest()
        conn.execute("INSERT OR IGNORE INTO segmentation_schema_migrations VALUES(?,?,?)",(MIGRATION_VERSION,datetime.now(timezone.utc).isoformat(),digest))
        conn.commit()
    except Exception:
        conn.rollback()
        raise

class SegmentationRepository:
    def __init__(self,database):self.db=database;migrate(database.conn)
    def save_engagement(self,engagement)->None:
        payload=json.dumps(engagement.__dict__,sort_keys=True,separators=(",",":"))
        self.db.conn.execute("INSERT OR REPLACE INTO segmentation_engagements VALUES(?,?,?)",(engagement.engagement_id,datetime.now(timezone.utc).isoformat(),payload));self.db.conn.commit()
        self.audit(engagement.engagement_id,"engagement_saved",{"sha256":hashlib.sha256(payload.encode()).hexdigest()})
    def audit(self,engagement_id,event_type,payload)->str:
        row=self.db.conn.execute("SELECT event_hash FROM segmentation_audit_events WHERE engagement_id=? ORDER BY rowid DESC LIMIT 1",(engagement_id,)).fetchone();previous=row[0] if row else "0"*64
        created=datetime.now(timezone.utc).isoformat();event_id=str(uuid4());body=json.dumps({"event_id":event_id,"engagement_id":engagement_id,"created_at":created,"event_type":event_type,"payload":payload,"previous_hash":previous},sort_keys=True,separators=(",",":"));digest=hashlib.sha256(body.encode()).hexdigest()
        self.db.conn.execute("INSERT INTO segmentation_audit_events VALUES(?,?,?,?,?,?,?)",(event_id,engagement_id,created,event_type,json.dumps(payload,sort_keys=True),previous,digest));self.db.conn.commit()
        return digest
    def verify_chain(self,engagement_id)->bool:
        previous="0"*64
        for row in self.db.conn.execute("SELECT * FROM segmentation_audit_events WHERE engagement_id=? ORDER BY rowid",(engagement_id,)):
            body=json.dumps({"event_id":row["event_id"],"engagement_id":row["engagement_id"],"created_at":row["created_at"],"event_type":row["event_type"],"payload":json.loads(row["payload_json"]),"previous_hash":previous},sort_keys=True,separators=(",",":"))
            if row["previous_hash"]!=previous or not hashlib.sha256(body.encode()).hexdigest()==row["event_hash"]:return False
            previous=row["event_hash"]
        return True
