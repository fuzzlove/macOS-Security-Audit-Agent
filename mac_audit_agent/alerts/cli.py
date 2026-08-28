from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from mac_audit_agent.alerts.resilient_pipeline import pipeline_for
from mac_audit_agent.alerts.suppression import SuppressionPolicy, SuppressionRequest
from mac_audit_agent.storage import AuditDatabase


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="msaa alerts", description="Inspect the local resilient alert pipeline.")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("status", "active", "history", "health", "export", "verify-integrity"):
        _common(commands.add_parser(name))
    show = commands.add_parser("show"); _common(show); show.add_argument("identifier")
    suppression = commands.add_parser("suppression"); _common(suppression)
    suppression_commands = suppression.add_subparsers(dest="suppression_command", required=True)
    suppression_commands.add_parser("list")
    create = suppression_commands.add_parser("create")
    create.add_argument("--field", required=True, choices=sorted(SuppressionPolicy.SAFE_FIELDS)); create.add_argument("--value", required=True)
    create.add_argument("--scope", default="detector"); create.add_argument("--owner", required=True); create.add_argument("--expires", required=True)
    create.add_argument("--reason", required=True); create.add_argument("--ticket", required=True); create.add_argument("--authorizer", required=True); create.add_argument("--approver", default="")
    revoke = suppression_commands.add_parser("revoke"); revoke.add_argument("rule_id"); revoke.add_argument("--actor", required=True); revoke.add_argument("--reason", required=True)
    return parser


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--db", type=Path, default=Path.home() / ".mac_audit_agent.sqlite3")
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--output", type=Path)


def _require_privileged_change() -> None:
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise PermissionError("suppression changes require the authorized privileged MSAA workflow")


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv); db = AuditDatabase(args.db.expanduser()); pipeline = pipeline_for(db); limit = max(1, min(args.limit, 1000))
    if args.command in {"status", "health"}: payload = {**pipeline.store.health(), **pipeline.degraded_status()}
    elif args.command == "verify-integrity": payload = pipeline.store.verify_integrity()
    elif args.command == "active": payload = [dict(row) for row in db.conn.execute("SELECT * FROM resilient_alert_aggregates WHERE lifecycle!='RESOLVED' ORDER BY CASE highest_severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,last_seen DESC LIMIT ?", (limit,))]
    elif args.command == "history": payload = [{key:value for key,value in dict(row).items() if key not in {"canonical_json","previous_integrity_hash","integrity_hash"}} for row in db.conn.execute("SELECT * FROM resilient_security_events ORDER BY sequence_number DESC LIMIT ?", (limit,))]
    elif args.command == "show":
        row = db.conn.execute("SELECT * FROM resilient_alert_aggregates WHERE alert_id=? OR fingerprint=?", (args.identifier,args.identifier)).fetchone(); payload = dict(row) if row else {"error":"alert not found"}
    elif args.command == "suppression":
        policy = pipeline.suppressions
        if args.suppression_command == "list": payload = policy.list()
        elif args.suppression_command == "create":
            try:
                _require_privileged_change()
                request = SuppressionRequest(args.scope,{args.field:args.value},args.owner,datetime.now(timezone.utc).isoformat(),args.expires,args.reason,args.ticket,args.authorizer,approval_identity=args.approver)
                payload = {"rule_id":policy.create(request,protected_scope=False),"created":True}
            except (PermissionError,ValueError) as exc: payload = {"error":str(exc)}
        else:
            try: _require_privileged_change(); payload = {"rule_id":args.rule_id,"revoked":policy.revoke(args.rule_id,actor=args.actor,reason=args.reason)}
            except (PermissionError,ValueError) as exc: payload = {"error":str(exc)}
    else:
        payload = {"health":{**pipeline.store.health(),**pipeline.degraded_status()},"integrity":pipeline.store.verify_integrity(),"active":[dict(row) for row in db.conn.execute("SELECT * FROM resilient_alert_aggregates ORDER BY last_seen DESC LIMIT ?",(limit,))]}
    rendered = json.dumps(payload,indent=2,sort_keys=True)
    if args.output:
        descriptor = os.open(args.output.expanduser(),os.O_WRONLY|os.O_CREAT|os.O_TRUNC|getattr(os,"O_NOFOLLOW",0),0o600)
        try: os.write(descriptor,(rendered+"\n").encode())
        finally: os.close(descriptor)
    else: print(rendered)
    return 0 if not isinstance(payload,dict) or "error" not in payload else 2
