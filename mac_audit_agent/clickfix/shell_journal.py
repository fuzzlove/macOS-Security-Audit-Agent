from __future__ import annotations

import json
from pathlib import Path


MAX_JOURNAL_BYTES = 32 * 1024 * 1024
MAX_LINE_BYTES = 64 * 1024
ALLOWED_DECISIONS = {"allow", "warn", "block", "error"}
REPORTABLE_TYPES = {"paste_warning", "paste_blocked", "submission_warning", "submission_blocked", "scanner_error", "scanner_timeout", "adapter_integrity_failure", "coverage_degraded"}


class ShellJournalError(ValueError): pass


class ShellEventJournalConsumer:
    """Bounded cursor consumer for the untrusted per-user privacy-safe journal."""
    def __init__(self, path: Path, *, cursor: int = 0): self.path=Path(path); self.cursor=max(0,int(cursor)); self.last_cursor=self.cursor

    def consume(self) -> list[dict[str, object]]:
        if not self.path.exists(): return []
        size=self.path.stat().st_size
        if size>MAX_JOURNAL_BYTES: raise ShellJournalError("shell_journal_size_limit")
        if self.cursor>size: self.cursor=0
        records=[]
        with self.path.open("rb") as handle:
            handle.seek(self.cursor)
            while True:
                line=handle.readline(MAX_LINE_BYTES+1)
                if not line: break
                if len(line)>MAX_LINE_BYTES or not line.endswith(b"\n"): raise ShellJournalError("shell_journal_line_invalid")
                try: payload=json.loads(line.decode("ascii"))
                except (UnicodeDecodeError,json.JSONDecodeError) as exc: raise ShellJournalError("shell_journal_json_invalid") from exc
                if not isinstance(payload,dict) or payload.get("schema")!="msaa.clickfix.event.v1": raise ShellJournalError("shell_journal_schema_invalid")
                forbidden={"command","raw_command","decoded_command","clipboard","environment","working_directory"}
                if forbidden & payload.keys(): raise ShellJournalError("shell_journal_sensitive_field")
                if payload.get("decision") not in ALLOWED_DECISIONS: raise ShellJournalError("shell_journal_decision_invalid")
                if payload.get("event_type") in REPORTABLE_TYPES: records.append(payload)
            self.last_cursor=handle.tell(); self.cursor=self.last_cursor
        return records


__all__ = ["ShellEventJournalConsumer", "ShellJournalError"]
