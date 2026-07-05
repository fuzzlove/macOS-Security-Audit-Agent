from __future__ import annotations

import os
from pathlib import Path

from mac_audit_agent.launch_agent import MAC_AUDIT_AGENT_ENV_DB_PATH, MONITOR_ROLE_USER, default_monitor_db_path
from mac_audit_agent.monitor import main as monitor_main


def main(argv: list[str] | None = None) -> int:
    args = list(argv or [])
    db_path = os.environ.get(MAC_AUDIT_AGENT_ENV_DB_PATH, "").strip() or str(default_monitor_db_path("user"))
    forwarded = ["--db-path", str(Path(db_path).expanduser()), "--mode", MONITOR_ROLE_USER]
    if not args:
        forwarded.append("--run")
    else:
        forwarded.extend(args)
    return monitor_main(forwarded)


if __name__ == "__main__":
    raise SystemExit(main())
