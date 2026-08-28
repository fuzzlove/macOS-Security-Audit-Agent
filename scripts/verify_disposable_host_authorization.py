from __future__ import annotations
import argparse,json
from datetime import datetime,timezone
from pathlib import Path
from authorize_disposable_host import host_id
def main():
 p=argparse.ArgumentParser(); p.add_argument("file",type=Path); p.add_argument("--action",choices=["install","signals","sigkill","reboot"],required=True); a=p.parse_args(); data=json.loads(a.file.read_text(encoding="utf-8")); key={"install":"allow_install","signals":"allow_fixture_signals","sigkill":"allow_component_sigkill","reboot":"allow_reboot"}[a.action]
 valid=data.get("host_pseudonymous_id")==host_id() and data.get("disposable_or_recoverable_acknowledged") is True and data.get(key) is True and datetime.fromisoformat(data["expires_at"])>datetime.now(timezone.utc)
 print(json.dumps({"authorized":valid,"action":a.action,"test_run_id":data.get("test_run_id"),"host_match":data.get("host_pseudonymous_id")==host_id()})); return 0 if valid else 3
if __name__=="__main__": raise SystemExit(main())
