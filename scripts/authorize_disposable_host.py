from __future__ import annotations
import argparse,hashlib,json,platform,socket
from datetime import datetime,timedelta,timezone
from pathlib import Path
def host_id(): return hashlib.sha256((socket.gethostname()+":"+platform.machine()).encode()).hexdigest()[:24]
def main():
 p=argparse.ArgumentParser(); p.add_argument("--output",type=Path,required=True); p.add_argument("--run-id",required=True); p.add_argument("--operator-role",required=True); p.add_argument("--hours",type=int,default=8); p.add_argument("--allow-install",action="store_true"); p.add_argument("--allow-signals",action="store_true"); p.add_argument("--allow-sigkill",action="store_true"); p.add_argument("--allow-reboot",action="store_true"); p.add_argument("--acknowledge-disposable",action="store_true"); a=p.parse_args()
 if not a.acknowledge_disposable: p.error("--acknowledge-disposable is required")
 now=datetime.now(timezone.utc); data={"schema_version":"1.0","test_run_id":a.run_id,"host_pseudonymous_id":host_id(),"purpose":"MSAA active-containment disposable-host qualification","allow_install":a.allow_install,"allow_service_registration":a.allow_install,"allow_fixture_signals":a.allow_signals,"allow_component_sigkill":a.allow_sigkill,"allow_reboot":a.allow_reboot,"authorized_at":now.isoformat(),"expires_at":(now+timedelta(hours=max(1,min(a.hours,24)))).isoformat(),"operator_role":a.operator_role,"disposable_or_recoverable_acknowledged":True}
 a.output.write_text(json.dumps(data,indent=2,sort_keys=True)+"\n",encoding="utf-8"); a.output.chmod(0o600); print(json.dumps({"created":str(a.output),"host_pseudonymous_id":data["host_pseudonymous_id"],"expires_at":data["expires_at"]}))
if __name__=="__main__": main()
