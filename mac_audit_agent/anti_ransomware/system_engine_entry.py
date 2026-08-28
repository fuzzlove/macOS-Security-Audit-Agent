from __future__ import annotations
import json, signal, sys, threading
from .containment_diagnostics import containment_status

def main(argv=None):
    argv=list(sys.argv[1:] if argv is None else argv)
    if argv==["--self-check"]: print(json.dumps(containment_status(),sort_keys=True)); return 0
    stop=threading.Event(); signal.signal(signal.SIGTERM,lambda *_:stop.set()); signal.signal(signal.SIGINT,lambda *_:stop.set())
    stop.wait(); return 0
if __name__=="__main__": raise SystemExit(main())
