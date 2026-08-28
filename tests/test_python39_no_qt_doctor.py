from __future__ import annotations

import json
import subprocess
from pathlib import Path


def test_python39_doctor_imports_no_qt() -> None:
    python39 = Path("/Library/Developer/CommandLineTools/usr/bin/python3")
    root = Path(__file__).parents[1]
    code = "import json,sys; from launcher import main; rc=main(['--doctor']); print(json.dumps({'rc':rc,'qt':[n for n in sys.modules if n.startswith(('PySide6','AppKit','Cocoa'))]}))"
    result = subprocess.run([str(python39), "-c", code], cwd=root, capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout.splitlines()[-1])
    assert payload["qt"] == []
