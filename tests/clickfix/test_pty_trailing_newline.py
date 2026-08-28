from pathlib import Path

ROOT=Path(__file__).parents[2]

def test_proxy_holds_paste_before_forwarding_and_strips_restored_newline():
    source=(ROOT/"mac_audit_agent/clickfix/safe_shell.py").read_text()
    assert "START=b\"\\x1b[200~\"" in source and "END=b\"\\x1b[201~\"" in source
    assert "held=bytes(paste)" in source
    assert "restored=held.rstrip(b\"\\r\\n\")" in source
    assert "os.write(fd,START+restored+END)" in source
    assert "os.write(fd,START+bytes(paste)+END)" in source
