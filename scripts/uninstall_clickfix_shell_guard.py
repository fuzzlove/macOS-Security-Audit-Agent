from __future__ import annotations
import argparse, shutil
from pathlib import Path
from install_clickfix_shell_guard import BEGIN, END

def _remove_block(path: Path) -> None:
    if not path.is_file(): return
    lines=path.read_text(encoding="utf-8").splitlines(keepends=True); output=[]; skipping=False
    for line in lines:
        if line.rstrip("\r\n")==BEGIN: skipping=True; continue
        if line.rstrip("\r\n")==END: skipping=False; continue
        if not skipping: output.append(line)
    path.write_text("".join(output),encoding="utf-8")
def main(argv=None):
    p=argparse.ArgumentParser();p.add_argument("--home",type=Path,default=Path.home());p.add_argument("--prefix",type=Path);p.add_argument("--remove-logs",action="store_true");a=p.parse_args(argv)
    home=a.home.expanduser().resolve();prefix=(a.prefix or home/".local/lib/msaa-clickfix").expanduser().resolve()
    try: prefix.relative_to(home)
    except ValueError: raise SystemExit("refused to remove a prefix outside the selected home")
    for name in (".zshrc",".bashrc",".bash_profile"): _remove_block(home/name)
    if prefix.exists() and not (prefix/"MANIFEST.sha256").is_file(): raise SystemExit("refused install prefix without MSAA manifest")
    if prefix.exists(): shutil.rmtree(prefix)
    if a.remove_logs:
        log=home/"Library/Logs/MSAA/clickfix-events.jsonl"
        if log.is_file() and not log.is_symlink(): log.unlink()
    print("MSAA ClickFix shell integration removed. Event logs were " + ("removed." if a.remove_logs else "preserved."))
if __name__=="__main__":main()
