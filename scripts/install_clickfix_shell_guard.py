from __future__ import annotations
import argparse, hashlib, json, os, plistlib, shutil, shlex, subprocess, sys
from datetime import datetime, timezone
from pathlib import Path

BEGIN="# >>> MSAA CLICKFIX GUARD MANAGED BLOCK >>>"; END="# <<< MSAA CLICKFIX GUARD MANAGED BLOCK <<<"
def _block(adapter):
    quoted=shlex.quote(str(adapter)); return f"{BEGIN}\n[ -r {quoted} ] && . {quoted}\n{END}\n"
def _edit(path,adapter,dry):
    text=path.read_text(encoding="utf-8") if path.exists() else ""
    if BEGIN in text and END in text:return "already_installed"
    if dry:return "would_modify"
    path.parent.mkdir(parents=True,exist_ok=True)
    if path.exists(): shutil.copy2(path,path.with_name(path.name+".msaa-clickfix-backup-"+datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")))
    path.write_text(text+("\n" if text and not text.endswith("\n") else "")+_block(adapter),encoding="utf-8");return "installed"
def _validate_scanner(scanner: Path, timeout_seconds: float = 3.0) -> None:
    request={"schema":"msaa.clickfix.request.v1","command":"printf MSAA_CLICKFIX_INSTALL_VALIDATION","phase":"test","paste_origin":"none","multiline":False,"trailing_newline":False,"shell_path":"","shell_version":"","terminal_bundle_id":"","tty":"","session_id":"installer-validation","mode":"audit","configuration_version":"installer"}
    try:
        result=subprocess.run([sys.executable,str(scanner)],input=json.dumps(request),text=True,capture_output=True,timeout=timeout_seconds,check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SystemExit("ClickFix scanner validation failed; startup files were not modified") from exc
    try: payload=json.loads(result.stdout)
    except json.JSONDecodeError as exc: raise SystemExit("ClickFix scanner validation failed: output was not one JSON decision") from exc
    if result.returncode != 0 or payload.get("decision") != "allow" or payload.get("command_sha256") is None:
        raise SystemExit("ClickFix scanner validation failed; startup files were not modified")
def _set_user_mode(home: Path, mode: str, dry: bool) -> str:
    if Path("/Library/Managed Preferences/com.msaa.clickfix.plist").is_file(): return "managed_system_policy_unchanged"
    path=home/"Library/Preferences/com.msaa.clickfix.plist"
    if dry:return f"would_set_{mode}"
    try: payload=plistlib.loads(path.read_bytes()) if path.is_file() else {}
    except (OSError,ValueError,TypeError,plistlib.InvalidFileException): payload={}
    if not isinstance(payload,dict):payload={}
    payload["mode"]=mode;payload["configuration_version"]="shell-installer-1"
    path.parent.mkdir(parents=True,exist_ok=True);temporary=path.with_name(path.name+".tmp")
    temporary.write_bytes(plistlib.dumps(payload,sort_keys=True));temporary.chmod(0o600);os.replace(temporary,path)
    return mode
def main(argv=None):
    p=argparse.ArgumentParser();p.add_argument("--dry-run",action="store_true");p.add_argument("--mode",choices=("audit","warn","block"));p.add_argument("--prefix",type=Path,default=Path.home()/".local/lib/msaa-clickfix");p.add_argument("--home",type=Path,default=Path.home());a=p.parse_args(argv)
    source=Path(__file__).resolve().parents[1];prefix=a.prefix.expanduser().resolve();home=a.home.expanduser().resolve()
    if not str(prefix).startswith(str(home)) and os.geteuid()!=0:raise SystemExit("managed prefix outside home requires administrator execution")
    files={"msaa-clickfix-scan":source/"scripts/msaa-clickfix-scan","msaa-clickfix-adapter":source/"scripts/msaa-clickfix-adapter","msaa-safe-shell":source/"scripts/msaa-safe-shell","msaa-clickfix.zsh":source/"mac_audit_agent/clickfix/shell_integration/msaa-clickfix.zsh","msaa-clickfix.bash":source/"mac_audit_agent/clickfix/shell_integration/msaa-clickfix.bash"}
    modules=("adapter_cli.py","safe_shell.py","scan_cli.py","shell_config.py","shell_events.py","shell_scanner.py","shell_tokenizer.py")
    _validate_scanner(files["msaa-clickfix-scan"])
    if not a.dry_run:
        prefix.mkdir(parents=True,exist_ok=True)
        for name,src in files.items():
            content=src.read_text(encoding="utf-8").replace("__MSAA_ADAPTER_PATH__",str(prefix/"msaa-clickfix-adapter"));dst=prefix/name;dst.write_text(content,encoding="utf-8");dst.chmod(0o755 if "." not in name or name=="msaa-safe-shell" else 0o644)
        package=prefix/"lib/mac_audit_agent/clickfix";package.mkdir(parents=True,exist_ok=True)
        (package.parent/"__init__.py").write_text("\"\"\"Private MSAA ClickFix runtime.\"\"\"\n",encoding="utf-8")
        (package/"__init__.py").write_text("\"\"\"Private MSAA ClickFix shell runtime.\"\"\"\n",encoding="utf-8")
        for name in modules: shutil.copy2(source/"mac_audit_agent/clickfix"/name,package/name)
        _validate_scanner(prefix/"msaa-clickfix-scan")
        installed=[*files,"lib/mac_audit_agent/__init__.py","lib/mac_audit_agent/clickfix/__init__.py",*(f"lib/mac_audit_agent/clickfix/{name}" for name in modules)]
        (prefix/"MANIFEST.sha256").write_text("\n".join(f"{hashlib.sha256((prefix/name).read_bytes()).hexdigest()}  {name}" for name in installed)+"\n",encoding="ascii")
    print("zsh:",_edit(home/".zshrc",prefix/"msaa-clickfix.zsh",a.dry_run));print("bashrc:",_edit(home/".bashrc",prefix/"msaa-clickfix.bash",a.dry_run));print("bash_profile:",_edit(home/".bash_profile",prefix/"msaa-clickfix.bash",a.dry_run))
    if a.mode: print("requested_policy:",_set_user_mode(home,a.mode,a.dry_run))
    else: print("policy: unchanged (new unmanaged installations default to AUDIT and do not interrupt commands; rerun with --mode warn or --mode block to enforce)")
    print("Rollback: scripts/uninstall-clickfix-shell-guard.sh; logs are preserved by default.")
if __name__=="__main__":main()
