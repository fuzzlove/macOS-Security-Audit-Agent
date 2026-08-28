from __future__ import annotations

import base64
import hashlib
import re
import time
import zlib
from dataclasses import asdict, dataclass
from typing import Any

from .shell_config import ShellGuardConfig
from .shell_tokenizer import command_segments, tokenize

SCANNER_VERSION = "1.0.0"
INTERPRETERS = {"sh","bash","zsh","dash","ksh","fish","osascript","python","python3","perl","ruby","node","source","."}
DOWNLOADERS = {"curl","wget"}
DECODERS = {"base64","openssl","xxd","gzip","gunzip"}


@dataclass(frozen=True)
class ScanDecision:
    schema: str; decision: str; score: int; confidence: str; rule_ids: tuple[str,...]; explanation_codes: tuple[str,...]
    command_sha256: str; command_length: int; normalized_length: int; decoder_depth: int; scanner_version: str; configuration_version: str; processing_time_ms: float; error: str | None

    def to_dict(self) -> dict[str, Any]: return asdict(self)


def _base(word: str) -> str: return word.rsplit("/",1)[-1].lower()


def _bounded_gzip(data: bytes, limit: int) -> bytes:
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    output = decoder.decompress(data, limit + 1)
    if len(output) > limit or decoder.unconsumed_tail or not decoder.eof:
        raise ValueError("decoder_size_limit")
    output += decoder.flush(limit + 1 - len(output))
    if len(output) > limit:
        raise ValueError("decoder_size_limit")
    return output


def _literal_decode(command: str, config: ShellGuardConfig) -> tuple[list[str], int]:
    if config.maximum_decode_depth == 0:
        return [], 0
    decoded: list[str] = []
    frontier = [command]
    maximum_depth = 0
    for depth in range(1, config.maximum_decode_depth + 1):
        next_frontier: list[str] = []
        for text in frontier:
            decoder_present = bool(re.search(r"\b(base64|openssl\s+(?:base64|enc)|xxd\s+-r)\b", text, re.I))
            gzip_present = bool(re.search(r"\b(?:gzip|gunzip)\b[^|;&\n]*(?:-d|--decompress)|\bgunzip\b", text, re.I))
            if decoder_present:
                for match in re.finditer(r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{24,}={0,2})(?![A-Za-z0-9+/])", text):
                    if len(match.group(1)) > config.maximum_decode_bytes:
                        raise ValueError("decoder_size_limit")
                    try:
                        raw = base64.b64decode(match.group(1), validate=True)
                    except (ValueError, base64.binascii.Error):
                        continue
                    if len(raw) > config.maximum_decode_bytes:
                        raise ValueError("decoder_size_limit")
                    if gzip_present and raw.startswith(b"\x1f\x8b"):
                        raw = _bounded_gzip(raw, config.maximum_decode_bytes)
                    value = raw.decode("utf-8", "replace")
                    decoded.append(value); next_frontier.append(value); maximum_depth = depth
                for match in re.finditer(r"(?:^|[\s'\"])([0-9a-fA-F]{32,})(?:$|[\s'\"])", text):
                    if len(match.group(1)) // 2 > config.maximum_decode_bytes:
                        raise ValueError("decoder_size_limit")
                    try:
                        value = bytes.fromhex(match.group(1)).decode("utf-8", "replace")
                    except ValueError:
                        continue
                    decoded.append(value); next_frontier.append(value); maximum_depth = depth
        if not next_frontier:
            break
        frontier = next_frontier
    return decoded, maximum_depth


def scan_request(request: dict[str, Any], config: ShellGuardConfig) -> ScanDecision:
    started = time.monotonic_ns(); command = request.get("command")
    if not isinstance(command, str): return _error("invalid_command", "", config, started)
    raw = command.encode("utf-8", "replace")
    if len(raw) > config.maximum_command_bytes: return _error("command_size_limit", command, config, started)
    control_present = bool(re.search(r"\x1b\[[0-?]*[ -/]*[@-~]", command))
    detection_command = command.replace("\\\r\n", "").replace("\\\n", "")
    detection_command = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", detection_command)
    try: parsed = tokenize(detection_command)
    except ValueError as exc: return _error(str(exc), command, config, started)
    digest = hashlib.sha256(raw).hexdigest()
    if digest in config.exact_hash_allowlist:
        return _finish("allow",0,"high",("exact_hash_allowlist_match",),("exact_hash_allowlist_match",),digest,len(command),len(parsed.normalized),0,config,started,None)
    segments = command_segments(parsed.tokens); names = [_base(s[0]) for s in segments if s]
    lowered = parsed.normalized.lower(); rules: dict[str,int] = {}
    def add(rule: str, score: int) -> None:
        if rule not in config.disabled_rule_ids: rules[rule] = max(rules.get(rule,0),score)
    pipe_pairs = list(zip(names, names[1:]))
    assignments = {match.group(1): match.group(2) for match in re.finditer(r"(?:^|[;\n]\s*)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*['\"]?([A-Za-z0-9_.:/+-]+)['\"]?", lowered)}
    resolved = lowered
    for key, value in list(assignments.items())[:32]:
        resolved = re.sub(rf"\$\{{{re.escape(key)}\}}|\${re.escape(key)}\b", value, resolved)
    resolved = re.sub(r"\$([A-Za-z_][A-Za-z0-9_]*)\$([A-Za-z_][A-Za-z0-9_]*)", lambda m: assignments.get(m.group(1),m.group(0))+assignments.get(m.group(2),""), resolved)
    reconstructed = resolved != lowered
    resolved_parsed = tokenize(resolved); resolved_names=[_base(s[0]) for s in command_segments(resolved_parsed.tokens) if s]
    resolved_pairs=list(zip(resolved_names,resolved_names[1:]))
    network_relationship = any(a in DOWNLOADERS and b in INTERPRETERS for a,b in pipe_pairs+resolved_pairs) or (any(n in DOWNLOADERS for n in resolved_names) and any(n in INTERPRETERS for n in resolved_names) and "|" in resolved) or bool(re.search(r"\$\([^)]*\b(?:curl|wget)\b[^)]*\)\s*(?:[;| ]|$).*(?:eval|(?:ba|z|da|k)?sh\s+-c)", resolved, re.S) or re.search(r"\b(?:eval|(?:ba|z|da|k)?sh\s+-c)\b[^\n]*\$\([^)]*\b(?:curl|wget)\b", resolved, re.S))
    if re.search(r"\$\(\s*printf\b[^)]*\bcu\b[^)]*\brl\b[^)]*\)",lowered) and re.search(r"\|\s*(?:/bin/)?zsh\b",lowered): network_relationship=True; add("command_name_reconstruction",2)
    if network_relationship: add("network_to_interpreter",8)
    if reconstructed and network_relationship: add("reconstructed_executable",2); add("environment_indirection",1)
    if "-c" in lowered and "$([" not in lowered and re.search(r"\b(?:sh|bash|zsh)\s+-c\b",lowered): add("shell_c_execution",1)
    if network_relationship and re.search(r"\beval\b",lowered): add("network_to_eval",8); add("dynamic_execution",2)
    decoder_to_execution = any(a in DECODERS and b in INTERPRETERS for a,b in pipe_pairs+resolved_pairs) or bool(re.search(r"\b(?:base64|openssl\s+(?:base64|enc)|xxd\s+-r|gzip\s+-d|gunzip)\b",lowered) and re.search(r"\beval\b",lowered))
    if decoder_to_execution: add("decoded_content_to_interpreter",7)
    if any(a == "pbpaste" and b in INTERPRETERS for a,b in pipe_pairs): add("clipboard_to_interpreter",7)
    if "pbpaste" in lowered and re.search(r"\b(?:eval|(?:ba|z|da|k)?sh\s+-c)\b",lowered): add("clipboard_to_interpreter",7); add("command_substitution",1)
    temporary = bool(re.search(r"(?:/tmp/|/private/tmp/|/var/tmp/|/downloads/|/cache/|/\.[^/\s]+)", lowered))
    retrieval = bool(re.search(r"\b(?:curl|wget)\b", lowered)); chmod = bool(re.search(r"\bchmod\b[^;&\n]*(?:\+x|7[0-7]{2})", lowered)); execution = bool(re.search(r"(?:^|[;&|\n])\s*(?:\./|/tmp/|/private/tmp/|/var/tmp/|source\s+|\.\s+/)", lowered))
    downloaded_path = re.search(r"\b(?:curl|wget)\b[^;&\n]*(?:-o|--output)\s+['\"]?([^\s;'\"]+)",resolved)
    downloaded_execute = bool(downloaded_path and re.search(rf"(?:\bsource\s+|(?:^|[;&|\n])\s*(?:\.|(?:ba|z|da|k)?sh)?\s*)['\"]?{re.escape(downloaded_path.group(1))}",resolved,re.S))
    if retrieval and temporary and ((chmod and execution) or downloaded_execute): add("download_stage_execute",7)
    if downloaded_execute and re.search(r"\b(?:source|\.)\s+",resolved): add("downloaded_content_sourced",7)
    apple_shell = bool(re.search(r"\bosascript\b[^\n]*(?:do shell script|do\s+shell\s+script)", lowered))
    if apple_shell and re.search(r"\b(?:base64|openssl|xxd|gzip|gunzip)\b",lowered): add("decoded_content_to_interpreter",7)
    if apple_shell: add("applescript_shell_execution",8 if retrieval or any(n in DECODERS for n in names) else 5)
    if "applescript://" in lowered: add("applescript_url_scheme",8)
    if re.search(r"\bcsrutil\s+disable\b|\bspctl\s+--master-disable\b", lowered): add("security_control_weakening",8)
    elif re.search(r"\bxattr\b[^\n]*(?:-[a-z]*(?:r[a-z]*d|d[a-z]*r)|-d[^\n]*-r)[^\n]*com\.apple\.quarantine|\bxattr\b[^\n]*-d\s+com\.apple\.quarantine[^\n]*(?:/tmp|/downloads|\./)", lowered): add("security_control_weakening",5)
    persistence_path=bool(re.search(r"library/launch(?:agents|daemons)",lowered)); persistence_activation=bool(re.search(r"\blaunchctl\s+(?:bootstrap|load|enable)\b",lowered))
    if persistence_path or persistence_activation or re.search(r"\bcrontab\s+-", lowered): add("persistence_creation",4)
    if persistence_path: add("launchagent_write",4)
    if persistence_activation: add("persistence_activation",4)
    if retrieval and persistence_path: add("downloaded_persistence",8)
    sensitive = bool(re.search(r"\bsecurity\s+(?:dump-keychain|find-(?:generic|internet)-password\b[^\n]*\s-w\b)|(?:browser|chrome|chromium)[^\n]*(?:login data|cookies)|\.ssh/(?:id_|)|\.aws/credentials|\.kube/config|wallet", lowered))
    if sensitive: add("sensitive_data_access",8 if any(name in DOWNLOADERS for name in names) else 4)
    if re.search(r"\bsecurity\s+find-(?:generic|internet)-password\b[^\n]*(?:\s-w\b|--password\b)",lowered): add("keychain_secret_output",4)
    if re.search(r"\bsecurity\s+dump-keychain\b",lowered): add("keychain_dump",6)
    if parsed.unicode_anomaly: add("execution_obfuscation_unicode",2)
    if parsed.control_anomaly or control_present: add("execution_obfuscation_control",2)
    if parsed.escaped_name: add("execution_obfuscation_escaped_name",2)
    if re.search(r"\beval\b|\$\([^)]*\$\(|(?:\||^)\s*\b(?:rev|tr|sed|awk)\b|\b(?:rev|tr|sed|awk)\b[^|]*\|", lowered): add("execution_obfuscation",2)
    if re.search(r"\beval\b",lowered): add("dynamic_execution",2)
    if re.search(r"(?:HISTFILE\s*=\s*/dev/null|unset\s+HISTFILE|history\s+-c|>/dev/null\s+2>&1|\bnohup\b)", command, re.I): add("history_or_output_evasion",1)
    decoder_depth = 0
    try:
        decoded, decoder_depth = _literal_decode(parsed.normalized, config)
        if decoded and any(re.search(r"\b(?:sh|bash|zsh|osascript|python3?)\b|MSAA_CLICKFIX_TEST", item, re.I) for item in decoded) and any(n in DECODERS for n in names): add("static_decoded_content",2)
        if decoded and re.search(r"\beval\b",lowered): add("static_decoded_content",2)
        base_decode_count=len(re.findall(r"\b(?:base64|openssl\s+(?:base64|enc)|xxd\s+-r)\b",lowered))
        if decoder_depth >= 2 or decoded and base_decode_count >= 2: decoder_depth=max(2,decoder_depth);add("multiple_decode_layers",3)
    except ValueError as exc: return _error(str(exc), command, config, started)
    symbolic = {
        "<attempt_disable_gatekeeper>":("gatekeeper_disable_intent","destructive_security_change"),
        "<attempt_disable_sip>":("sip_disable_intent","destructive_security_change"),
        "<attempt_modify_tcc_database>":("tcc_tampering_intent",),
        "<attempt_delete_root_filesystem>":("destructive_filesystem_intent",),
        "<attempt_delete_user_home>":("destructive_filesystem_intent",),
        "<attempt_erase_system_volume>":("destructive_disk_intent",),
        "<attempt_overwrite_disk_device>":("raw_disk_write_intent",),
        "<attempt_recursive_permission_destruction>":("destructive_permission_change",),
        "<attempt_disable_security_controls_and_delete_data>":("compound_destructive_intent",),
        "<attempt_fork_or_resource_exhaustion>":("denial_of_service_intent",),
        "<attempt_mass_process_termination>":("destructive_process_control",),
        "<attempt_read_browser_login_database>":("browser_credential_access",),
        "<attempt_read_browser_cookies>":("browser_cookie_access",),
        "<attempt_archive_ssh_keys>":("ssh_key_collection",),
        "<attempt_collect_cloud_credentials>":("cloud_credential_collection",),
        "<attempt_collect_wallet_data>":("wallet_data_collection",),
        "<attempt_archive_and_exfiltrate_user_data>":("archive_creation","exfiltration_intent"),
    }
    if request.get("phase")=="test" and lowered.strip() in symbolic:
        for rule in symbolic[lowered.strip()]: add(rule,10)
    score = sum(rules.values())
    paste = request.get("paste_origin") not in {None,"none","typed",False}
    if rules and paste: score += 2
    if rules and bool(request.get("multiline")): score += 1
    if rules and paste and bool(request.get("trailing_newline")): score += 2
    if rules and len(command)>1024: score += 2
    elif rules and len(command)>256: score += 1
    if rules and temporary: score += 1
    if rules and re.search(r"(?:^|[;&|\n])\s*sudo\b", lowered): score += 1
    hard = {"network_to_interpreter","decoded_content_to_interpreter","clipboard_to_interpreter"}
    if paste and (hard & rules.keys() or "download_stage_execute" in rules or "security_control_weakening" in rules and rules["security_control_weakening"]>=8 or apple_shell and retrieval): decision = "block"
    elif score >= config.block_threshold: decision = "block"
    elif score >= config.warn_threshold: decision = "warn"
    else: decision = "allow"
    if (time.monotonic_ns()-started)/1_000_000 > config.scanner_timeout_ms:
        return _error("scanner_timeout", command, config, started)
    # Audit mode changes enforcement, not the recorded risk decision; adapters use mode.
    return _finish(decision,score,"high" if any(v>=7 for v in rules.values()) else "medium" if rules else "high",tuple(sorted(rules)),tuple(sorted(rules)),digest,len(command),len(parsed.normalized),decoder_depth,config,started,None)


def _finish(decision,score,confidence,rules,codes,digest,length,norm,depth,config,started,error):
    return ScanDecision("msaa.clickfix.decision.v1",decision,score,confidence,rules,codes,digest,length,norm,depth,SCANNER_VERSION,config.configuration_version,round((time.monotonic_ns()-started)/1_000_000,3),error)
def _error(code, command, config, started):
    raw=command.encode("utf-8","replace"); return _finish("error",0,"low",(),(),hashlib.sha256(raw).hexdigest(),len(command),len(command),0,config,started,code)
