from __future__ import annotations

import re
from typing import Any

ATTACK_TECHNIQUES = (
    {"id":"T1056.001","name":"Input Capture: Keylogging","relationship":"direct","platforms":["macOS"],"detection":"DET0089 / AN0245: unexpected Quartz Event Services or IOHID use and unauthorized TCC access"},
    {"id":"T1056.002","name":"Input Capture: GUI Input Capture","relationship":"adjacent","platforms":["macOS"],"detection":"Correlate suspicious credential prompts with application/window activity; an event tap alone does not establish this technique."},
    {"id":"T1010","name":"Application Window Discovery","relationship":"correlation","platforms":["macOS"],"detection":"Keyloggers may associate captured input with foreground-window titles."},
    {"id":"T1115","name":"Clipboard Data","relationship":"correlation","platforms":["macOS"],"detection":"Clipboard collection alongside a keyboard tap increases input-capture concern."},
    {"id":"T1547","name":"Boot or Logon Autostart Execution","relationship":"correlation","platforms":["macOS"],"detection":"Unexpected LaunchAgents/LaunchDaemons can make input capture persistent."},
    {"id":"T1041","name":"Exfiltration Over C2 Channel","relationship":"correlation","platforms":["macOS"],"detection":"Correlate staged keylog data with unusual outbound activity; no network content is collected here."},
)

DOCUMENTED_THREAT_CONTEXT = (
    {"id":"S1016","name":"MacMa","kind":"documented malware","platforms":["macOS"],"techniques":["T1056.001"],"match_tokens":["macma"],"note":"ATT&CK documents Core Graphics Event Taps used to intercept keystrokes."},
    {"id":"S0161","name":"XAgentOSX","kind":"documented APT-associated malware","platforms":["macOS"],"techniques":["T1056.001","T1010","T1041"],"match_tokens":["xagentosx","xagent"],"note":"ATT&CK documents active-window monitoring, buffered keystrokes, and C2 transmission."},
    {"id":"S0282","name":"MacSpy","kind":"documented malware","platforms":["macOS"],"techniques":["T1056.001"],"match_tokens":["macspy"],"note":"ATT&CK documents keystroke capture."},
    {"id":"S0279","name":"Proton","kind":"documented malware","platforms":["macOS"],"techniques":["T1056.001"],"match_tokens":["proton"],"note":"ATT&CK documents keylogging capability; name matches require strong corroboration."},
    {"id":"G0007","name":"APT28","kind":"documented threat group","platforms":["multi-platform"],"techniques":["T1056.001"],"match_tokens":[],"note":"ATT&CK documents the group using keylogging tools, including macOS-capable associated tooling."},
    {"id":"G0094","name":"Kimsuky","kind":"documented threat group","platforms":["Windows"],"techniques":["T1056.001"],"match_tokens":[],"note":"ATT&CK documents polling-based keylogging and temporary log storage; contextual only on macOS."},
    {"id":"S0625","name":"Cuba","kind":"documented ransomware family","platforms":["Windows"],"techniques":["T1056.001","T1486"],"match_tokens":[],"note":"ATT&CK documents keylogging in this ransomware family; contextual only and not a macOS attribution."},
    {"id":"S0567","name":"Dtrack","kind":"documented Lazarus-associated spyware","platforms":["Windows"],"techniques":["T1056.001","T1074.001"],"match_tokens":[],"note":"ATT&CK documents a keylogging executable and local data staging; contextual only on macOS."},
)

BEHAVIOR_TOKENS = re.compile(r"(?i)(?:^|[/_. -])(keylog(?:ger)?|klog|cg(?:event)?tap|iohid|keyboard(?:tap|hook)|keystroke)(?:$|[/_. -])")

def match_documented_behavior(path: str, arguments: str) -> tuple[list[str],list[dict[str,Any]]]:
    haystack=f"{path} {arguments}".lower(); signals=[]; matches=[]
    if BEHAVIOR_TOKENS.search(haystack): signals.append("name or argument resembles documented keylogging/event-tap behavior")
    for profile in DOCUMENTED_THREAT_CONTEXT:
        tokens=profile.get("match_tokens",())
        if tokens and any(re.search(rf"(?<![a-z0-9]){re.escape(str(token))}(?![a-z0-9])",haystack) for token in tokens):
            matches.append({**profile,"assessment":"name match only; requires signature, hash, persistence, and behavior corroboration"})
    return signals,matches

def knowledge_summary() -> dict[str,Any]:
    return {"attack_techniques":[dict(item) for item in ATTACK_TECHNIQUES],"documented_examples":[{key:value for key,value in item.items() if key!="match_tokens"} for item in DOCUMENTED_THREAT_CONTEXT],"attribution_warning":"Technique similarity or a name match is not actor, malware-family, or ransomware attribution."}
