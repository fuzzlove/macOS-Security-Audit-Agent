from __future__ import annotations
import hashlib, json, re
from .models import AddressSelector, FirewallPolicy
from .validator import validate_policy
def _selector(value: AddressSelector):
    if value.kind=="any": return "any"
    if value.kind=="localhost": return "127.0.0.1"
    if value.kind=="table": return "{ " + ", ".join(f"<{v}>" for v in sorted(value.values)) + " }"
    return "{ " + ", ".join(sorted(value.values)) + " }" if len(value.values)>1 else value.values[0]
def render_policy(policy: FirewallPolicy) -> str:
    validate_policy(policy); lines=[f"# MSAA policy {policy.policy_id} schema={policy.schema_version} version={policy.version}"]
    for rule in sorted((r for r in policy.rules if r.enabled),key=lambda r:(r.priority,r.rule_id)):
        parts=[rule.action]
        if rule.direction!="both": parts.append(rule.direction)
        if rule.log: parts.append("log")
        if rule.quick: parts.append("quick")
        if rule.interfaces: parts.extend(("on","{ " + ", ".join(sorted(rule.interfaces)) + " }"))
        if rule.address_family!="any": parts.append(rule.address_family)
        if rule.protocols: parts.extend(("proto","{ " + ", ".join(sorted(rule.protocols)) + " }"))
        parts.extend(("from",_selector(rule.source)))
        if rule.source_ports: parts.extend(("port","{ " + ", ".join(p.render() for p in rule.source_ports) + " }"))
        parts.extend(("to",_selector(rule.destination)))
        if rule.destination_ports: parts.extend(("port","{ " + ", ".join(p.render() for p in rule.destination_ports) + " }"))
        # PF state tracking applies to traffic that is passed.  pfctl rejects
        # `keep state` (and its variants) on block rules.
        if rule.action=="pass" and rule.state_mode!="none": parts.extend((rule.state_mode,"state"))
        label=rule.label or f"MSAA:{policy.policy_id}:{rule.rule_id}"
        if not re.fullmatch(r"[A-Za-z0-9_.: -]{1,128}",label): raise ValueError("FW006: unsafe PF label")
        parts.extend(("label",json.dumps(label))); lines.append(" ".join(parts))
    content="\n".join(lines)+"\n"; digest=hashlib.sha256(content.encode()).hexdigest(); return f"# content-sha256 {digest}\n"+content
def policy_hash(policy): return hashlib.sha256(render_policy(policy).encode()).hexdigest()
