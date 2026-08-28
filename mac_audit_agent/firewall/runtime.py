from __future__ import annotations
import hashlib, json, os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from mac_audit_agent.performance.subprocess_runner import run_bounded_command
from mac_audit_agent.mission_governance import AuthorizationContext, AuthorizationPolicy, GovernanceAuditLog, HumanApproval, PolicyRequest

PFCTL=Path("/sbin/pfctl"); NAMESPACE="com.liquidsky.msaa"
@dataclass(frozen=True)
class FirewallRuntimeStatus:
    available: bool; enabled: bool|None; anchor_loaded: bool|None; active_rules: int; checked_at: str; exit_code: int; stdout: str; stderr: str; informational: tuple[str,...]=(); error_code: str=""
    def to_dict(self): return asdict(self)
def inspect_status(anchor="com.liquidsky.msaa.firewall"):
    if not PFCTL.is_file(): return FirewallRuntimeStatus(False,None,None,0,datetime.now(timezone.utc).isoformat(),127,"","pfctl unavailable",error_code="FW001")
    info=run_bounded_command([str(PFCTL),"-s","info"],timeout_seconds=8,max_output_bytes=131072,env={"LC_ALL":"C"})
    rules=run_bounded_command([str(PFCTL),"-a",anchor,"-sr"],timeout_seconds=8,max_output_bytes=524288,env={"LC_ALL":"C"})
    combined="\n".join((info.stdout,info.stderr)); enabled=True if "Status: Enabled" in combined else (False if "Status: Disabled" in combined else None)
    informational=tuple(line for line in (info.stderr+"\n"+rules.stderr).splitlines() if "ALTQ" in line)
    filtered="\n".join(line for line in rules.stderr.splitlines() if "ALTQ" not in line)
    active=[line for line in rules.stdout.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    return FirewallRuntimeStatus(True,enabled,bool(active),len(active),datetime.now(timezone.utc).isoformat(),info.returncode,info.stdout,filtered,informational,"" if info.returncode==0 else "FW002")
def normalized_runtime_hash(text): return hashlib.sha256("\n".join(line.strip() for line in text.splitlines() if line.strip() and "ALTQ" not in line).encode()).hexdigest()

class FirewallPrivilegeClient:
    """Optional authenticated-helper transport; the UI also offers fixed sudo tools."""
    ALLOWED=frozenset({"get_status","list_msaa_anchors","inspect_anchor","validate_candidate","install_anchor","reload_anchor","flush_anchor","enable_pf","disable_msaa_policy","uninstall_msaa_anchor","restore_pf_conf_backup","collect_diagnostics"})
    MUTATING=frozenset({"install_anchor","reload_anchor","flush_anchor","enable_pf","disable_msaa_policy","uninstall_msaa_anchor","restore_pf_conf_backup"})
    def __init__(self, transport=None, *, authorization_context: AuthorizationContext|None=None, human_approval: HumanApproval|None=None, audit_log: GovernanceAuditLog|None=None): self.transport=transport;self.authorization_context=authorization_context;self.human_approval=human_approval;self.audit_log=audit_log
    def available(self): return self.transport is not None and bool(getattr(self.transport,"authenticated",False))
    def request(self, operation, payload=None):
        if operation not in self.ALLOWED: raise PermissionError("FW015: operation is not allowlisted")
        if not self.available(): raise PermissionError("FW014: no authenticated PF helper is installed. Generate a reviewed anchor or use the fixed sudo pfctl action; networking was not changed")
        if operation in self.MUTATING:
            payload=payload or {};target=str(payload.get("authorized_target", ""))
            request=PolicyRequest("AUTHORIZED_OPERATIONAL","security_control_modification",target=target,operational_effect="configuration_change",actor_reference=str(payload.get("actor_reference","local-user")),session_id=str(payload.get("session_id","")),framework_versions=dict(payload.get("framework_versions",{})),rollback_available=bool(payload.get("rollback_available",False)),recovery_available=bool(payload.get("recovery_available",False)),audit_available=self.audit_log is not None)
            decision=AuthorizationPolicy().evaluate(request,self.authorization_context,self.human_approval)
            if self.audit_log:self.audit_log.append(request,decision,authorization_id=self.authorization_context.authorization_id if self.authorization_context else "",framework_versions=request.framework_versions)
            if not decision.allowed:raise PermissionError(f"GOV001: operational firewall change denied ({decision.reason_code}); advisory review remains available")
        return self.transport.request(operation,payload or {})
