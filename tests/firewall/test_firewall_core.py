import pytest
from mac_audit_agent.performance.subprocess_runner import BoundedCommandResult
from mac_audit_agent.firewall.errors import FirewallError
from mac_audit_agent.firewall.imports import parse_list
from mac_audit_agent.firewall.models import AddressSelector,FirewallPolicy,FirewallRule
from mac_audit_agent.firewall.renderer import policy_hash,render_policy
from mac_audit_agent.firewall.runtime import FirewallPrivilegeClient
from mac_audit_agent.firewall.validator import normalize_domain,normalize_ips,parse_ports,validate_policy
from mac_audit_agent.firewall.ip_anchor import create_candidate,parse_ip_list,render_ip_anchor,sudo_install_command,validate_candidate
from mac_audit_agent.firewall.application_firewall import inspect_application_firewall,sudo_application_firewall_command
from mac_audit_agent.firewall.policy_inventory import inventory_policies
def command_result(code,out="",err=""): return BoundedCommandResult([],code,out,err,"","")
def test_domain_idna_and_rejection():
    assert normalize_domain("BÜCHER.example.")=="xn--bcher-kva.example"
    with pytest.raises(FirewallError): normalize_domain("bad..example")
def test_ports_are_bounded_and_deterministic():
    assert [p.render() for p in parse_ports("https,22,8000:8100")]==["22","443","8000:8100"]
    for value in ("0","65536","100:10","22; block all"):
        with pytest.raises(FirewallError): parse_ports(value)
def test_ip_families_and_collapse():
    assert normalize_ips(["192.0.2.0/25","192.0.2.128/25"],4)==("192.0.2.0/24",)
    with pytest.raises(FirewallError): normalize_ips(["2001:db8::1"],4)
def test_render_is_stable_and_rejects_injection():
    rule=FirewallRule("r1","Block web",protocols=("tcp",),destination=AddressSelector("network",("192.0.2.0/24",)),destination_ports=parse_ports("443"))
    policy=FirewallPolicy("example", "Example",rules=(rule,)); assert render_policy(policy)==render_policy(policy); assert policy_hash(policy)==policy_hash(policy)
    with pytest.raises(FirewallError): validate_policy(FirewallPolicy("../etc/pf.conf","bad"))

def test_block_rule_never_renders_invalid_pf_state_clause():
    block=FirewallRule("r1","Block TCP",action="block",direction="out",protocols=("tcp",),state_mode="keep")
    rendered=render_policy(FirewallPolicy("protocol-preview","Protocol rule",rules=(block,)))
    rule_line=next(line for line in rendered.splitlines() if line.startswith("block "))
    assert "keep state" not in rule_line

def test_pass_rule_can_render_pf_state_clause():
    allow=FirewallRule("r1","Allow TCP",action="pass",direction="out",protocols=("tcp",),state_mode="keep")
    rendered=render_policy(FirewallPolicy("protocol-preview","Protocol rule",rules=(allow,)))
    rule_line=next(line for line in rendered.splitlines() if line.startswith("pass "))
    assert "keep state" in rule_line
def test_import_never_injects_pf_text():
    summary=parse_list("example.com\n0.0.0.0 ads.example\n# note\nblock out all",kind="domain"); assert "example.com" in summary.accepted and "ads.example" in summary.accepted and "all" in summary.invalid
def test_privilege_client_fails_closed_without_sudo_fallback():
    client=FirewallPrivilegeClient();
    with pytest.raises(PermissionError,match="FW014"): client.request("reload_anchor",{"anchor":"com.liquidsky.msaa.firewall"})
    with pytest.raises(PermissionError,match="FW015"): client.request("run_shell",{})

def test_mixed_ip_import_separates_families_collapses_and_rejects_text():
    imported=parse_ip_list("192.0.2.0/25\n192.0.2.128/25\n2001:db8::1\n192.0.2.1\nblock out all\n# note")
    assert imported.ipv4 == ("192.0.2.0/24",)
    assert imported.ipv6 == ("2001:db8::1/128",)
    assert imported.invalid == ("block",)

def test_ip_anchor_has_family_specific_tables_and_rules():
    imported=parse_ip_list("192.0.2.10\n2001:db8::/48")
    rendered=render_ip_anchor("threats",imported)
    assert "table <msaa_threats_ipv4>" in rendered and "quick inet to <msaa_threats_ipv4>" in rendered
    assert "table <msaa_threats_ipv6>" in rendered and "quick inet6 to <msaa_threats_ipv6>" in rendered
    assert rendered == render_ip_anchor("threats",imported)

def test_long_policy_id_generates_pf_compatible_stable_table_names():
    imported=parse_ip_list("192.0.2.10\n2001:db8::/48")
    rendered=render_ip_anchor("network-monitor-identitys",imported)
    table_names=[]
    for line in rendered.splitlines():
        if line.startswith("table <"):
            table_names.append(line.split("<",1)[1].split(">",1)[0])
    assert len(table_names) == 2
    assert all(len(name.encode("ascii")) <= 31 for name in table_names)
    assert rendered == render_ip_anchor("network-monitor-identitys",imported)

def test_candidate_is_exclusive_regular_and_private(tmp_path):
    candidate=create_candidate("test",parse_ip_list("192.0.2.1"),root=tmp_path)
    assert candidate.path.is_file() and not candidate.path.is_symlink()
    assert candidate.path.stat().st_mode & 0o777 == 0o600
    assert candidate.anchor_name == "com.liquidsky.msaa.firewall.test"

def test_candidate_validation_uses_fixed_pfctl_arguments(tmp_path,monkeypatch):
    candidate=create_candidate("test",parse_ip_list("192.0.2.1"),root=tmp_path)
    calls=[]
    monkeypatch.setattr("mac_audit_agent.firewall.ip_anchor.run_bounded_command",lambda args,**kwargs: calls.append(args) or command_result(0,"","No ALTQ support in kernel"))
    validated=validate_candidate(candidate)
    assert calls == [["/sbin/pfctl","-n","-a","com.liquidsky.msaa.firewall.test","-f",str(candidate.path)]]
    assert validated.validation.returncode == 0

def test_sudo_install_command_is_hash_bound_and_shell_quoted(tmp_path):
    candidate=create_candidate("test",parse_ip_list("192.0.2.1"),root=tmp_path)
    command=sudo_install_command(candidate)
    assert command.startswith("sudo ")
    assert "mac_audit_agent.firewall.sudo_pf" in command
    assert candidate.content_hash in command
    assert candidate.anchor_name in command

def test_application_firewall_inspection_and_fixed_sudo_commands(monkeypatch):
    outputs={"--getglobalstate":"Firewall is enabled. (State = 1)","--getstealthmode":"Stealth mode enabled","--getblockall":"Block all DISABLED!","--getallowsigned":"Automatically allow built-in signed software ENABLED.","--getallowsignedapp":"Automatically allow downloaded signed software ENABLED.","--listapps":"ALF: total number of apps = 0"}
    monkeypatch.setattr("mac_audit_agent.firewall.application_firewall.SOCKETFILTERFW",type("FakePath",(),{"is_file":lambda self:True,"__str__":lambda self:"/usr/libexec/ApplicationFirewall/socketfilterfw"})())
    monkeypatch.setattr("mac_audit_agent.firewall.application_firewall.run_bounded_command",lambda args,**kwargs: command_result(0,outputs[args[1]],""))
    status=inspect_application_firewall()
    assert status.enabled is True
    assert "total number of apps" in status.applications
    assert sudo_application_firewall_command(True).endswith("--setglobalstate on")
    assert sudo_application_firewall_command(False).endswith("--setglobalstate off")

def test_policy_inventory_lists_latest_candidate_and_rule_counts(tmp_path):
    generated=tmp_path/"generated"; generated.mkdir(); anchors=tmp_path/"anchors"; anchors.mkdir()
    older=generated/"com.liquidsky.msaa.firewall.protocol-preview.11111111111111111111111111111111.conf"
    newer=generated/"com.liquidsky.msaa.firewall.protocol-preview.22222222222222222222222222222222.conf"
    older.write_text("# MSAA policy protocol-preview version=1\nblock out quick proto tcp from any to any\n")
    newer.write_text("# MSAA policy protocol-preview version=2\npass out quick proto tcp from any to any keep state\nblock in quick proto udp from any to any\n")
    older.touch(); newer.touch()
    policies=inventory_policies(generated_root=generated,anchor_root=anchors)
    assert len(policies)==1
    assert policies[0].policy_id=="protocol-preview" and policies[0].state=="Candidate"
    assert (policies[0].version,policies[0].rules,policies[0].allow_rules,policies[0].block_rules)==(2,2,1,1)

def test_policy_inventory_merges_installed_anchor_and_reports_drift(tmp_path):
    generated=tmp_path/"generated"; generated.mkdir(); anchors=tmp_path/"anchors"; anchors.mkdir()
    candidate=generated/"com.liquidsky.msaa.firewall.threats.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.conf"
    candidate.write_text("# MSAA managed IP-list policy threats\nblock out quick inet to 192.0.2.1\n")
    installed=anchors/"com.liquidsky.msaa.firewall.threats"
    installed.write_text("# MSAA managed IP-list policy threats\nblock out quick inet to 198.51.100.1\n")
    policies=inventory_policies(generated_root=generated,anchor_root=anchors)
    assert len(policies)==1 and policies[0].state=="Installed"
    assert policies[0].drift=="Candidate differs"
    assert policies[0].installed_path==str(installed)
