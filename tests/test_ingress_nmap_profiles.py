from __future__ import annotations
from pathlib import Path
import pytest
from mac_audit_agent.network_segmentation.backends.nmap import NmapBackend
from mac_audit_agent.network_segmentation.nmap_profiles import PROFILES,profile_by_id

def backend(monkeypatch):
    item=NmapBackend();monkeypatch.setattr(item,"discover",lambda:Path("/usr/local/bin/nmap"));return item
def test_professional_fixed_profiles_cover_required_protocol_families():
    ids={item.profile_id for item in PROFILES}
    assert {"safe_tcp_common","tcp_top_100","tcp_top_1000","full_tcp","safe_udp_common","udp_top_50","dns_path","icmp","icmpv6","extended_protocols"}<=ids
def test_scoped_profile_arguments_are_lists_and_reject_out_of_scope(monkeypatch):
    item=backend(monkeypatch);args=item.build_profile_arguments("10.20.30.10/32","10.20.30.0/24",profile_by_id("safe_tcp_common"))
    assert args[0]=="/usr/local/bin/nmap" and "-sT" in args and args[-1]=="10.20.30.10/32"
    with pytest.raises(PermissionError,match="OUT_OF_SCOPE"):item.build_profile_arguments("10.20.31.10/32","10.20.30.0/24",profile_by_id("safe_tcp_common"))
def test_full_range_requires_separate_approval(monkeypatch):
    item=backend(monkeypatch)
    with pytest.raises(PermissionError,match="high-traffic"):item.build_profile_arguments("10.0.0.1/32","10.0.0.0/24",profile_by_id("full_tcp"))
    args=item.build_profile_arguments("10.0.0.1/32","10.0.0.0/24",profile_by_id("full_tcp"),explicit_high_traffic=True)
    assert "65535" in args[args.index("-p")+1]
def test_nmap_xml_closed_is_reachable_not_segmentation():
    xml=b'<nmaprun><host><address addr="10.0.0.1"/><ports><port protocol="tcp" portid="443"><state state="closed" reason="reset"/></port><port protocol="tcp" portid="445"><state state="filtered" reason="no-response"/></port></ports></host></nmaprun>'
    rows=NmapBackend.summarize_xml(xml)
    assert rows[0]["segmentation_result"]=="INFERRED_ALLOWED"
    assert rows[1]["segmentation_result"]=="INDETERMINATE"
