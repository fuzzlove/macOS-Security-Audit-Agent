import json
import urllib.request

import pytest

from mac_audit_agent.network_rdap import lookup_ip_rdap


class Response:
    def __enter__(self): return self
    def __exit__(self,*_args): return False
    def geturl(self): return "https://rdap.db.ripe.net/ip/193.0.0.1"
    def read(self,_limit): return json.dumps({"rdapConformance":["rdap_level_0"],"name":"RIPE-NCC","handle":"NET-193","startAddress":"193.0.0.0","endAddress":"193.0.7.255","country":"NL","status":["active"]}).encode()


class Opener:
    def open(self,_request,timeout): assert timeout==8; return Response()


def test_rdap_result_preserves_provider_and_qualification(monkeypatch):
    monkeypatch.setattr(urllib.request,"build_opener",lambda *_args:Opener())
    result=lookup_ip_rdap("193.0.0.1","ARIN bootstrap")
    assert result.requested_provider=="ARIN bootstrap" and result.authoritative_host=="rdap.db.ripe.net"
    assert "not" in result.qualification.lower()


def test_private_and_invalid_addresses_are_not_sent():
    with pytest.raises(ValueError): lookup_ip_rdap("127.0.0.1","RIPE")
    with pytest.raises(ValueError): lookup_ip_rdap("not-an-ip","RIPE")
