from __future__ import annotations

import json
from pathlib import Path

import pytest

from mac_audit_agent.network_segmentation import EgressEvidenceStore,EgressProbe,EgressTestEngine,provider_by_id
from mac_audit_agent.network_segmentation.reporting import export_report


class FakeTransport:
    def __init__(self):self.calls=[]
    def connect(self,hostname,port,timeout_seconds):
        self.calls.append((hostname,port,timeout_seconds))
        if port==443:return "reachable",("192.0.2.1",),1.25,""
        return "blocked_or_filtered",("192.0.2.1",),float(timeout_seconds*1000),"connect_timeout"


def _run():
    transport=FakeTransport();run=EgressTestEngine(transport).run(provider=provider_by_id("portquiz"),probes=[EgressProbe(443),EgressProbe(444)],authorization_reference="SOW-TEST-1",target_scope="synthetic test host",authorized=True,timeout_seconds=.2,workers=2);return run,transport


def test_egress_requires_explicit_authorization():
    with pytest.raises(PermissionError):EgressTestEngine(FakeTransport()).run(provider=provider_by_id("portquiz"),probes=[EgressProbe(443)],authorization_reference="SOW",target_scope="test",authorized=False)


def test_mocked_egress_preserves_distinct_outcomes_without_network():
    run,transport=_run()
    assert [item.status for item in run.results]==["reachable","blocked_or_filtered"]
    assert len(transport.calls)==2
    assert run.configuration["payload_bytes_sent"]==0
    assert all(len(item.evidence_sha256)==64 for item in run.results)
    assert any("does not prove" in item for item in run.limitations)


def test_evidence_store_round_trip(tmp_path:Path):
    run,_=_run();store=EgressEvidenceStore(tmp_path/"egress.sqlite3")
    try:digest=store.save(run);saved=store.load(run.run_id)
    finally:store.close()
    assert len(digest)==64
    assert saved["authorization_reference"]=="SOW-TEST-1"
    assert (tmp_path/"egress.sqlite3").stat().st_mode&0o777==0o600


@pytest.mark.parametrize("suffix",[".json",".csv",".txt",".html"])
def test_dependency_free_report_formats(tmp_path:Path,suffix:str):
    run,_=_run();path=export_report(run,tmp_path/("report"+suffix));content=path.read_text(encoding="utf-8")
    assert "SOW-TEST-1" in content
    assert "reachable" in content


def test_json_report_is_structured(tmp_path:Path):
    run,_=_run();payload=json.loads(export_report(run,tmp_path/"report.json").read_text())
    assert payload["schema_version"]=="msaa.network-segmentation.v1"
    assert payload["provider"]["provider_id"]=="portquiz"


def test_provider_registry_rejects_arbitrary_destinations():
    with pytest.raises(ValueError,match="approved provider"):provider_by_id("attacker-controlled")


def test_probe_limits_and_protocol_validation():
    with pytest.raises(ValueError):EgressProbe(0).validate()
    with pytest.raises(ValueError):EgressProbe(53,"udp").validate()


def test_more_than_1024_ports_requires_explicit_full_range_authorization():
    probes=[EgressProbe(port) for port in range(1,1026)]
    with pytest.raises(PermissionError,match="full-range authorization"):
        EgressTestEngine(FakeTransport()).run(provider=provider_by_id("portquiz"),probes=probes,authorization_reference="SOW",target_scope="test",authorized=True)


def test_authorized_broad_provider_uses_bounded_submission_batches():
    probes=[EgressProbe(port) for port in range(1,1026)]
    run=EgressTestEngine(FakeTransport()).run(provider=provider_by_id("portquiz"),probes=probes,authorization_reference="SOW-FULL",target_scope="test",authorized=True,full_range_authorized=True,workers=4,timeout_seconds=.1)
    assert len(run.results)==1025
    assert run.configuration["full_range_authorized"] is True
    assert run.configuration["submission_batch_size"]==256
