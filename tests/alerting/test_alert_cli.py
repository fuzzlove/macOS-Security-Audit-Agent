from __future__ import annotations

import json

from mac_audit_agent.alerts.cli import main


def test_status_and_suppression_list_are_safe_json(tmp_path,capsys):
    path=tmp_path/"events.sqlite3"
    assert main(["status","--db",str(path)])==0
    status=json.loads(capsys.readouterr().out)
    assert status["integrity_ok"] is True and "emergency_buffer_capacity" in status
    assert main(["suppression","--db",str(path),"list"])==0
    assert json.loads(capsys.readouterr().out)==[]


def test_unprivileged_suppression_change_is_rejected(tmp_path,capsys,monkeypatch):
    monkeypatch.setattr("mac_audit_agent.alerts.cli.os.geteuid",lambda:501)
    result=main(["suppression","--db",str(tmp_path/"events.sqlite3"),"create","--field","rule_id","--value","RULE-1","--owner","owner","--expires","2099-01-01T00:00:00+00:00","--reason","fixture","--ticket","T-1","--authorizer","admin"])
    assert result==2 and "privileged" in json.loads(capsys.readouterr().out)["error"]
