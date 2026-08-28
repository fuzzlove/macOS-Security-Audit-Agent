from __future__ import annotations
import json
from mac_audit_agent.clickfix.shell_events import append_event, event_from
from mac_audit_agent.clickfix.corpus_validation import evaluate_fixture
from .conftest import load_fixtures


def test_logs_contain_hashes_but_no_raw_or_decoded_fixture(tmp_path):
    path=tmp_path/"events.jsonl"
    for fixture in load_fixtures():
        if fixture.get("event_sequence") or fixture.get("simulation"): continue
        result=evaluate_fixture(fixture)
        request={key:fixture.get(key) for key in ("paste_origin","multiline","trailing_newline","shell")};request["phase"]="test"
        append_event(event_from(request,result,event_type="submission_warning",config_source="test",coverage="offline_corpus"),path)
    content=path.read_text(encoding="ascii")
    for fixture in load_fixtures(): assert fixture["command_text"] not in content
    for line in content.splitlines():
        record=json.loads(line);assert "command" not in record and len(record.get("command_sha256", "")) in {0,64}
