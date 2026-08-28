from __future__ import annotations
import json
from pathlib import Path
import pytest

CORPUS=Path(__file__).with_name("fixtures.json")

def load_fixtures(): return json.loads(CORPUS.read_text(encoding="utf-8"))

def pytest_generate_tests(metafunc):
    if "clickfix_fixture" in metafunc.fixturenames:
        values=[item for item in load_fixtures() if not item.get("event_sequence")]
        metafunc.parametrize("clickfix_fixture",values,ids=[item["fixture_id"] for item in values])
