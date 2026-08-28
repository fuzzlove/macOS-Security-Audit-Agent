from __future__ import annotations
import socket
from mac_audit_agent.clickfix.corpus_validation import evaluate_fixture
from .conftest import load_fixtures


def test_corpus_evaluation_opens_no_socket_or_dns(monkeypatch):
    def denied(*_args,**_kwargs): raise AssertionError("network API used during offline corpus")
    monkeypatch.setattr(socket,"socket",denied);monkeypatch.setattr(socket,"create_connection",denied);monkeypatch.setattr(socket,"getaddrinfo",denied);monkeypatch.setattr(socket,"gethostbyname",denied)
    for fixture in load_fixtures():
        if not fixture.get("event_sequence"): evaluate_fixture(fixture)
