from __future__ import annotations
import ast
from pathlib import Path
from .conftest import load_fixtures


def test_fixture_domains_and_symbolic_destructive_content_are_inert():
    for item in load_fixtures():
        text=item["command_text"]
        assert "http://" not in text
        assert all(host in {"example.invalid"} for host in __import__("re").findall(r"https://([^/\s'\"]+)",text))
        if item["category"]=="destructive_symbolic": assert text.startswith("<ATTEMPT_") and text.endswith(">")


def test_test_sources_never_execute_fixture_content():
    forbidden_calls={"system","popen","eval","exec","execv","execl","spawnl","spawnv","getaddrinfo","gethostbyname"}
    for path in Path(__file__).parent.glob("*.py"):
        if path.name=="build_fixture_files.py": continue
        tree=ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node,ast.Call):
                name=getattr(node.func,"attr",getattr(node.func,"id",""))
                assert name not in forbidden_calls, f"{path.name} calls {name}"
                for keyword in node.keywords:
                    assert not (keyword.arg=="shell" and isinstance(keyword.value,ast.Constant) and keyword.value.value is True)
