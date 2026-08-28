from __future__ import annotations

from dataclasses import dataclass

from mac_audit_agent.runtime.setup_guidance import build_setup_guidance


@dataclass
class Runtime:
    version_tuple: tuple[int, ...] = (3, 9, 6)
    gui_allowed: bool = False


class Registry:
    def evaluate(self, capability_id):
        return type("Capability", (), {"status": "blocked"})()


def test_python39_guidance_uses_project_venv_not_clt_pip() -> None:
    guidance = build_setup_guidance(Runtime(), Registry())
    commands = "\n".join(guidance.exact_commands)
    assert "python3.12 -m venv .venv" in commands
    assert 'python -m pip install -e ".[gui,office]"' in commands
    assert "/Library/Developer/CommandLineTools" not in commands
    assert "Do not install MSAA extras" in guidance.recommended_fix
