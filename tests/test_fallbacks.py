from __future__ import annotations

from mac_audit_agent.runtime.capabilities import CapabilityRegistry
from mac_audit_agent.runtime.detector import detect_python_runtime
from mac_audit_agent.runtime.fallbacks import FALLBACKS
from mac_audit_agent.runtime.setup_guidance import build_setup_guidance


def test_major_optional_dependencies_have_plain_language_fallbacks() -> None:
    for dependency in ("PySide6", "cryptography", "psutil", "requests", "docx", "openpyxl", "reportlab", "matplotlib", "AppKit", "scapy", "nmap"):
        fallback = FALLBACKS[dependency]
        assert fallback.user_message and fallback.fallback_description


def test_setup_guidance_is_non_destructive_and_actionable() -> None:
    runtime = detect_python_runtime()
    guidance = build_setup_guidance(runtime, CapabilityRegistry(runtime))
    assert guidance.recommended_fix
    assert guidance.destructive is False
    if not runtime.gui_allowed:
        assert any("python3.13" in command for command in guidance.exact_commands)
