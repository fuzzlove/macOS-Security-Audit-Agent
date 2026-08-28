from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Optional


@dataclass(frozen=True)
class DependencyFallback:
    dependency: str; affected_capability: str; fallback_available: bool; fallback_description: str; user_message: str
    def to_dict(self) -> dict: return asdict(self)


FALLBACKS = {
    "PySide6": DependencyFallback("PySide6", "gui", True, "Doctor, integrity and protection CLI remain available.", "The graphical interface requires the GUI extra. Core diagnostics still work."),
    "cryptography": DependencyFallback("cryptography", "integrity_signature_sign", True, "hashlib verification remains available; signing is disabled.", "Hash verification is available. Manifest signing requires the crypto extra."),
    "psutil": DependencyFallback("psutil", "process_metadata", True, "Use ps, lsof, netstat and launchctl with reduced metadata.", "Process inspection is using macOS system tools fallback."),
    "requests": DependencyFallback("requests", "apple_security_guidance", True, "Use urllib.request and cached data.", "Network guidance uses the standard-library client or cached data."),
    "docx": DependencyFallback("python-docx", "docx_export", True, "HTML, JSON and CSV remain available.", "Word export is unavailable; other report formats still work."),
    "openpyxl": DependencyFallback("openpyxl", "xlsx_export", True, "CSV remains available.", "Excel export is unavailable; CSV export still works."),
    "reportlab": DependencyFallback("reportlab", "pdf_export", True, "HTML export remains available.", "PDF export is unavailable; HTML export still works."),
    "matplotlib": DependencyFallback("matplotlib", "chart_rendering", True, "Render tables without charts.", "Charts are unavailable; report tables remain available."),
    "AppKit": DependencyFallback("pyobjc/AppKit", "os_notifications", True, "Use local alert trace/log and CLI output.", "Native notifications are unavailable; alerts remain recorded locally."),
    "scapy": DependencyFallback("scapy/libpcap", "packet_capture", False, "Local lsof/netstat visibility remains available.", "Packet capture is unavailable; basic network visibility remains available."),
    "nmap": DependencyFallback("nmap", "network_scan_enhanced", True, "Use basic local network and listener inspection.", "Enhanced nmap scanning is unavailable; basic local checks remain available."),
}


def fallback_for(dependency: str) -> Optional[DependencyFallback]: return FALLBACKS.get(dependency)

__all__ = ["DependencyFallback", "FALLBACKS", "fallback_for"]
