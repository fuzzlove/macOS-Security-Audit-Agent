from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from enum import Enum

from .architecture import detect_architecture
from .macos_version import detect_macos_version
from .python_runtime import detect_python_details


class CapabilityState(str, Enum):
    AVAILABLE="AVAILABLE"; UNAVAILABLE="UNAVAILABLE"; DEGRADED="DEGRADED"; PERMISSION_REQUIRED="PERMISSION_REQUIRED"; DEPENDENCY_MISSING="DEPENDENCY_MISSING"; UNSUPPORTED_OS="UNSUPPORTED_OS"; UNSUPPORTED_ARCHITECTURE="UNSUPPORTED_ARCHITECTURE"; UNSUPPORTED_PYTHON="UNSUPPORTED_PYTHON"; NOT_INSTALLED="NOT_INSTALLED"; NOT_SIGNED="NOT_SIGNED"; NOT_ENTITLED="NOT_ENTITLED"; NOT_LOADED="NOT_LOADED"; FAILED="FAILED"; UNKNOWN="UNKNOWN"


@dataclass(frozen=True)
class CapabilityStatus:
    capability_id: str; available: bool; state: CapabilityState; reason_code: str; message: str; required_action: str | None; evidence: dict[str, object]
    def to_dict(self) -> dict[str, object]:
        value=asdict(self); value["state"]=self.state.value; return value


def evaluate_platform_capabilities() -> dict[str, CapabilityStatus]:
    architecture=detect_architecture(); macos=detect_macos_version(); python=detect_python_details()
    gui=CapabilityStatus("gui", python.gui_allowed and macos.supported, CapabilityState.AVAILABLE if python.gui_allowed and macos.supported else CapabilityState.UNSUPPORTED_PYTHON if not python.gui_allowed else CapabilityState.UNSUPPORTED_OS, "GUI_RUNTIME_OK" if python.gui_allowed and macos.supported else "GUI_RUNTIME_BLOCKED", "GUI runtime prerequisites are available." if python.gui_allowed and macos.supported else "GUI is unavailable for this Python or macOS runtime.", "Use Python 3.12/3.13 on a supported macOS release." if not python.gui_allowed else None, {"python":python.to_dict(),"macos":macos.to_dict()})
    endpoint=CapabilityStatus("endpoint_security", False, CapabilityState.NOT_ENTITLED, "ES_ENTITLEMENT_NOT_VERIFIED", "Endpoint Security is observation-only until a signed, entitled sensor is installed and approved.", "Install the signed sensor and grant required local/MDM approval.", {"native_architecture":architecture.native_hardware,"sensor_path":"/Library/Application Support/MacAuditAgent/bin/MSAAEndpointSecuritySensor.app/Contents/MacOS/MSAAEndpointSecuritySensor"})
    fda=CapabilityStatus("full_disk_access", False, CapabilityState.PERMISSION_REQUIRED, "FDA_NOT_VERIFIED", "Protected paths may be unavailable until Full Disk Access is granted.", "Grant access only to the exact signed MSAA component.", {"automatic_tcc_modification":False})
    return {item.capability_id:item for item in (gui,endpoint,fda)}


__all__ = ["CapabilityState", "CapabilityStatus", "evaluate_platform_capabilities"]
