"""Authoritative, side-effect-free macOS platform and deployment probes."""

from .architecture import ArchitectureInfo, detect_architecture
from .capabilities import CapabilityState, CapabilityStatus, evaluate_platform_capabilities
from .execution_mode import ExecutionModeInfo, detect_execution_mode
from .macos_version import MacOSVersionInfo, detect_macos_version
from .paths import PlatformPaths, resolve_platform_paths
from .python_runtime import PythonRuntimeDetails, detect_python_details

__all__ = ["ArchitectureInfo", "CapabilityState", "CapabilityStatus", "ExecutionModeInfo", "MacOSVersionInfo", "PlatformPaths", "PythonRuntimeDetails", "detect_architecture", "detect_execution_mode", "detect_macos_version", "detect_python_details", "evaluate_platform_capabilities", "resolve_platform_paths"]
