"""macOS desktop security audit agent."""

# Python 3.9's dataclass decorator predates the layout-only ``slots`` option.
# Install the narrow compatibility behavior before package submodules import it.
from mac_audit_agent.compat.dataclasses import install_legacy_dataclass_compat

install_legacy_dataclass_compat()
