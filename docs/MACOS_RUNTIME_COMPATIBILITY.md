# macOS Runtime Compatibility

MSAA supports Apple Silicon and Intel Macs. Optional tools are discovered with `shutil.which()` or system paths rather than assuming `/opt/homebrew`.

GUI runtime policy:

- Supported GUI Python range: Python 3.10 through 3.13.
- Python 3.14 GUI/Qt paths are blocked until validated.
- CLI, daemon, Codex, and pre-UAT non-interactive paths must not create `QApplication`.
- User-visible GUI actions should route through the main GUI or user notifier.

Runtime profile is exposed by `mac_audit_agent.runtime.platform_profile.detect_platform_profile()`.
