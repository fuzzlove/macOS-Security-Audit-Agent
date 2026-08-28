# macOS GUI Runtime Crash Review

Reviewed 2026-07-12 following an ARM64 SIGABRT in `libqcocoa` while Apple Command Line Tools Python 3.9.6 attempted `NSApplication` registration.

## Root cause and bypass

The crash was a process-context governance failure. Stage-0 `launcher.py` had a guard, but GUI policy still admitted Python 3.10 and 3.11, while `mac_audit_agent.app` performed only a version-range check before importing `PySide6.QtWidgets` and `ui.main_window`. Direct imports and tests could bypass the complete macOS session, parent-process, root, and thread preflight. `assert_qapplication_allowed` ran after Qt imports and did not enforce the original process main thread.

An automated alert-card test reproduced the unsafe class of failure under CLT Python 3.9: direct `QApplication` construction aborted rather than raising Python. The corrected test uses the explicitly selected `offscreen` backend. No production Cocoa reproduction was attempted because that would risk another crash report.

## Corrections

`runtime/gui_preflight.py` is standard-library-only and runs before Qt/AppKit imports. GUI Python is exactly 3.12 or 3.13. It blocks root, LaunchDaemon, SSH/non-Aqua, wrong-thread, unsafe automation, inconsistent PySide/Shiboken, and unsupported runtimes with stable GUI001–GUI010 codes. Launcher JSON diagnostics and direct app imports use this boundary. The isolated probe loads no MSAA UI and cannot crash its parent.

Automatic runtime re-exec uses absolute validated candidates, a recursion marker, and `PYTHONNOUSERSITE=1`. Doctor and headless routes remain before GUI preflight and GUI imports.

## Remaining limitations

Interactive Cocoa and LaunchServices validation requires a logged-in macOS session. Signed app-bundle, Intel, universal, notarization, and actual native notification checks were not executable in this source sandbox. Many UI test modules import Qt at test collection and must be run only under the approved backend wrapper.
