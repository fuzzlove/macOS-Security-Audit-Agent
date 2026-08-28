# APP999 Anti-Ransomware Panel Startup Fix

Date: 2026-07-11

## Exact failure

| File | Location | Button | Reference | Callback existed | Startup impact | Resolution |
| --- | --- | --- | --- | --- | --- | --- |
| `mac_audit_agent/ui/anti_ransomware_panel.py` | `AntiRansomwarePanel.__init__` and `_refresh` | Install Active Protection | `self.install_protection` | No method; the same name was intended for a button attribute | `_refresh()` ran before the button attribute was created, producing `AttributeError`. External/new wiring could also resolve the name as a button rather than a callable method. | Button renamed to `install_protection_button`; initial refresh moved after all controls; public `install_protection()` method implemented and connected through the defensive registry. |
| `mac_audit_agent/ui/anti_ransomware_panel.py` | repair/verify/refresh/diagnostics actions | Install/Repair/Verify | public method names | Missing before repair | Future registry or action wiring could reproduce APP999 | Implemented `repair_protection`, `verify_protection`, `refresh_protection_status`, and `open_protection_diagnostics`. |
| `mac_audit_agent/ui/main_window.py` | Dashboard and Operational Health wiring | Install/Repair Active Protection | canonical MainWindow methods | Present | No startup defect | Retained; both surfaces call the same headless protection backend. |

## Safety and behavior

- The panel contains UI confirmation and result presentation only; LaunchDaemon, LaunchAgent, DB, manifest, and launchctl work remains in `mac_audit_agent.protection`.
- Missing registered callbacks call `connect_or_disable`: the control is disabled, receives `Action unavailable: callback not implemented.`, and logs `APP_BUTTON_CALLBACK_MISSING`. A missing callback cannot raise during panel construction.
- Install and repair display the administrator boundary and never invoke `sudo` silently.
- Success, first failure stage, recommended action, current protection state, Dashboard, and Operational Health are refreshed after the backend returns.

## Python 3.14 startup boundary

Python 3.14 remains available for headless doctor, protection, integrity, service, and Pre-UAT commands. GUI startup is blocked before importing PySide6/AppKit unless `MSAA_ALLOW_EXPERIMENTAL_PY314_GUI=1` is explicitly set for compatibility testing. Validated GUI runtimes remain Python 3.10–3.13; Python 3.12 or 3.13 is recommended.

## Verification

- `AntiRansomwarePanel` constructs successfully in an isolated offscreen compatibility test.
- All five public panel callbacks exist.
- The Install Active Protection button is enabled and connected.
- Python 3.14 GUI invocation exits cleanly with an actionable message and no traceback.
- Python 3.14 `--doctor --json` succeeds as a headless diagnostic path and reports callback audit `PASS`.
