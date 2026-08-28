# UI Button Functionality Audit

Date: 2026-07-11

The machine-readable inventory is produced by `mac_audit_agent.quality.button_functionality_auditor.audit_visible_buttons()`. It parses every Python UI module for `QPushButton`, `QToolButton`, and the canonical button factories, then records label, file, panel, variable, callback, enabled state, tooltip, and classification. Dynamic and loop-created controls are retained as manual-review candidates rather than silently treated as functional.

Current static result: **211 concrete visible/source button declarations inventoried, 0 enabled disconnected candidates, 0 critical blockers**. Factory `on_click=` callbacks and later `clicked.connect(...)` wiring are both recognized; generic dynamic button factory internals are not misreported as visible controls.

## Critical Active Protection actions

| Label | File / panel | Callback | Actual action | Mutation / permission | Progress and result | Tooltip | Classification |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Install Active Protection / Repair Active Protection | `mac_audit_agent/ui/anti_ransomware_panel.py`, `AntiRansomwarePanel` | `install_protection` / `repair_protection` | Confirms the documented change, invokes the shared headless install or repair backend, re-resolves status, and renders structured results | System installation needs explicit root execution; non-root returns `permission_blocked` and exact next action | Preparing/progress text, structured result, first failure stage, evidence path, Dashboard and Health refresh | Yes | functional |
| Install Active Protection | `mac_audit_agent/ui/operational_health_panel.py`, `OperationalHealthPanel` | `install_active_protection_requested` → `MainWindow.install_active_protection_from_ui` | Invokes `install_active_protection`, refreshes Operational Health, displays exact result/evidence | Administrator required; no silent elevation | Completion/failure dialog plus refresh | Yes | functional |
| Repair Active Protection | same | `repair_active_protection_requested` → `MainWindow.repair_active_protection_from_ui` | Idempotent repair using shared backend; preserves DB/events and creates backups | Administrator required for system component | Completion/failure dialog plus refresh | Yes | functional |
| Verify Active Protection | same | `verify_active_protection_requested` → `MainWindow.verify_active_protection_from_ui` | Read-only live launchctl/plist/SQLite/heartbeat/alignment check | No mutation | Structured result plus refresh | Yes | functional |
| Export Protection Diagnostics | same | `export_protection_diagnostics_requested` → `MainWindow.export_active_protection_diagnostics` | Writes sanitized live resolver output to user-selected JSON | User-selected path only | Success message | Yes | functional |

## Existing high-value controls reviewed

| Control family | Expected and actual target | Classification |
| --- | --- | --- |
| Preserve Evidence Snapshot | Emits `preserve_integrity_evidence_snapshot_requested`, connected to `create_system_recovery_snapshot` | functional |
| Operational Health repair/audit/verify | Signals connect to MainWindow repair and Background Monitor live audit/event-flow callbacks | functional |
| Anti-Ransomware setup/readiness/copy | Opens contextual help, refreshes live state, or copies sanitized JSON | functional |
| Anti-Ransomware containment/block/trust | Disabled with explicit prerequisite tooltip | disabled with reason |
| Export actions | Canonical export buttons use an explicit destination callback; disabled placeholders include a tooltip | functional or disabled with reason |

## Enforcement

`ui.buttons.functional_actions` is release-blocking for missing/disconnected Active Protection actions. The full generated inventory also exposes `disconnected_candidates` for manual review because Python signal connections made through loops, helper factories, or subsequent controller wiring cannot always be proven by a single-file AST pass. A new critical button cannot pass merely because its label exists.
