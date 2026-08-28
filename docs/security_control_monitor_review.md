# Security Control Monitor Review

Reviewed 2026-07-12. MSAA currently routes background events through `notification_manager.py`, SQLite storage, a user-notifier process, and `security_overlay.py`. It also has action queues, alert traces, diagnostic delivery tests, monitoring panels, integrity verification, and several polling collectors.

## Root causes

The visible notifier uses one JSON state file and one `SecurityOverlay` widget. A later event replaces the earlier payload instead of adding an independent durable card. The overlay hides when the file is unreadable, `active` becomes false, or an expiry is reached. Medium and High persistence is inconsistent. Cooldown grouping can prevent a second render while reporting a queue length of one. Acknowledgment rewrites the single shared state. Placement always uses the primary display, not the active display. These mechanisms explain alerts appearing, improving briefly, and then disappearing or being replaced.

No `WA_DeleteOnClose` or lost Python widget reference was found in this path. The primary defect is architectural replacement and hide behavior. Native notification support still includes legacy AppleScript/tray paths and is not a complete UserNotifications integration.

## Changes and migration

The additive `security_controls` package introduces typed states/events, a formal registry, normalization, authorization, incident-risk assessment, redaction, trusted collectors, tamper-evident storage, sensor-gap telemetry, native notification health boundaries, and signed proprietary rule bundles. `alerts/durable.py` adds restart restoration, persistence policy, acknowledgment, and delivery metrics.

Its SQLite schema is separate and additive. Existing background-monitor data is not deleted or rewritten. Production rollout requires a pre-migration backup and integration with the repository database path resolver.

Tests cover normalization, authorization, severity, CVSS separation, redaction, command allowlisting, evidence chaining, tampering, acknowledgment, restart restoration, FSEvents gaps, and native-delivery claims.

## Platform limitations

Endpoint Security attribution, FSEvents streaming, real UserNotifications dispatch, native click-through, system-extension IPC, wake/login orchestration, and full control collectors require signed native components and macOS permissions. They are not simulated. No privileged security setting was changed during testing.
