# MSAA Security Operations UX Consolidation

## Inventory baseline

The desktop currently exposes 41 primary navigation destinations. The largest UI
implementation is `ui/main_window.py` (about 10,000 lines), followed by the
background-monitor and persistence panels. This makes navigation labels, refresh
behavior, data ownership, and evidence routing easy to diverge.

The consolidation must reuse these existing system-of-record services:

| Concern | Existing authority | Consolidation decision |
|---|---|---|
| Findings | `models.Finding`, `storage.AuditDatabase` | Keep `Finding` canonical; adapters may normalize older dictionaries into it. |
| Security events | `models.BackgroundMonitorEvent`, `alerts.resilient_models.SecurityEvent` | Use `SecurityEvent` for correlated alert ingestion and retain background events as source evidence. |
| Alerts | resilient alert store/pipeline and aggregate tables | Alert Center consumes this store; modules must not invent incompatible inbox records. |
| Assessments | `assessment.SecurityAssessment`, framework assessment records | Extend one assessment engine with profiles and common check results. |
| Sensor state | health registry, providers, coordinator, persistence | Dashboard and Reliability consume coordinator output; they do not re-probe sensors independently. |
| Evidence | evidence graph, secure evidence repository, flight recorder | Findings and alerts route to evidence references rather than copying raw evidence into UI-only state. |
| Local scans | collectors and stored `ScanResult` | Dashboard summarizes the latest stored result and routes to Results/Assessment for detail. |
| Protection | anti-ransomware health, active-protection status, containment coordinator | Dashboard reports state; Anti-Ransomware owns configuration and containment. |
| Network | network monitor, network intelligence, segmentation engine | Monitor owns connections, Intelligence owns meaning/enrichment, Segmentation owns authorized boundary tests. |
| Appearance | themes, severity styles, theme panel | Rename the user surface to Appearance; preserve semantic severity colors. |

## Duplicate and conflicting surfaces

- Dashboard, Results, Assessment, Scan Categories, Apple Exposure Assessment,
  Framework Coverage, and Visibility Integrity all present posture-like data with
  different summaries. Dashboard becomes the command center; Assessment becomes
  the reusable assessment workflow; Results remains evidence detail.
- Network Monitor and Network Intelligence both show listeners, connections, DNS,
  VPN, and proxy data. Collection stays with Network Monitor; enrichment and
  interpretation stay with Network Intelligence.
- Anti-Typosquatting already supports domains and eight package ecosystems in one
  engine. The product name becomes **Package & Domain Impersonation**; no second
  typosquatting engine is created.
- Operational Health, Sensor Health, Visibility Integrity, and Reliability overlap.
  Sensor Health answers current functional coverage, Dashboard surfaces critical
  degradation, and Reliability owns history. Visibility/integrity evidence remains
  available without being presented as a separate sensor implementation.
- “Not Signed” is ambiguous and overstates unsigned status. The surface becomes
  **Unsigned Software** while keeping signature types and behavioral context.
- “Add/Remove Programs” becomes **Applications**. Removal remains previewed,
  reversible where possible, and excludes user data by default.
- “Skins” becomes **Appearance**. “Profile & Access” becomes **Identity & Access**.
- “Investigation Priorities” becomes the singular **Investigation Priority** queue.

## Polling and refresh audit

Independent timers currently include:

- Alert Center: 5 seconds;
- Network Monitor: 5 seconds;
- CVE/exposure scheduling in the main window;
- Background Monitor: 30 seconds;
- ClickFix Guard: 30 seconds;
- tray status: 30 seconds;
- investigation-note autosave: 30 seconds;
- threat news scheduling;
- animation-only timers and the active timesheet clock.

The 5-second Alert Center and Network Monitor loops are the main duplicate database
pressure. They should eventually subscribe to one application refresh coordinator
that pauses hidden pages and coalesces refreshes. Autosave, animations, and an
actively running timesheet have different semantics and must not be merged into
security polling.

## Dead, placeholder, and misleading UI

- `button_callback_registry` can render “callback not implemented”; production
  controls must instead be hidden or explicitly capability-gated.
- The anti-typosquatting passive DNS provider is an injected capability placeholder,
  not a production online source; the UI must not imply it performed a lookup.
- Pre-UAT and experimental/fault-injection controls remain developer-only.
- Legacy hidden dashboard image labels are compatibility objects and must never be
  windows or visible dashboard content.
- Raw event totals are useful diagnostics but not primary posture signals.

## Consolidated navigation model

1. **Overview** — Dashboard, Apple Security Assessment, Family & Safety.
2. **Protection** — Host IDS, Anti-Ransomware, Sensor Health, ClickFix Guard,
   Keylogger Detection, Firewall, Emergency Protection.
3. **Posture & Inventory** — Assessment, Zero Trust Posture, Unsigned Software,
   Applications, Persistence Intelligence, Identity & Access, DNS Assurance,
   Package & Domain Impersonation.
4. **Network** — Network Monitor, Network Intelligence, Network Segmentation.
5. **Investigation** — Investigation Priority, Flight Recorder, Alert Center, Logs,
   Evidence/Live Response, Reliability.
6. **Workspace** — Reports/Results, Consultant Timesheet, Settings, Appearance,
   Security Research Device, Code Review.

This is an information architecture target. Existing pages are moved or renamed
incrementally so stored route identifiers and report compatibility can be preserved.

## Shared operational questions

Every top-level page must make its ownership explicit:

- **Posture:** assessment and configuration state.
- **Now:** live/correlated activity.
- **Attention:** prioritized findings and degraded coverage.
- **Action:** bounded remediation with consequences and verification.
- **Evidence:** durable references proving why MSAA reached the conclusion.

Severity and confidence remain separate. Unknown and unavailable are never rendered
as healthy, failed, or malicious without supporting evidence. Framework mappings are
context and never certification claims.
