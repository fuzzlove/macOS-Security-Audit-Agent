# UI Audit

Generated for the state-aware control refactor.

## Control Standard

Every visible control must either do something immediately or explain why it is unavailable.

State model:

- `enabled`: the action can run now.
- `visible`: the action belongs in the current context.
- `reason`: plain-language explanation when unavailable.
- `requirements`: data or selection needed for the action.

Implementation helper: `mac_audit_agent/ui/action_state.py`.

## Navigation Tabs

| Tab | Purpose | Requires Data | Requires Selection | Requires Scan | Requires Monitor Event | Requires Report | Currently Functional | Placeholder | Hidden Candidate | Remove Candidate |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Dashboard | High-level summary and primary scan/report workflow | No | No | Export only | No | Export only | Yes | No | No; advanced scan actions are routed through menus | No |
| Family & Safety | Guided safety audit, caregiver/school/parent recommendations, local reports | No | No | No | No | Export auto-generates report | Yes | No | No | No |
| Intrusion Detection | Correlated patterns, coverage, context, AI-ready local summary | Monitor data improves output | Context requires selected pattern/event | Optional | Optional | AI summary requires report payload | Yes | No | Context action hidden until selection | No |
| Investigation Priorities | Ranked finding review queue | Yes | Priority details require selected item | Yes | Optional | Yes | Yes | No | Review actions should stay inside priority panel | No |
| Flight Recorder | Timeline of monitor activity and correlated events | Yes | Context requires selected event | No | Yes | No | Yes | No | Context action hidden until selection | No |
| Evidence Snapshots | Recovery, cleanup, snapshot, and preservation workflow | Some actions require snapshots/history | Some tables require row selection | No | No | No | Yes | No | Snapshot open/export/delete should only appear when snapshots exist | No |
| Apple Exposure Assessment | Apple security intelligence and local exposure assessment | Forecast data | Details/review/snooze/guidance require selected card | No | No | Forecast cards | Yes | No | Selection actions now explain requirement | No |
| Logs | Local scan logs and background monitor events | No | No | Optional | Optional | No | Yes | No | No | No |
| Settings | Operational health and background monitor configuration | No | Some monitor event actions require selection | No | Optional | No | Yes | No | Advanced/test monitor buttons should move behind Advanced menu over time | No |
| Skins | Local appearance controls | No | No | No | No | No | Yes | No | No | No |
| Scan Categories | Command registry and command previews | Registry data | Command preview requires row selection | No | No | No | Yes | No | No | No |
| Results | Findings, ports, users, CVEs, workflow and evidence tables | Yes | Details require selected finding/table row | Yes | Optional | Yes | Yes | No | No; clean installs show an empty-state panel until results exist | No |
| Investigation Notes | Local investigation notes and exports | Scan improves context | No | Optional | No | Notes | Yes | No | Export should explain when no notes exist | No |
| Command Preview | Read-only command preview and safety metadata | Registry data | Specific command details require command selection | No | No | No | Yes | No | No | No |

## Persistent Details Panel

| Control | Purpose | Requires Data | Requires Selection | Requires Scan | Currently Functional | Refactor Decision |
| --- | --- | --- | --- | --- | --- | --- |
| Details text area | Shows selected finding or command details | Optional | Finding/command for detailed content | No | Yes | Empty state text remains visible |
| Remediation text area | Shows remediation summary | Finding data | Selected finding | Yes for findings | Yes | Empty state text remains visible |
| Remediation command selector | Select copyable remediation command | Finding remediation command | Selected finding | Yes | Yes | Hidden until selected finding |
| Copy Command | Copies selected remediation command | Remediation command | Selected finding | Yes | Yes | Hidden until selected finding; disabled with reason if no command |
| Run Command | Runs selected remediation command after confirmation | Remediation command | Selected finding | Yes | Yes | Hidden until selected finding; disabled with reason if no command |
| Add Note | Adds note to selected finding | Finding | Selected finding | Yes | Yes | Hidden until selected finding |
| Mark Reviewed | Changes review state | Finding | Selected finding | Yes | Yes | Hidden until selected finding |
| Mark False Positive | Changes review state | Finding | Selected finding | Yes | Yes | Hidden until selected finding |
| Mark Confirmed Concern | Changes review state | Finding | Selected finding | Yes | Yes | Hidden until selected finding |
| Mark Needs Follow-Up | Changes review state | Finding | Selected finding | Yes | Yes | Hidden until selected finding |
| Show Context | Opens workflow context for selected finding | Finding | Selected finding | Yes | Yes | Hidden until selected finding |
| Why did this alert fire? | Opens provenance dialog | Finding | Selected finding | Yes | Yes | Hidden until selected finding |
| Support card | Opens optional support link | No | No | No | Yes | Visible; not part of analyst workflow |

## Menus

| Menu Item | Purpose | Requires Data | Requires Selection | Requires Scan | Requires Monitor Event | Currently Functional | Refactor Decision |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Diagnostics > Show Last Collector Debug | Shows last collector debug payload | Debug payload | No | Optional | No | Yes | Should explain when no debug payload exists |
| Diagnostics > Aggressive Local Vulnerability Review | Starts local vulnerability review | No | No | No | No | Yes | Keep as advanced action |
| Diagnostics > Full Localhost Port Scan | Runs localhost-only port scan | No | No | No | No | Yes | Keep as advanced action |
| Advanced Evidence > Packet Capture Snapshot | Runs confirmed local packet capture | No | No | No | No | Yes | Keep advanced and confirmation-gated |
| Advanced Evidence > Local Network Device Discovery | Runs local network discovery | No | No | No | No | Yes | Keep advanced and confirmation-gated |
| Background Monitor > Generate Test Event | Creates test monitor event | Monitor config | No | No | No | Yes | Test action; should move behind test/diagnostic grouping |
| Background Monitor > Test Notification | Tests notifier | Monitor config | No | No | No | Yes | Test action; keep diagnostic |
| Background Monitor > Test High Priority Dialog | Tests visible alert path | Monitor config | No | No | No | Yes | Test action; keep diagnostic |
| Background Monitor > Test Bottom-Right Alert | Tests overlay alert | Monitor config | No | No | No | Yes | Test action; keep diagnostic |
| Background Monitor > Test Idle Activity Warning | Tests idle warning | Monitor config | No | No | No | Yes | Test action; keep diagnostic |
| Settings > Family & Safety | Opens Family & Safety tab | No | No | No | No | Yes | Keep |
| Settings > Appearance | Opens Skins tab | No | No | No | No | Yes | Keep |
| Settings > Event Priorities | Opens event priority dialog | No | No | No | No | Yes | Keep |
| Settings > Monitor Protection | Opens monitor protection dialog | No | No | No | No | Yes | Keep |
| Settings > Monitor Mode | Opens monitor mode dialog | No | No | No | No | Yes | Keep |
| Help > About Mac Audit Agent | Shows about dialog | No | No | No | No | Yes | Keep |
| Tray > Open Security Viewer | Restores window | No | No | No | No | Yes | Keep |
| Tray > Background Monitor | Opens Settings/monitor panel | No | No | No | No | Yes | Keep |
| Tray > View Security Logs | Opens Logs tab | No | No | No | No | Yes | Keep |
| Tray > Monitor status | Shows monitor state | Monitor state | No | No | Optional | Yes | Disabled status item with explanatory text |
| Tray > Recent events | Shows event count | Monitor state | No | No | Optional | Yes | Disabled status item with explanatory text |
| Tray > Refresh Status | Refreshes tray state | No | No | No | No | Yes | Keep |
| Tray > Quit Viewer | Quits app viewer | No | No | No | No | Yes | Keep |

## Panel-Level Notes

### Dashboard

Primary actions:

- Run Scan
- Reset / New Scan
- Open Reports Folder

Context-dependent actions:

- Export JSON: requires completed scan. Disabled with tooltip: "Run a scan first to generate an exportable report."
- Export HTML: requires completed scan. Disabled with same tooltip.

Advanced actions:

- Aggressive Local Vulnerability Review
- Full Localhost Port Scan
- Local Network Device Discovery

These are no longer mixed into the Dashboard primary header. They remain available from Diagnostics and Advanced Evidence menus, with a Dashboard note explaining where they live.

### Intrusion Detection / Flight Recorder

Primary actions:

- Refresh
- Open Logs
- Preserve Evidence Snapshot

Context-dependent actions:

- Show Context: hidden until a pattern or event is selected.
- Export AI Summary: disabled with reason until a local summary is available.

### Apple Exposure Assessment

Primary actions:

- Update Assessment
- Diagnostics
- Export Assessment

Context-dependent actions:

- Details
- Review
- Snooze
- Guidance

These are disabled with tooltip "Select a exposure card first."

### Background Monitor

Primary actions:

- Install System Monitor + User Notifier
- Repair Background Monitor
- Save Notification Settings
- Show Monitor Logs

Context-dependent actions:

- Start/Stop/Restart/Uninstall Monitor: require installed monitor and now explain that requirement.
- Show Context / Why did this alert fire? / Alert Pipeline Trace: hidden until a monitor event is selected.

Follow-up: move the many test buttons into a diagnostics drawer or menu to reduce clean-install noise.

### Family & Safety

Primary actions:

- Run Safety Audit
- Export HTML
- Export JSON

Export actions auto-generate a local report if none exists, so they are immediately functional and not dead controls.

### Skins

Primary action:

- Apply Skin

No data requirements.

### Results

Clean install state:

- Shows "No results available yet."
- Recommends running Safe Scan from the Dashboard.
- Hides the results tab set until a scan/result payload exists.

Populated state:

- Shows findings, ports, localhost scan, packet capture, network discovery, workflow, investigation priorities, execution evidence, CVE, process, user, history, file, baseline, and raw log tabs.

## Placeholder / TODO Search Decisions

Search terms reviewed:

- TODO
- pass
- placeholder
- not implemented
- future
- coming soon
- dummy
- test only
- mock
- stub

Findings:

- Most `pass` entries are exception handling no-ops in system integration code and are not visible UI placeholders.
- Test/mock/stub mentions are in tests or diagnostic language and are not exposed as unfinished user controls.
- Explicit test controls are visible in Background Monitor and Apple Exposure Assessment. They are functional, but should be grouped as diagnostics instead of mixed with primary workflows.

## Acceptance Progress

Completed in this pass:

- Added shared `ActionState`.
- Hidden selected-finding actions until a finding is selected.
- Added reasons/tooltips for disabled remediation commands.
- Hidden Intrusion Detection context action until a pattern/event is selected.
- Added disabled reason for unavailable AI summary export.
- Added disabled reasons for Apple Exposure Assessment card actions.
- Added disabled reasons for background monitor lifecycle controls.
- Hidden monitor event context/provenance/trace actions until event selection.
- Added disabled reasons for Dashboard report export controls.
- Grouped Dashboard primary and report actions.
- Removed advanced scan buttons from the Dashboard primary header and routed users to menus.
- Added a clean-install Results empty-state panel and hid blank result tabs until scan data exists.

Remaining follow-up:

- Move Background Monitor test controls into a diagnostics drawer/menu.
- Add richer empty-state panels inside individual result subtabs after a scan when a specific artifact type is absent.
- Add automated UI assertion that every disabled button has a tooltip.
