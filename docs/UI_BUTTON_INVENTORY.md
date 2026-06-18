# UI Button Inventory

Generated for the production UI cleanup.

Rule: a visible production control must either perform a working action or explain why it is unavailable. Synthetic/demo/test controls are hidden unless `Settings > Developer Mode` is enabled.

## Dashboard

| Label | Panel | Purpose | Function | Required State | Enabled Condition | Disabled Reason | Decision |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Run Scan | Dashboard | Start local safe audit | `run_scan` | None | Always | n/a | Keep |
| Reset / New Scan | Dashboard | Clear current scan state | `reset_scan_state` | None | Always | n/a | Keep |
| Export JSON | Dashboard | Export current report | `export_json` | Completed scan | Scan result exists | Run a scan first to generate an exportable report. | Keep state-aware |
| Export HTML | Dashboard | Export current report | `export_html` | Completed scan | Scan result exists | Run a scan first to generate an exportable report. | Keep state-aware |
| Open Reports Folder | Dashboard | Open local report directory | `open_reports_folder` | None | Always | n/a | Keep |
| Open Assessment | Dashboard summary | Open Apple Exposure Assessment tab | `show_forecast_page` | None | Always | n/a | Keep |
| Open Health | Dashboard summary | Open Settings health panel | `show_settings_page` | None | Always | n/a | Keep |

## Apple Exposure Assessment

| Label | Panel | Purpose | Function | Required State | Enabled Condition | Disabled Reason | Decision |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Update Assessment | Apple Exposure Assessment | Refresh Apple/macOS security update advisor | `refresh_apple_security_forecast` | None | Always | n/a | Keep |
| Diagnostics | Apple Exposure Assessment | Show source/cache/filter diagnostics | `show_apple_security_forecast_diagnostics` | None | Always | n/a | Keep |
| Export Assessment | Apple Exposure Assessment | Export current production report | `export_html` | Report payload | Always available; report handles empty forecast | n/a | Keep |
| View Details | Apple Exposure Assessment | Inspect selected exposure card | `open_details` | Selected card | Card selected | Select a exposure card first. | Keep state-aware |
| Reviewed | Apple Exposure Assessment | Mark selected forecast reviewed | `mark_reviewed` | Selected card | Card selected | Select a exposure card first. | Keep state-aware |
| Snooze | Apple Exposure Assessment | Temporarily snooze selected card | `snooze_selected` | Selected card | Card selected | Select a exposure card first. | Keep state-aware |
| Update Guide | Apple Exposure Assessment | Show Apple update guidance | `open_update_guidance` | Selected card | Card selected | Select a exposure card first. | Keep state-aware |

Removed from production: `Generate Demo`, `Safari/WebKit Demo`, `Clear Demo`, synthetic/demo forecast generation.

## Family & Safety

| Label | Panel | Purpose | Function | Required State | Enabled Condition | Disabled Reason | Decision |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Run Safety Audit | Family & Safety | Run local family safety audit | `run_family_safety_audit` | None | Always | n/a | Keep |
| Export HTML | Family & Safety | Export family safety report | `export_family_safety_html` | Report auto-generated | Always | n/a | Keep |
| Export JSON | Family & Safety | Export family safety report | `export_family_safety_json` | Report auto-generated | Always | n/a | Keep |

## Intrusion Detection / Flight Recorder

| Label | Panel | Purpose | Function | Required State | Enabled Condition | Disabled Reason | Decision |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Refresh | Intrusion/Flight Recorder | Refresh local correlation data | `refresh_intrusion_detection` / `refresh_flight_recorder` | None | Always | n/a | Keep |
| Show Context | Intrusion/Flight Recorder | Show selected event/pattern context | `_show_intrusion_context` | Selection | Event/pattern selected | Select an item to show context. | Keep state-aware |
| Preserve Evidence Snapshot | Intrusion/Flight Recorder | Create evidence snapshot | `create_system_recovery_snapshot` | None | Always | n/a | Keep |
| Export AI Summary | Intrusion/Flight Recorder | Export local summary artifact | `export_intrusion_ai_summary` | Summary payload | Summary available | Run or refresh correlation first. | Keep state-aware |
| Open Logs | Intrusion/Flight Recorder | Open logs tab | `show_logs_page` | None | Always | n/a | Keep |

## Evidence Snapshots

| Label | Panel | Purpose | Function | Required State | Enabled Condition | Disabled Reason | Decision |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Run Incident Check | Evidence Snapshots | Assess cleanup/preservation risk | `run_system_recovery_incident_check` | None | Always | n/a | Keep |
| Create Evidence Snapshot | Evidence Snapshots | Preserve local evidence snapshot | `create_system_recovery_snapshot` | None | Always | n/a | Keep |
| Preview Cleanup | Evidence Snapshots | Preview cleanup candidates | `preview_system_recovery_cleanup` | None | Always | n/a | Keep |
| Run Cleanup | Evidence Snapshots | Run reviewed cleanup | `run_system_recovery_cleanup` | Selected candidates | Candidates selected | Select cleanup candidates before running cleanup. | Keep state-aware |
| Open Snapshots Folder | Evidence Snapshots | Open local snapshot folder | `open_system_recovery_snapshots_folder` | None | Always | n/a | Keep |
| Browse | Evidence Snapshots | Select custom log folder for preview | File picker | None | Always | n/a | Keep |

## Logs / Settings / Skins

| Label | Panel | Purpose | Function | Required State | Enabled Condition | Disabled Reason | Decision |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Refresh | Logs | Refresh logs | `refresh_logs_page` | None | Always | n/a | Keep |
| Open Reports Folder | Logs | Open reports folder | `open_reports_folder` | None | Always | n/a | Keep |
| Refresh | Operational Health | Refresh health report | `refresh_operational_health` | None | Always | n/a | Keep |
| Audit System Monitor Deployment | Operational Health | Audit installed monitor health | `audit_system_monitor_deployment` | None | Always | n/a | Keep |
| Verify Event Flow | Operational Health | Synthetic event flow verification | `verify_system_monitor_event_flow` | Developer Mode | Developer Mode enabled | Hidden unless Developer Mode is enabled. | Developer-only |
| Apply Skin | Skins | Apply selected appearance | Theme panel | Selected skin | Always | n/a | Keep |

## Background Monitor

| Label | Panel/Menu | Purpose | Function | Required State | Enabled Condition | Disabled Reason | Decision |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Install System Monitor + User Notifier | Settings > Monitor | Install monitor components | `install_monitor` | None | Always | n/a | Keep |
| Repair Background Monitor | Settings > Monitor | Repair monitor install | `repair_monitor` | None | Always | n/a | Keep |
| Force Reinstall Monitor | Settings > Monitor | Reinstall monitor components | `force_reinstall_monitor` | None | Always | n/a | Keep |
| Restart Monitor | Settings > Monitor | Restart monitor | `restart_monitor` | Installed monitor | State-aware | Install monitor first. | Keep state-aware |
| Start Monitor | Settings > Monitor | Start monitor | `start_monitor` | Installed monitor | State-aware | Install monitor first. | Keep state-aware |
| Stop Monitor | Settings > Monitor | Stop monitor | `stop_monitor` | Running monitor | State-aware | Monitor is not running. | Keep state-aware |
| Uninstall Monitor | Settings > Monitor | Remove monitor | `uninstall_monitor` | Installed monitor | State-aware | Install monitor first. | Keep state-aware |
| Show Monitor Logs | Settings > Monitor | Show monitor logs | `show_logs` | None | Always | n/a | Keep |
| Clear Monitor Logs | Settings > Monitor | Clear local monitor logs | `clear_monitor_logs` | Confirmation | Always | n/a | Keep |
| Repair Alerts / Notifier | Settings > Monitor | Repair notification path | `repair_alerts_notifier` | None | Always | n/a | Keep |
| Event Priorities | Settings > Monitor | Configure event priorities | `show_event_priorities_dialog` | None | Always | n/a | Keep |
| Audit System Monitor Deployment | Settings > Monitor | Audit monitor deployment | `audit_system_monitor_deployment` | None | Always | n/a | Keep |
| Repair System Monitor Deployment | Settings > Monitor | Repair system deployment | `repair_system_monitor_deployment` | None | Always | n/a | Keep |
| Save Notification Settings | Settings > Monitor | Persist notification settings | `save_notification_settings` | None | Always | n/a | Keep |
| Save Emergency Lockdown Policy | Security Response > Emergency Lockdown | Persist Lockdown response mode: disabled, recommend only, assist user, attempt activation, or managed environment | `save_emergency_lockdown_policy` | Warning acknowledged for attempt activation mode | Always; attempt activation rejects save without exact confirmation | Attempt activation requires “I understand” and typed confirmation; success still requires independent verification. | Keep state-aware |
| Emergency Lockdown Dry Run | Security Response > Emergency Lockdown | Show what the emergency policy would do for a critical event without changing system state | `dry_run_emergency_lockdown_policy` | None | Always | n/a | Keep |
| Export Monitor Log JSON | Settings > Monitor | Export monitor events | `export_json` | Events optional | Always | n/a | Keep |
| Export Monitor Log HTML | Settings > Monitor | Export monitor events | `export_html` | Events optional | Always | n/a | Keep |
| Show Context | Settings > Monitor | Show selected event context | `show_selected_event_context` | Selected event | Event selected | Select a monitor event first. | Keep state-aware |
| Why did this alert fire? | Settings > Monitor | Show selected event provenance | `show_selected_event_provenance` | Selected event | Event selected | Select a monitor event first. | Keep state-aware |
| Alert Pipeline Trace | Settings > Monitor | Show selected event alert trace | `show_selected_alert_pipeline_trace` | Selected event | Event selected | Select a monitor event first. | Keep state-aware |

Developer-only hidden controls: `Test Notification`, `Test High Priority Dialog`, `Test Silent Log Event`, `Generate Test Event`, `Test Bottom-Right Alert`, `Test Critical Alert`, `Test Idle Activity Warning`, `Verify Event Flow`, and matching Background Monitor menu actions.

## Menus

| Label | Menu | Purpose | Function | Required State | Enabled Condition | Disabled Reason | Decision |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Show Last Collector Debug | Diagnostics | Show last collector debug payload | `show_last_collector_debug` | Debug payload optional | Always; dialog explains missing payload | n/a | Keep |
| Aggressive Local Vulnerability Review | Diagnostics | Run local vulnerability review | `run_aggressive_local_vulnerability_review` | None | Always | n/a | Keep |
| Full Localhost Port Scan | Diagnostics | Run localhost-only scan | `run_full_localhost_port_scan` | None | Always | n/a | Keep |
| Packet Capture Snapshot | Advanced Evidence | Start confirmed packet capture | `run_packet_capture_snapshot` | Confirmation | tcpdump available; dialog explains limits | n/a | Keep |
| Local Network Device Discovery | Advanced Evidence | Discover local network devices | `run_network_discovery` | Network interface | Dialog validates scope | n/a | Keep |
| Developer: Generate/Test... | Background Monitor | Synthetic monitor/notifier controls | Trigger methods | Developer Mode | Developer Mode enabled | Hidden unless Developer Mode is enabled. | Developer-only |
| Developer Mode | Settings | Toggle synthetic controls | `_set_developer_mode` | None | Always | n/a | Keep |
