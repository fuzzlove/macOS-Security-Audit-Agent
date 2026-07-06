# UI Label Header Deduplication Audit

## Header Hierarchy

MSAA now treats page text as a four-level hierarchy:

1. `PageHeader`: one primary title per major view.
2. Page subtitle: short orientation text directly under the primary title.
3. `SectionHeader`: specific subsection names below the primary title.
4. Field labels and button labels: action or data labels that do not repeat the page title.

Primary page titles must not be repeated inside the same view. Contextual `?` buttons are allowed only when they route to a specific Help topic.

## Findings And Actions

| File path | Widget/object | Visible text | Parent view | Duplicate location | Action |
| --- | --- | --- | --- | --- | --- |
| `mac_audit_agent/ui/main_window.py` | `PageHeader` | `Dashboard` | Dashboard | None after cleanup | Keep as primary header |
| `mac_audit_agent/ui/main_window.py` | Dashboard summary card | `Apple Exposure Assessment` | Dashboard | Dedicated dashboard card, not page title | Keep as unique summary card title |
| `mac_audit_agent/ui/main_window.py` | Dashboard summary card | `Operational Health` | Dashboard | Dedicated dashboard card, not page title | Keep as unique summary card title |
| `mac_audit_agent/ui/main_window.py` | Dashboard summary card | `Integrity Health` | Dashboard | Dedicated dashboard card, not page title | Keep as unique summary card title |
| `mac_audit_agent/ui/main_window.py` | `PageHeader` | `Apple Exposure Assessment` | Apple Exposure Assessment | `CveRadarPanel` internal title | Keep primary header; removed internal duplicate |
| `mac_audit_agent/ui/cve_radar_panel.py` | Former internal header | `Apple Exposure Assessment` | Apple Exposure Assessment | Main page header | Removed and replaced with `Assessment Status` section label |
| `mac_audit_agent/ui/main_window.py` | `PageHeader` | `Family & Safety Center` | Family & Safety | `FamilySafetyPanel` internal title | Keep primary header; moved subtitle into page header |
| `mac_audit_agent/ui/family_safety_panel.py` | Former internal header | `Family & Safety Center` | Family & Safety | Main page header | Removed |
| `mac_audit_agent/ui/main_window.py` | `PageHeader` | `Persistence Intelligence` | Persistence Intelligence | `PersistenceIntelligencePanel` internal title | Keep primary header; moved actions into content toolbar |
| `mac_audit_agent/ui/persistence_intelligence_panel.py` | Former internal header | `Persistence Intelligence` | Persistence Intelligence | Main page header | Removed |
| `mac_audit_agent/ui/main_window.py` | `PageHeader` | `Network Intelligence` | Network Intelligence | `NetworkIntelligencePanel` internal title | Keep primary header; moved description into page subtitle |
| `mac_audit_agent/ui/network_intelligence_panel.py` | Former internal header | `Network Intelligence` | Network Intelligence | Main page header | Removed |
| `mac_audit_agent/ui/main_window.py` | `PageHeader` | `Settings` | Settings | Former stacked `Operational Health` and `Monitor Settings` primary headers | Keep as the only primary Settings header |
| `mac_audit_agent/ui/main_window.py` | Former primary header | `Operational Health` | Settings | `OperationalHealthPanel` title | Converted from page header role by replacing Settings top area with a single `Settings` PageHeader |
| `mac_audit_agent/ui/main_window.py` | `SectionHeader` | `Monitor Settings` | Settings | Former primary header with same visual weight as page title | Converted to section header |
| `mac_audit_agent/ui/operational_health_panel.py` | Section title | `Operational Health` | Settings | No longer duplicates a page title | Keep as section/panel label |
| `mac_audit_agent/help/help_viewer.py` | Help topic title label | Topic-specific title | Help Center | Global `Help Menu ?` button | Keep; Help topic title is not a duplicate global menu label |
| `mac_audit_agent/ui/main_window.py` | `globalHelpMenuButton` | `Help Menu ?` | Main outer navigation | None | Keep as the only global Help Menu entry point |

## Implementation Notes

- Added `mac_audit_agent/ui/page_header.py` with `PageHeader` and `SectionHeader`.
- Replaced ad hoc help headers in `MainWindow` with `PageHeader`.
- Removed duplicate internal titles from wrapped Apple Exposure, Family & Safety, Persistence Intelligence, and Network Intelligence panels.
- Converted Settings to one primary `Settings` header with specific sections below.
- Added `mac_audit_agent/ui/ui_text_audit.py` for visible adjacent duplicate label detection.
- Added Pre-UAT coverage through `mac_audit_agent/quality/ui_header_auditor.py`.

## Regression Coverage

- `test_major_views_have_one_primary_page_header`
- `test_wrapped_panels_do_not_repeat_page_titles`
- `test_settings_page_has_single_primary_title`
- `test_duplicate_header_helper_flags_adjacent_duplicate_labels`
- `run_ui_header_audit` in Pre-UAT UI mode
