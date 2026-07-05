# Help Menu Button Layout Audit

## Canonical Layout Decision

MSAA has one global Help Menu button:

- Label: `Help Menu ?`
- Location: main outer navigation, at the top of the left navigation rail
- Object name: `globalHelpMenuButton`
- Owner: `mac_audit_agent/ui/main_window.py`
- Action: `MainWindow.open_help_center()` -> `HelpController.open_help_topic("help_center")`

This button is the only global Help entry point. It is visible on startup, not icon-only, and sits outside feature tabs, cards, dialogs, and diagnostic panels.

## Button Inventory

| File path | UI location | Label | Classification | Action |
| --- | --- | --- | --- | --- |
| `mac_audit_agent/ui/main_window.py` | Main outer left navigation, first item | `Help Menu ?` | Global Help Menu | Keep as the single central Help Menu button |
| `mac_audit_agent/ui/main_window.py` | Application action list, keyboard only | `Open Help Center` | Shortcut | Keep as non-visible F1 shortcut to the same HelpController |
| `mac_audit_agent/help/contextual_help.py` | Feature headers and cards created by `make_help_button()` | `?` | Contextual help | Keep only for specific topic routing through HelpController |
| `mac_audit_agent/ui/main_window.py` | Major feature page headers built by `_build_help_header()` | `?` | Contextual help | Keep; opens the related feature topic, not the global Help Menu |
| `mac_audit_agent/ui/main_window.py` | Dashboard integrity card title row | `?` | Contextual help | Keep; opens `integrity_verification` in the same Help Center instance |
| `mac_audit_agent/ui/main_window.py` | Finding details panel | `Why did this alert fire?` | Provenance action, not Help Menu | Keep; explains selected alert provenance and does not duplicate Help |
| `mac_audit_agent/ui/background_monitor_panel.py` | Background monitor event controls | `Why did this alert fire?` | Provenance action, not Help Menu | Keep; explains selected monitor event provenance and does not duplicate Help |
| `mac_audit_agent/help/help_controller.py` | Shared controller | No visible button | Help routing source of truth | Keep; owns singleton HelpViewer lifecycle |
| `mac_audit_agent/help/help_viewer.py` | Help Center dialog | Window title `MSAA Help` | Unified Help surface | Keep; only HelpController should create/reuse this viewer |

## Removed Or Prohibited Layouts

- No menu-bar `Help` menu.
- No Help Menu buttons inside settings, reports, operational health, Apple Exposure, Persistence Intelligence, Network Intelligence, Family & Safety, or About surfaces.
- No duplicate global `?` buttons.
- No UI component may instantiate `HelpViewer` directly.
- No feature panel may create a second Help Center or mini Help panel.

## Current Routing Rules

- Global Help: `Help Menu ?` -> `open_help_center()` -> `help_center`.
- Contextual Help: `?` -> `open_help_topic(topic_id)`.
- F1 shortcut: `Open Help Center` -> `open_help_center()`.
- Provenance explanations: remain feature actions and do not route to Help.

## Regression Coverage

- `test_main_window_has_single_global_help_menu_entry`
- `test_global_help_menu_button_is_visible_labeled_accessible_and_left_positioned`
- `test_no_duplicate_visible_global_help_labels_or_help_menu_actions`
- `test_global_help_menu_button_opens_help_center_and_reuses_viewer`
- `test_contextual_help_buttons_remain_icon_sized_and_specific`
- `test_contextual_help_buttons_route_to_same_help_center_instance`
- `test_help_controller_reuses_single_help_center_viewer`
- `test_ui_code_uses_help_controller_instead_of_direct_help_viewer_construction`
