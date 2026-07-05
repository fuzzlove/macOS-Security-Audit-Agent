# Help Menu Duplication Audit

## Canonical Decision

MSAA now has one global Help entry point:

- `Help Menu ?` button in the left navigation rail
- Implementation: `MainWindow.global_help_button`
- Action: `MainWindow.open_help_center()` -> `MainWindow.open_help_topic("help_center")`
- Controller: `HelpController` singleton in `mac_audit_agent/help/help_controller.py`

All contextual help must route to the same `HelpController` instance and navigate to a specific topic. Contextual `?` buttons are not global Help Menu entries.

## Entry Point Inventory

| Location | UI region | Type | Status | Action |
| --- | --- | --- | --- | --- |
| `mac_audit_agent/ui/main_window.py` `global_help_button` | Left navigation rail | Button labeled `Help Menu ?` | Primary | Keep as the only global Help Menu entry point |
| `mac_audit_agent/ui/main_window.py` former menu-bar `Help` menu | macOS menu bar | Menu with many topic actions | Duplicate | Removed; topic routing now uses Help Center navigation/search/contextual links |
| `mac_audit_agent/ui/main_window.py` `help_shortcut_action` | Keyboard shortcut only | QAction, F1 | Shortcut | Retained as non-visible shortcut labeled `Open Help Center`; calls the canonical Help Center |
| `mac_audit_agent/help/contextual_help.py` `make_help_button()` | Feature headers/cards | `?` icon button | Contextual | Kept, but routes through `MainWindow.open_help_topic()` / `HelpController` singleton |
| `mac_audit_agent/ui/main_window.py` `_build_help_header()` | Major feature pages | Contextual `?` icon | Contextual | Kept; opens relevant topic, not a separate help system |
| `mac_audit_agent/ui/main_window.py` dashboard integrity card | Dashboard card title row | Contextual `?` icon | Contextual | Kept; opens `integrity_verification` in same Help Center |
| `mac_audit_agent/help/help_viewer.py` `HelpViewer` | Help Center window | Unified Help Center | Primary surface | Reused by `HelpController`; no duplicate viewer instances |
| `mac_audit_agent/help/help_center.py` | Knowledge base service | Structured Help source | Source of truth | Kept as central content/navigation service |
| `mac_audit_agent/help/contextual_help.py` former `show_context_help()` | Feature help button path | New `HelpViewer` per click | Duplicate behavior | Refactored to reuse `HelpController` |
| `mac_audit_agent/ui/main_window.py` `show_provenance_button` | Finding details | Button labeled `Why did this alert fire?` | Not Help Menu | Keep as provenance/action explanation control; does not open Help Center |
| `mac_audit_agent/ui/background_monitor_panel.py` `show_provenance_button` | Background monitor events | Button labeled `Why did this alert fire?` | Not Help Menu | Keep as provenance/action explanation control; does not open Help Center |

## Removed Duplication

- Removed the menu-bar `Help` menu and its duplicate topic actions.
- Removed per-click contextual `HelpViewer` creation.
- Standardized global opening through `open_help_center()`.
- Standardized topic navigation through `open_help_topic(topic_id)`.

## Current Rules

- Exactly one visible global Help Menu entry exists: `Help Menu ?`.
- Contextual `?` icons must use `helpButton_<topic_id>` object names and open a specific topic.
- Contextual help must not create a separate Help window.
- F1 is a keyboard shortcut only and must call the same Help Center controller.
- `HelpController` owns Help Center singleton behavior.

## Regression Coverage

- `test_main_window_has_single_global_help_menu_entry`
- `test_help_controller_is_singleton`
- `test_global_help_menu_button_opens_help_center_and_reuses_viewer`
- `test_contextual_help_buttons_remain_icon_sized_and_specific`
- `test_contextual_help_buttons_route_to_same_help_center_instance`
- `test_help_controller_reuses_single_help_center_viewer`
- `test_no_duplicate_visible_global_help_labels_or_help_menu_actions`
- `test_f1_shortcut_action_opens_help_center`
