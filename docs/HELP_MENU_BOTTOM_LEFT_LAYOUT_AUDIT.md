# Help Menu Bottom-Left Layout Audit

Generated: 2026-07-08

## Scope

Audited the global `Help Menu ?` control in the MSAA main application shell.

Search terms covered:

- `Help Menu?`
- `Help Menu ?`
- `Help Menu`
- `help_button`
- `help_menu_button`
- `HelpCenter`
- `HelpController`
- `global help`
- `question mark`
- `QPushButton`
- `QToolButton`

## Current Implementation

| Field | Value |
| --- | --- |
| Visible label | `Help Menu ?` |
| File path | `mac_audit_agent/ui/main_window.py` |
| Class/function | `MainWindow._build_ui()` |
| Object name | `globalHelpMenuButton` |
| Callback | `self.global_help_button.clicked.connect(self.open_help_center)` |
| Help controller path | `MainWindow.open_help_center()` uses the shared `HelpController` / `HelpViewer` flow |
| Size/style | `mac_audit_agent/ui/help_button_style.py` compact style, 28-34 px height, max width 122 px |
| Tooltip | `Open the MSAA Help Menu.` |
| Accessible name | `Help Menu` |
| Accessible description | `Opens the central MSAA Help Menu and Help Center.` |

## Previous Layout Issue

Before this fix, `MainWindow._build_ui()` added the global Help Menu button directly to `left_nav_layout` before the `QListWidget` primary navigation:

```python
left_nav_layout.addWidget(self.global_help_button)
left_nav_layout.addWidget(self.sidebar, 1)
```

That made Help appear as the first sidebar control, visually competing with primary feature navigation and disrupting the sidebar proportions.

## Target Layout

The global Help Menu now lives in a dedicated sidebar utility footer:

```text
MainWindow
  leftNavigation
    Main Navigation QListWidget
      ...primary feature tabs...
      Support the Author
    sidebarUtilityFooter
      globalHelpMenuButton
```

Target container:

- File path: `mac_audit_agent/ui/main_window.py`
- Object name: `sidebarUtilityFooter`
- Parent: `leftNavigation`
- Placement: after primary navigation in `left_nav_layout`
- Alignment: `Qt.AlignLeft | Qt.AlignBottom`

## Navigation Relationship

- `Help Menu ?` is a utility action, not a feature tab.
- `Help Menu ?` is not added to the primary `QListWidget`.
- `Support the Author` remains the final primary navigation item through `pinned_position="last"`.
- Future feature tabs should continue to insert before `Support the Author`.

## Files Changed

- `mac_audit_agent/ui/main_window.py`
- `mac_audit_agent/ui/navigation_registry.py`
- `mac_audit_agent/quality/button_layout_auditor.py`
- `mac_audit_agent/quality/functional_registry.py`
- `mac_audit_agent/tests/test_help.py`
- `mac_audit_agent/tests/test_help_menu_button_pre_uat.py`
- `mac_audit_agent/tests/test_navigation_registry.py`
- `docs/HELP_MENU_BOTTOM_LEFT_LAYOUT_AUDIT.md`

## Validation Added

- Tests assert exactly one global Help Menu button exists.
- Tests assert the button is parented by `sidebarUtilityFooter`.
- Tests assert the footer is the final sidebar layout item.
- Tests assert Help is not present in the primary navigation list.
- Tests assert `Support the Author` remains the final primary navigation item.
- Pre-UAT registry now includes `ui.help_menu_bottom_left`.
- Button layout audit now validates the source-level footer placement.
