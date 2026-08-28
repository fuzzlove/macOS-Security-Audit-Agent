# Help Menu Button Size Audit

## Implementation

- File path: `mac_audit_agent/ui/main_window.py`
- Widget/object name: `self.global_help_button`, object name `globalHelpMenuButton`
- Parent container: `self.left_nav`
- Layout position: first widget in `left_nav_layout`, above the main `QListWidget` navigation
- Central style helper: `mac_audit_agent/ui/help_button_style.py`

## Previous State

- Text: `Help Menu ?`
- Minimum height: `36`
- Maximum height: none
- Size policy: `QSizePolicy.Expanding`, `QSizePolicy.Fixed`
- Font weight: `700`
- Padding: `6px 12px`
- Tooltip: long Help Center explanation
- Accessible name: `Help Menu`
- Accessible description: `Open the MSAA Help Center`

## Surrounding Navigation

- Sidebar widget: `QListWidget`
- Sidebar width: min `150`, max `240`
- Left navigation width: min `170`, max `260`
- The help control sits directly above compact navigation rows, so it should read as a compact navigation utility, not a banner or primary CTA.

## Final Dimensions

- Minimum height: `28px`
- Maximum height: `34px`
- Maximum width: `122px`
- Size policy: `QSizePolicy.Preferred` horizontally, `QSizePolicy.Fixed` vertically
- Padding: `4px 8px`
- Font size: `12px`
- Font weight: `500`
- Border radius: `6px`

## Behavior Preserved

- Still text-labeled as `Help Menu ?`
- Still opens the centralized MSAA Help Center through `open_help_center`
- Still unique; no extra Help menu action is added
- Still keyboard focusable
- Tooltip: `Open the MSAA Help Menu.`
- Accessible name: `Help Menu`
- Accessible description: `Opens the central MSAA Help Menu and Help Center.`
