# UI Button Fixed-Size Exceptions

Date: 2026-07-08

Policy: visible action buttons should use canonical min/max dimensions and `QSizePolicy.Preferred` or a responsive action row. Fixed sizes are allowed only for icon-only controls, tiny status controls, or non-button visual assets.

## Allowed Exceptions

| Component | File | Reason |
|---|---|---|
| Header logo | `mac_audit_agent/ui/main_window.py` | Image asset, not a button. Uses fixed square geometry for predictable branding. |
| Dashboard logo | `mac_audit_agent/ui/main_window.py` | Image asset, not a button. Uses fixed square geometry for predictable branding. |
| Icon-only buttons created by `create_icon_button` | `mac_audit_agent/ui/button_factory.py` | Bounded 28-34 px control size is intentional and requires tooltip/accessibility metadata. |

## Disallowed Patterns

- `setFixedHeight` on text buttons.
- `setFixedWidth` on text buttons that appear in menus, sidebars, cards, or action rows.
- Oversized padding in local button stylesheets.
- Plain horizontal action rows with more buttons than can fit at the supported minimum width.

## Current Status

Static button inventory did not find fixed-size button usage in scanned button construction windows. The global Help Menu fixed height was removed and now uses compact min/max sizing.
