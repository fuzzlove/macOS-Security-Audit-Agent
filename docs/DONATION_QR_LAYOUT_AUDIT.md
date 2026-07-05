# Donation QR Layout Audit

## Component Location

- Primary component: `MainWindow._build_support_section()` in `mac_audit_agent/ui/main_window.py`
- Parent surface: selected item details side panel from `MainWindow._build_selected_command_panel()`
- User-facing placement: support card below finding details, remediation guidance, and review actions
- Link target: Patreon support URL, with visible Patreon/BuyMeACoffee text

## Previous Layout Risks

- Container layout type: `QVBoxLayout` inside a clickable `QFrame`
- Fixed constraints: QR image label used `setFixedSize(100, 100)`
- Image scaling mode: pixmap was pre-scaled to 100x100 with `Qt.KeepAspectRatio`
- Text behavior: body and link labels wrapped, but the title did not explicitly wrap
- Parent constraint: the details panel contains expanding `QTextEdit` widgets above the support card, so the card could lose vertical space on smaller windows
- Scroll fallback: none inside the support card
- Padding: 12px margins were usable but tight around a QR code plus multiple text labels

## Implemented Fix

- Removed hard fixed QR label sizing and replaced it with bounded sizing:
  - minimum QR label: 128x128
  - maximum QR label: 160x160
  - fixed label size policy to preserve a square QR region
- Loaded/scaled support art at 160x160 and rendered at 128x128 with `Qt.KeepAspectRatio`
- Added an internal `QScrollArea` with vertical scrollbar as needed and no horizontal scrollbar
- Set the support card to `QSizePolicy.Expanding, QSizePolicy.MinimumExpanding`
- Set support card minimum height to 286px to protect normal rendering from the expanding detail text editors above it
- Increased internal content margins to 18px and spacing to 12px
- Enabled word wrap and centered alignment for title, body, and link text

## Current Layout Contract

- QR code remains square and centered.
- QR code is never intentionally cropped; pixmap scaling uses `Qt.KeepAspectRatio`.
- Text labels wrap instead of truncating or requiring horizontal scrolling.
- The support card can grow vertically when space exists.
- When vertical space is unusually constrained, the internal scroll area exposes the full QR and text content instead of clipping children.
- The outer support card remains clickable and keeps its support-link tooltip.

## Regression Coverage

- `mac_audit_agent/tests/test_assets.py::test_support_rail_uses_image_and_patreon_link`
  - verifies support widgets exist
  - verifies QR pixmap exists
  - verifies QR minimum bounds
  - verifies card minimum height
  - verifies scroll area fallback is enabled
  - verifies link text wraps
  - verifies support click path still opens the Patreon URL
