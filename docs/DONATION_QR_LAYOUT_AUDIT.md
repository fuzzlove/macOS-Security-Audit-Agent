# Donation QR Layout Audit

## Component Location

- Primary page: `MainWindow._build_support_author_page()` in `mac_audit_agent/ui/main_window.py`
- Primary component: `MainWindow._build_support_section(full_page=True)` in `mac_audit_agent/ui/main_window.py`
- User-facing placement: dedicated final `Support the Author` navigation tab
- Link target: Patreon support URL, with visible Patreon, Buy Me a Coffee, GitHub, and Website actions

## Previous Layout Risks

- Container layout type: `QVBoxLayout` inside a clickable `QFrame`
- Fixed constraints: QR image label used `setFixedSize(100, 100)`
- Image scaling mode: pixmap was pre-scaled to 100x100 with `Qt.KeepAspectRatio`
- Text behavior: body and link labels wrapped, but the title did not explicitly wrap
- Previous parent constraint: the details panel contained expanding `QTextEdit` widgets above the support card, so the card could lose vertical space on smaller windows
- Scroll fallback: none inside the support card
- Padding: 12px margins were usable but tight around a QR code plus multiple text labels

## Implemented Fix

- Removed hard fixed QR label sizing and replaced it with bounded sizing:
  - full-page minimum QR label: 180x180
  - full-page preferred render size: 240x240
  - full-page maximum QR label: 320x320
  - fixed label size policy to preserve a square QR region
- Loaded/scaled bundled production QR art with `Qt.KeepAspectRatio`
- Added an internal `QScrollArea` with vertical scrollbar as needed and no horizontal scrollbar
- Set the support card to `QSizePolicy.Expanding, QSizePolicy.MinimumExpanding`
- Set full-page support card minimum height to 420px
- Increased full-page internal content margins to 28px and spacing to 18px
- Enabled word wrap and centered alignment for title, body, and link text
- Removed the old embedded details-panel support card so the full support experience appears only in the final support tab

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
  - verifies the support card is on the final Support the Author page, not embedded in the details panel
  - verifies QR pixmap exists
  - verifies QR minimum bounds
  - verifies card minimum height
  - verifies scroll area fallback is enabled
  - verifies link text wraps
  - verifies support click path still opens the Patreon URL
- `mac_audit_agent/tests/test_assets.py::test_support_author_navigation_is_final_and_unique`
  - verifies Support the Author is the final navigation item
  - verifies there is exactly one Support the Author navigation item
