# Support Author Layout Audit

## Current Support UI Locations

| Location | Status | Action |
| --- | --- | --- |
| `MainWindow._build_support_author_page()` | Canonical | Dedicated final navigation page |
| `MainWindow._build_support_section(full_page=True)` | Canonical card | Reused only by the Support the Author page |
| Selected Item Details side panel | Removed duplicate | Embedded support card caused vertical cropping in constrained layouts |

## Canonical Placement

- Navigation title: `Support the Author`
- Navigation id: `support_author`
- Registry: `mac_audit_agent/ui/navigation_registry.py`
- Order rule: `pinned_position="last"`
- Validation: `validate_navigation_order()` fails if the support item is missing, duplicated, or not final.

## Layout Cause of Cropping

The previous support card lived inside the selected-item details panel below expanding text editors and remediation controls. On smaller windows the details panel did not provide enough vertical space for the QR, body text, links, and buttons, so the support content could appear cropped or cramped.

## Layout Correction

- Moved support into a standalone final page.
- Support page uses `QScrollArea` with `setWidgetResizable(True)`.
- Full-page card uses larger QR bounds:
  - minimum QR size: 180x180
  - preferred QR size: 240x240
  - maximum QR size: 320x320
- The old embedded details-panel support section was removed to avoid duplicate full support panels.
- Production links remain centralized in `mac_audit_agent/branding/support_links.py`.
- QR asset remains bundled at `mac_audit_agent/assets/donation_qr.png`.

## Canonical Support Links

- Patreon: `https://patreon.com/fuzzlove`
- Buy Me a Coffee: `https://buymeacoffee.com/fuzzlove`
- GitHub: `https://github.com/fuzzlove`
- Website: `https://liquidskysecurity.com`
- Developer: Liquidsky Network Security
