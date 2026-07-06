# Donation Support Link Audit

## Current Donation UI Location

- Primary page: `MainWindow._build_support_author_page()` in `mac_audit_agent/ui/main_window.py`
- Primary card: `MainWindow._build_support_section(full_page=True)` in `mac_audit_agent/ui/main_window.py`
- User-facing placement: dedicated final `Support the Author` navigation tab
- Central link registry: `mac_audit_agent/branding/support_links.py`

## Production Support Links

| Link | Production URL |
| --- | --- |
| Patreon | `https://patreon.com/fuzzlove` |
| Buy Me a Coffee | `https://buymeacoffee.com/fuzzlove` |
| GitHub | `https://github.com/fuzzlove` |
| Website | `https://liquidskysecurity.com` |
| Developer / Organization | Liquidsky Network Security |

## QR Code Asset

- Current QR asset path: `mac_audit_agent/assets/donation_qr.png`
- Metadata path: `mac_audit_agent/assets/donation_qr.json`
- QR target URL: `https://patreon.com/fuzzlove`
- Purpose: production donation/support QR for the MSAA support card
- Packaging: `pyproject.toml` includes `assets/*.png` and `assets/*.json`; PyInstaller includes the full `mac_audit_agent/assets` directory.

## Demo / Placeholder Findings

- Legacy support image behavior loaded a remote GitHub user-attachment image from `main_window.py`.
- Legacy Patreon behavior used an old Patreon join URL directly in `main_window.py`.
- The support card text was generic and did not name Liquidsky Network Security.

## Corrections

- Removed remote support image loading from production UI.
- Added a bundled production QR asset generated for the canonical Patreon URL.
- Added metadata recording target URL, generation time, purpose, developer, and verification status.
- Centralized all support links in `mac_audit_agent/branding/support_links.py`.
- Updated the support UI copy to:
  - `Support MSAA Development`
  - Liquidsky Network Security maintenance/support text
  - Patreon, Buy Me a Coffee, GitHub, and Website actions
  - Liquidsky Network Security copyright footer
- Removed the old embedded details-panel support section so the full support experience appears only in the dedicated final navigation tab.
- Updated tests so production support URLs cannot regress to demo/placeholder values.
