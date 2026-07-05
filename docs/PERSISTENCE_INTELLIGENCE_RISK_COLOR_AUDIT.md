# Persistence Intelligence Risk Color Audit

## Summary

Persistence Intelligence now uses the shared `mac_audit_agent.ui.risk_colors` palette for risk, severity, trust, baseline, confidence, and status display. Colors are solid, high-contrast, and paired with visible text labels and tooltips.

## Tables

| Table / View | Column | Data Source | Previous Display | Desired Color Behavior | Implemented |
|---|---|---|---|---|---|
| Persistence Inventory | Risk | `PersistenceItem.risk_level` | Plain text | Strong severity badge using risk level and risk score | Yes |
| Persistence Inventory | Risk Score | `PersistenceItem.risk_score` | Available in model/report export, not a separate compact UI column | Score-backed risk styling; score cells are colored when displayed in reports or future table variants | Yes |
| Persistence Inventory | Trust | `PersistenceItem.trust_label` | Plain text | Trusted/legitimate green, suspicious/high risk red, unknown gray | Yes |
| Persistence Inventory | Trust Score | `PersistenceItem.trust_score` | Available in model/report export, not a separate compact UI column | Trust-backed styling; score cells are colored when displayed in reports or future table variants | Yes |
| Persistence Inventory | Baseline | `PersistenceItem.baseline_status` | Not shown | New/changed/hash changed emphasized, known/trusted green/blue, unknown gray | Yes |
| Persistence Inventory | Mechanism | `PersistenceItem.mechanism` | Plain text | Neutral text; primary emphasis remains risk/trust/baseline | Yes |
| Persistence Findings | Severity | `PersistenceFinding.severity` | Plain text | Strong severity badge | Yes |
| Persistence Findings | Confidence | `PersistenceFinding.confidence` | Plain text | Secondary color treatment; high confidence does not outrank severity | Yes |
| Persistence Findings | Status | Static `Open` pending workflow state | Not shown | Status badge; open/reviewed/resolved palette support | Yes |
| Chain View | Risk / Trust relationships | `build_chain_view()` plus item lookup | Raw JSON/plain text | HTML badges beside chain entries | Yes |
| Timeline | Severity | Timeline event `severity` | Plain text | Strong severity badge in UI table and HTML timeline export | Yes |
| Baseline Compare | Added/removed/modified/hash changes | Baseline comparison JSON | Raw JSON text | Documented as text view; color will apply if converted to table | Not a table |
| Assessment / Reports | Persistence findings severity | MSAA finding severity | Existing severity display | Canonical solid severity colors in HTML/Word/Excel paths | Yes |
| Persistence HTML Report | Inventory/Findings risk | Persistence report adapter | Plain text | Risk badges with shared palette | Yes |
| Persistence JSON Report | Item/finding risk | Persistence report adapter | No color metadata | Adds `risk_label` and `risk_color` metadata | Yes |
| Excel Reports | Severity/risk-like columns | Export workbook rows | Limited severity fills | Shared solid color fills for severity/risk/trust/baseline columns | Yes |
| Word Reports | Severity labels | Export finding rows | Colored text only | Shared palette text plus shaded severity cells | Yes |

## Canonical Columns

Recognized risk-related names include:

- `risk`
- `risk_level`
- `risk_label`
- `risk_score`
- `severity`
- `trust`
- `trust_label`
- `trust_score`
- `confidence`
- `baseline`
- `baseline_status`
- `finding_status`
- `status`

## Notes

- Unknown or missing values render as `UNKNOWN`, not blank.
- Sorting uses `Qt.UserRole` risk rank for styled table cells.
- The shared palette avoids transparent colors and centralizes styling to prevent duplicate hardcoded palettes.
