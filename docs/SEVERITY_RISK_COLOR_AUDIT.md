# Severity and Risk Color Audit

MSAA now uses `mac_audit_agent.ui.severity_styles` as the canonical NIST/NVD/CVSS-inspired severity palette. The palette is a government-style severity visualization; it is not an official NIST color standard and does not imply certification or government approval.

## Canonical Rules

- Severity labels are always visible; color is not the only signal.
- Colors are solid `#RRGGBB` values with no transparency.
- CVSS-style scores map to None, Low, Medium, High, and Critical using NVD qualitative ranges.
- Risk scores where higher is worse are mapped separately from security scores where higher is better.
- Missing or unrecognized values render as `UNKNOWN`, not blank.

## Affected Areas

| File | Tab/View | Widget/Table | Column/Field | Data Key | Current Styling | Required Styling | Implemented |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `mac_audit_agent/reporting.py` | HTML exports | Findings, severity cards, timeline, Apple Exposure, health rows | Severity / Risk / Status | `severity`, `forecast_level`, `status` | Mixed local CSS and report labels | Canonical severity classes and inline badges | Yes |
| `mac_audit_agent/exporters/excel_exporter.py` | Excel exports | Findings, remediation, Apple Exposure, device/network/admin tables | Severity, Criticality, Risk, CVSS, Forecast, Trust, Baseline, Status | multiple | Risk-only helper | Canonical fills with readable foreground | Yes |
| `mac_audit_agent/exporters/word_exporter.py` | Word exports | Findings and detailed finding tables | Severity | `severity` | Risk helper shading | Canonical severity shading and label text | Yes |
| `mac_audit_agent/ui/risk_colors.py` | Compatibility layer | Persistence and risk badges | Risk / Trust / Baseline | multiple | Separate risk palette | Wrapper over canonical severity palette | Yes |
| `mac_audit_agent/ui/persistence_intelligence_panel.py` | Persistence Intelligence | Inventory, findings, top risks, detail badges | Severity, Risk, Trust, Baseline, Status | `severity`, `risk_level`, `risk_score`, `trust_label`, `baseline_status` | Shared risk helper | Canonical palette through compatibility wrapper | Yes |
| `mac_audit_agent/persistence_intelligence/report_adapter.py` | Persistence exports | HTML persistence sections | Severity, Risk, Trust, Baseline | multiple | Shared risk helper | Canonical palette through compatibility wrapper | Yes |
| `mac_audit_agent/persistence_intelligence/timeline.py` | Persistence timeline | Timeline table | Severity | `severity` | Shared risk badge | Canonical palette through compatibility wrapper | Yes |
| `mac_audit_agent/ui/operational_health_panel.py` | Operational Health | Component health table | Status | `status` | Plain table text | Canonical status severity styling | Yes |
| `mac_audit_agent/ui/main_window.py` | Dashboard / Findings | Dashboard severity cards and severity-row styling | Severity | `severity` | Report severity map | Canonical severity lookup | Yes |
| `mac_audit_agent/security_overlay.py` / `mac_audit_agent/alert_styles.py` | Alerts | Alert overlay | Severity | `severity` | Existing solid palette matching critical/high/medium/low/info/success | Same government-style palette; no duplicate alert system created | Yes |
| `mac_audit_agent/reliability.py` | SARIF export | SARIF results | Severity | `severity` | Existing SARIF level mapping | Critical/high error, medium warning, low/info note | Existing |
| `mac_audit_agent/family_safety/` | Family & Safety Center | Category status/report values | Status / Risk | category status | Reported through HTML/JSON paths | Canonical report/export styling where rendered | Yes |
| `mac_audit_agent/quality/` | Pre-UAT Audit | Functional checks/report exports | Status / Failure Severity | `status`, `severity_if_failed` | Existing text plus report/export styling | Canonical styling where exported | Yes |
| `mac_audit_agent/apple_exposure_guidance.py` and Apple Exposure report rows | Apple Exposure Assessment | Exposure cards/report rows | Forecast Level, Severity, CVSS, KEV | `forecast_level`, `severity`, `cvss_score`, `kev_status` | Mixed label display | Canonical report/export styling; UI cards use same semantic labels where table-backed | Yes |

## Normalization Notes

- `urgent` -> `critical`
- `elevated` -> `high`
- `watch` -> `medium`
- `clear`, `healthy`, `verified`, `trusted` -> `success`
- `degraded`, `stale`, `partial` -> `medium`
- `broken`, `failing`, `failed`, `modified` -> `critical`
- `review_needed`, `unavailable`, missing values -> `unknown`

## Remaining Guardrails

- New UI/report code should import from `mac_audit_agent.ui.severity_styles`.
- Existing persistence code may continue using `mac_audit_agent.ui.risk_colors`; that module is now a compatibility wrapper over the canonical severity palette.
- Do not introduce new hardcoded severity palettes in feature code.
