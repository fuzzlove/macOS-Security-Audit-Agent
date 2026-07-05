# Reporting Test Failures

## Stabilized Failures

| Test | Expected Behavior | Root Cause | Fix Applied |
| --- | --- | --- | --- |
| `test_html_contains_escaped_content` | Finding command/source text appears in HTML and is escaped. | The active professional report renderer omitted the finding command/source field. | Added command/source normalization and a `Command / Source` row rendered with `safe_html()`. |
| `test_severity_css_classes_exist` | Severity classes and badges use solid colors, with no `rgba(` in report CSS. | The report layout CSS used transparent `rgba(...)` border/shadow values. | Replaced transparent CSS values with solid hex colors while preserving severity palette classes. |
| `test_reports_include_investigation_priorities_section` | HTML reports always include `Investigation Priorities`. | The active renderer exposed `Top 10 Priorities` but omitted the dedicated investigation-priorities section. | Added an always-present `Investigation Priorities` section with fallback priorities derived only from existing critical/high findings. |

## Guardrails

- Tests were not skipped or weakened.
- Dynamic finding command/source values are escaped before insertion.
- Severity styles remain solid hex colors.
- Empty investigation-priority output renders an explicit empty state.
