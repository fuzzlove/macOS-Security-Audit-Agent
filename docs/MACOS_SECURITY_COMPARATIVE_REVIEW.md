# macos_security Comparative Review

Generated: 2026-07-06

## Scope

Requested comparative source:

- `../macos_security`
- same-parent fallback names: `macos_security`, `macOS_security`, `macos-security`, `MacOS-Security`

Result:

- The requested adjacent directory was not present from the MSAA repository root.
- The parent directory contains `macOS-Security-Audit-Agent`, but not a sibling `macos_security` project.
- The only matching path found was `../macOS-Security-Audit-Agent/macos_security`, which resolves to the current MSAA checkout's internal directory. It was not treated as the requested adjacent project because it is not a separate sibling source.

## Inventory

| Field | Result |
| --- | --- |
| Project name | Not available |
| Path | `../macos_security` not found |
| License file | Not inspected; source unavailable |
| README summary | Not inspected; source unavailable |
| Major modules | Not inventoried |
| Collectors | Not inventoried |
| Checks | Not inventoried |
| Reports | Not inventoried |
| UI concepts | Not inventoried |
| Security frameworks referenced | Not inventoried |
| macOS-specific hardening logic | Not inventoried |
| Evidence collection logic | Not inventoried |
| Remediation guidance | Not inventoried |
| Export formats | Not inventoried |
| Tests | Not inventoried |
| Packaging/build approach | Not inventoried |
| Logging strategy | Not inventoried |
| Configuration strategy | Not inventoried |
| Alerting strategy | Not inventoried |
| Privilege model | Not inventoried |

## Non-Copying Position

No implementation, assets, report templates, UI text, tests, or documentation were copied from an adjacent project because the requested source was unavailable.

## Standards-Driven Alternative

MSAA improvement recommendations were derived from public standards and public guidance categories instead:

- NIST CSF 2.0
- NIST SP 800-53 Rev. 5
- NIST SP 800-171 Rev. 2 / Rev. 3
- CISA Cybersecurity Performance Goals and KEV context
- DoD CMMC readiness references
- NSA public cybersecurity guidance
- PCI DSS v4.0.1 where payment-card relevance exists
- MITRE ATT&CK technique context where applicable

See also:

- `docs/MSAA_VS_MACOS_SECURITY_COMPARE_CONTRAST.md`
- `docs/STANDARDS_DERIVED_IMPROVEMENT_MATRIX.md`
- `docs/derived_features/`

## Guardrails

- Do not use the internal `./macos_security` directory as a substitute for the missing adjacent project without a separate explicit review request.
- Do not preserve another project's source structure, wording, reports, comments, test data, or assets.
- Any future comparison must re-run this review and update the IP safety document before implementation.
