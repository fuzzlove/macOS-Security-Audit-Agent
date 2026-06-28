# Framework Mapping

## Purpose

MSAA maps scan checks, detections, findings, and report recommendations to recognized cybersecurity frameworks so analysts can understand how local evidence relates to common investigation, monitoring, and risk-management language.

MSAA provides framework mappings for analyst context and reporting support. These mappings do not constitute certification, compliance, authorization, or an official assessment.

## Supported Frameworks

- NIST Cybersecurity Framework 2.0
- NIST SP 800-53 Rev. 5
- NIST SP 800-61 Rev. 3
- MITRE ATT&CK Enterprise macOS techniques
- CISA Known Exploited Vulnerabilities catalog where relevant
- NVD/CVE metadata where relevant

## Mapping Methodology

Mappings are assigned from three sources:

- Rule-level mappings for detector rules such as LaunchDaemon changes, admin changes, network listeners, suspicious execution, hardware changes, and monitoring health.
- Category-level mappings for scan findings created from local evidence such as ports, processes, permissions, persistence, account changes, and report/evidence workflows.
- Vulnerability-level mappings when CVE identifiers, CVSS metadata, NVD references, or CISA KEV status are present.

The mapping layer uses language such as "mapped to", "aligned with", "supports", and "references". It avoids certification or authorization claims.

## Limitations

- Framework mappings are contextual aids, not a control assessment.
- A local MSAA finding does not prove that an organization satisfies or fails any framework requirement.
- MITRE ATT&CK mappings are applied only where the observed behavior reasonably aligns with a macOS-relevant technique.
- CISA KEV and NVD/CVE mappings depend on available vulnerability metadata.
- Analysts should validate applicability, scope, asset ownership, compensating controls, and local policy before using mappings in formal reporting.

## Examples

LaunchDaemon added:

- MITRE ATT&CK macOS: T1543.004 Launch Daemon
- NIST CSF 2.0: Detect / Continuous Monitoring; Respond / Analysis
- NIST SP 800-53 Rev. 5: SI-4, AU-6, CM-3, CM-6
- NIST SP 800-61 Rev. 3: Detection and Analysis

Hidden localhost port mismatch:

- MITRE ATT&CK macOS: T1046 Network Service Discovery
- NIST CSF 2.0: Detect / Continuous Monitoring
- NIST SP 800-53 Rev. 5: SI-4, SC-7, AU-6
- NIST SP 800-61 Rev. 3: Detection and Analysis

Apple Exposure Assessment CVE:

- NIST CSF 2.0: Identify, Protect, Respond
- NIST SP 800-53 Rev. 5: RA-5, SI-2
- NVD/CVE: CVE identifier and CVSS metadata when available
- CISA KEV: referenced when the CVE appears in KEV metadata
