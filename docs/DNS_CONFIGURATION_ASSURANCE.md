# DNS Configuration Assurance

The DNS section collects resolver addresses through existing Network Intelligence, compares normalized IPs with client-approved resolver scope, and exports JSON or HTML evidence. Collected evidence remains **Concern** until the client records validation. Mismatches remain Concern even after client-validation is selected.

## How to — new analysts

1. Obtain the approved resolver list from the client and enter only IP addresses.
2. Select **Collect Current DNS Configuration**.
3. Review observed, unapproved, and missing resolver addresses.
4. Export the report and send it through the approved client evidence channel.
5. Mark evidence collected after preservation. Mark client validation only after the client confirms scope.
6. Investigate red flags immediately, preserving the source provenance and checking for benign VPN, DHCP, MDM, or network-location explanations.

MSAA does not bundle or claim an authoritative INTERPOL malicious-DNS feed. An administrator may import a bounded, provenance-bearing approved JSON intelligence set. A match is a red flag, not proof of compromise, and must be independently validated.
