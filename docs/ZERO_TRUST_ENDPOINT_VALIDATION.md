# Zero Trust Endpoint Validation

Every Zero Trust control has an automatic route, a manual verification route, and explicit evidence fields. Missing telemetry remains **Not validated**. A positive adverse observation remains **Concern**. Selecting **Evidence: collected** records an assessor assertion and timestamp in the MSAA monitor event log; it does not itself change the technical result to Validated.

| Control | Automatic validation | Manual validation and evidence |
|---|---|---|
| FileVault enabled | Bounded `/usr/bin/fdesetup status` collection | Open Zero Trust **How to Verify** or Persistence Intelligence. Confirm FileVault is enabled for the startup disk and preserve state, collector result, and observation time. Never collect a recovery key. |
| Secure Boot verified | Bounded `/usr/sbin/system_profiler SPHardwareDataType -json`; only an explicit Secure Boot field is accepted | Review the Mac's Startup Security/boot policy using the approved Apple workflow. Record hardware support, boot policy, collection time, and any unavailable telemetry. Authenticated root alone is not treated as Secure Boot proof. |
| SIP enabled | Bounded `/usr/bin/csrutil status` collection | Review System Integrity Protection in Persistence Intelligence and confirm current enabled status. Preserve state, collector result, and time. |
| Firewall enabled | Bounded `socketfilterfw --getglobalstate` collection | Open Firewall Status. Confirm application-firewall state and separately review PF state and exceptions. |
| Unsigned/unknown-developer applications | Not Signed software-provenance inventory and deterministic classification counts | Open Not Signed, review path, hash, Team ID, signing identifier, notarization, and errors. Export selected evidence or **Export All Running Software**. Unknown provenance is not proof of malware. |
| Running processes | Not Signed correlates processes with owning software and signing evidence | Use Not Signed > Running Processes. Export the complete running-software report and investigate unresolved identity. |
| Persistence | Registered persistence inventory | Review each launch, login, scheduled, SSH, and automation entry against the approved baseline. |
| DNS and outbound connections | Network Intelligence refresh and deterministic risk/provenance correlation | Compare DNS, gateway, VPN, proxy, destinations, ports, and owning processes with client policy. Export evidence for client review. |
| Unvalidated network connections | Network Monitor refresh identifies connections lacking sufficient owner/provenance evidence | Review every connection in Network Monitor and Network Intelligence. Correlate PID/path with Not Signed, export evidence, and obtain client confirmation that endpoints and purposes are approved for scope. The control remains Concern until that validation is represented in authoritative evidence. |

The event log records state changes between `not collected` and `collected`, including control identifier, timestamp, previous state, authoritative view, and a qualification that this is an assessor assertion rather than independent proof.

## Evidence pacing safeguard

By default, marking four distinct controls collected within 120 seconds creates a high-severity review event and asks the assessor to explain the workflow. This accommodates legitimate end-of-assessment checkoff while preserving an accountable timing signal. The event is not proof of negligence or invalid evidence and does not automatically fail controls. Reviewers should compare the explanation with exported artifacts, original collection timestamps, and client validation.
