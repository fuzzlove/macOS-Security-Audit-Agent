# ClickFix Guard incident response

A Critical ClickFix alert means command-like clipboard content was present during a known social-engineering execution precursor. It does not prove compromise or execution. The analytical disposition is `POTENTIAL_CLICKFIX`.

## User instructions

1. Do not paste or run the clipboard contents.
2. Do not close MSAA.
3. Do not delete browser history, Terminal history, or downloaded files.
4. Disconnect from sensitive systems if organizational policy requires it.
5. Contact the designated incident-response or security team.
6. Provide the MSAA incident identifier.

## Analyst triage

1. Validate the clipboard classification and rule-bundle integrity.
2. Review the redacted preview safely; do not execute or manually decode it on the production endpoint.
3. Preserve an encrypted clipboard artifact only where policy already permits.
4. Review the foreground application as a low-confidence lure-source inference.
5. Review recent browser, download, process ancestry, network, Terminal/interpreter, persistence, credential-access, and security-setting telemetry.
6. Determine whether execution occurred. NSWorkspace launch alone is insufficient; prioritize Endpoint Security execution evidence where available.
7. Isolate the endpoint only when approved policy thresholds are met.
8. Export a signed evidence bundle and retain chain/checkpoint verification results.

The correlated alert remains “Potential ClickFix Execution Chain Observed” until analysts establish an evidence-backed disposition. Acknowledgment records actor, UTC time, and reason; it never deletes or marks the content safe.
