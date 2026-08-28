# Apple MDM Deployment

Templates under `packaging/anti_ransomware/mdm` contain placeholders for Team ID, bundle IDs, designated requirements, UUIDs, PPPC/FDA, and managed policy. They are unsigned examples, not production profiles.

Administrators must derive identifiers from the final signed/notarized artifact, review payload support for the managed macOS versions, sign and deploy through authorized MDM, verify local installed state and heartbeats, and document organization-specific PF management allowlists. Apple Business Manager or Apple School Manager enrollment does not itself prove that MSAA permissions are active.
