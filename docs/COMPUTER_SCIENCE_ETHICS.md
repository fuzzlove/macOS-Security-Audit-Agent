# One-Time Computer Science Ethics Class

MSAA requires each local macOS user to pass a basic computer science ethics class before that user can review and accept the EULA. The EULA remains a separate mandatory per-launch gate. Neither passing the class nor accepting the EULA grants authorization to inspect or affect any target.

The curriculum covers authorization and scope, avoiding harm, privacy and data minimization, uncertainty and validation, human accountability, evidence preservation, rollback, and the effects computers can have on individuals and essential services. Six questions require a score of 100%. Incorrect answers can be reviewed and retried; MSAA does not persist individual answers.

## Startup sequence

1. Present the existing one-time non-binding startup preview when necessary.
2. If no valid local ethics completion exists, present the class and assessment.
3. Refuse application access and EULA acceptance until the assessment passes.
4. Cache the versioned passing record for that pseudonymous local user.
5. Present the complete EULA on every launch, including the launch where the ethics class was passed.
6. After the application database opens, mirror the pending completion into the existing monitor-event stream.

## Local records

- Completion cache: `~/.mac_audit_agent/governance/ethics-completion.json`
- Append-only logical event log: `~/.mac_audit_agent/governance/ethics-events.jsonl`
- Monitor event type: `governance_ethics_class_passed`

Directories use mode `0700` and files use mode `0600`. Records contain the curriculum version and SHA-256 digest, timestamp, score percentage, application version, and a local UID-derived pseudonymous reference. They explicitly state that answers were not recorded and authorization was not granted.

The local cache is permission-restricted but is not hardware-attested or tamper-proof. If the cache is missing, malformed, belongs to another local user, or does not match the supported curriculum record, MSAA safely requires the class again. An administrator controlling the account or filesystem may alter local state.

Passing records only that the user demonstrated the basic concepts in this assessment at that time. It does not establish ethical character, predict future conduct, certify professional competence, replace training required by an employer, or prove that a later action was authorized or appropriate.
