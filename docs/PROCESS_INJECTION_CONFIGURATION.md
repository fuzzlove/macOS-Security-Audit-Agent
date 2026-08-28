# Process Injection Configuration

The RCE configuration controls injection correlation window, novelty/similarity thresholds, evidence tier, Tier 2 authorization, maximum evidence size, encryption requirement, protected categories, ATT&CK path/freshness, queue bounds, retention, redaction, and management UIDs.

Defaults are high sensitivity, monitor-only, Tier 0/1 metadata, Tier 2 disabled, no process termination/suspension/blocking, local approved ATT&CK data only, and root-authorized mutation. Invalid configuration is rejected without replacing last-known-good state. Configuration changes generate evidence.
