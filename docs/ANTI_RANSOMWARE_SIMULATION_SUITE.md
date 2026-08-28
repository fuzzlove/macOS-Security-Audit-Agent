# Safe Anti-Ransomware Simulation Suite

The Simulation Lab under **Anti-Ransomware** contains 24 deterministic,
attack-shaped scenarios plus four benign negative controls. They evaluate
MSAA's built-in behavioral definitions in memory and show the exact signal IDs,
score, confidence, severity, risk state, expected outcome, and recommended
response.

| ID | Scenario | Principal definitions |
|---|---|---|
| AR-SIM-01 | Rapid write and entropy burst | `synthetic_write_burst`, `high_entropy_transition` |
| AR-SIM-02 | Encrypted-extension replacement | `high_entropy_transition`, `extension_changed`, `rename_over_original` |
| AR-SIM-03 | Original deleted after rewrite | `high_entropy_transition`, `original_deleted`, `synthetic_write_burst` |
| AR-SIM-04 | Protected canary changed | `protected_canary_modified`, `high_entropy_transition` |
| AR-SIM-05 | Ransom-note pattern after write burst | `ransom_note_pattern`, `synthetic_write_burst` |
| AR-SIM-06 | Snapshot deletion intent plus writes | `snapshot_deletion_attempt`, `synthetic_write_burst` |
| AR-SIM-07 | Backup targeting with replacement | snapshot, entropy, and original-deletion correlation |
| AR-SIM-08 | Protection service impairment | `protection_service_impairment`, `synthetic_write_burst` |
| AR-SIM-09 | Protection impairment and canary change | service impairment and protected-canary correlation |
| AR-SIM-10 | Evidence tamper and entropy rewrite | `protection_or_evidence_tamper`, `high_entropy_transition` |
| AR-SIM-11 | Integrity tamper and ransom note | tamper, write-burst, and note-pattern correlation |
| AR-SIM-12 | Atomic replacement chain | entropy, extension, deletion, and rename-over-original |
| AR-SIM-13 | Canary and ransom-note correlation | `protected_canary_modified`, `ransom_note_pattern` |
| AR-SIM-14 | Large-file bounded analysis | `large_file_sampled`, entropy, and write-burst correlation |
| AR-SIM-15 | Approved maintenance still correlated | reduced snapshot signal plus burst and note context |
| AR-SIM-16 | Multi-stage ransomware composite | protection impairment, snapshots, canary, and entropy |
| AR-SIM-17 | Rename-delete encryption chain | entropy, extension, deletion, and rename-over-original |
| AR-SIM-18 | Canary, note, and write wave | rapid writes, protected canary, and note pattern |
| AR-SIM-19 | Backup and protection suppression | snapshot deletion and protection impairment |
| AR-SIM-20 | Evidence tamper before replacement | evidence tamper and high-entropy atomic replacement |
| AR-SIM-21 | Extension wave and ransom note | write burst, extension change, and note pattern |
| AR-SIM-22 | Large-file replacement chain | bounded sampling, entropy, deletion, and replacement |
| AR-SIM-23 | Snapshot and evidence destruction | backup targeting and evidence tamper |
| AR-SIM-24 | Full defensive stress chain | write, backup, service, canary, entropy, and note signals |
| AR-CTRL-01 | Ordinary extension rename | must remain below escalation threshold |
| AR-CTRL-02 | Approved snapshot maintenance | must remain below escalation threshold |
| AR-CTRL-03 | Isolated note-like filename | must remain below escalation threshold |
| AR-CTRL-04 | Large pre-compressed file sample | must not look like a new entropy transition |

The suite intentionally performs none of the modeled operations. Command
observations are data objects passed to `sabotage_signals`; they are not sent to
a shell or subprocess. File transitions are metadata/statistics objects passed
to `transition_signals`; no user file is opened or changed.

The negative controls are part of the pass gate. A complete pass requires all
24 attack-shaped scenarios to be caught and all four benign controls to remain
below their maximum score. A detector that simply labels every file event as
ransomware therefore cannot pass the demonstration.

## What a pass proves

A pass proves that the checked-in behavior-definition functions produced every
required signal and that the explainable risk engine met the scenario's minimum
score. The report stores the rule source, required and observed signals,
ruleset version, catalog SHA-256, and complete safety declaration.

A pass does **not** prove:

- that Endpoint Security delivered a live event;
- that Full Disk Access or process attribution is available;
- that production containment works;
- that a current external YARA rule or malware hash matched;
- that every ransomware family or novel behavior will be detected.

Use **Run Harmless Detection Test** separately to validate bounded disposable
filesystem activity and development-observer visibility. Review **Sensor
Health** for live coverage and **Malware Definitions** for the active YARA/hash
release.

## Challenge-bound live fixture suite

The harmless live test exercises 12 bounded stages inside one randomly named,
marked disposable directory: rapid creation, entropy rewrite, rename,
synthetic extension changes, nested writes, atomic replacement, truncation and
rewrite, a benign note marker, canary modification, disposable deletion,
hidden-file rewrite, and a known benign test-hash path. The installed observer
must return a SHA-256 challenge receipt for every stage. A generic timestamp or
unrelated filesystem event cannot make the test pass.

The System Monitor heartbeat must also be fresh. A database row that still says
`running` after the daemon exits is reported as stale and the live test remains
inconclusive. All fixture paths are removed automatically; receipts retain only
the random challenge hash, stage, operation, and observation time.

## Safe YARA validation

The Simulation Lab also provides **Run 20 Safe YARA Tests**. This is separate
from the behavioral scenarios and live filesystem stages. It runs entirely in
memory and covers:

- exact, nocase, wide, hexadecimal, regular-expression, and file-size matching;
- multi-string thresholds and high-specificity all-signal conditions;
- benign shell, plist, and synthetic Mach-O contexts;
- near-miss, partial-signal, and ordinary-document negative controls;
- malformed-rule compilation rejection;
- duplicate rule names isolated across namespaces;
- include-directive, unsupported-module, and within-package duplicate rejection.

This proves that the local YARA engine and MSAA rule-safety gates behave as
expected. It does not claim coverage of every ransomware family. The active
external release remains a separate validation target.

## CLI

```bash
.venv-new/bin/python3 -m mac_audit_agent.anti_ransomware.cli \
  simulate --safe --no-file-destruction --profile definition-suite --json
```

Run the installed-observer validation separately:

```bash
.venv-new/bin/python3 -m mac_audit_agent.anti_ransomware.cli \
  test --safe --profile live-fixture-suite --json
```

Run the 20 in-memory YARA controls:

```bash
.venv-new/bin/python3 -m mac_audit_agent.anti_ransomware.cli \
  simulate --safe --no-file-destruction --profile yara-definition-suite --json
```

Run the six-case signature-independent adaptive detector demonstration:

```bash
.venv-new/bin/python3 -m mac_audit_agent.anti_ransomware.cli \
  simulate --safe --no-file-destruction --profile adaptive-unsigned-suite --json
```

This covers unsigned-only behavior, an entropy wave, a correlated ransomware
chain, equivalent behavior from signed software, partial sensor coverage, and a
baseline rate deviation without encryption evidence. Unsigned status alone must
not pass as ransomware, and partial coverage must disable automatic response.

Run the dedicated 20-case adaptive ransomware action suite:

```bash
.venv-new/bin/python3 -m mac_audit_agent.anti_ransomware.cli \
  simulate --safe --no-file-destruction --profile adaptive-action-suite --json
```

The action suite independently tests distinct-file entropy, rename fanout,
deletion fanout, directory and volume spread, write volume, canary changes,
ransom-note sequencing, unsigned and first-seen context, signed and notarized
attack behavior, interpreter-attributed scripts, incomplete telemetry, baseline
cold start, low-and-slow activity, and duplicate-event replay resistance. Every
case is metadata-only and records that no containment was performed.

With administrator authorization, compile and sanity-test the active immutable
YARA release separately:

```bash
sudo -- .venv-new/bin/python3 -m mac_audit_agent.anti_ransomware.cli \
  simulate --safe --no-file-destruction --profile active-yara-release --json
```

The active-release test reports its release, manifest reference, loaded rule
count, compiled namespace count, and unexpected matches against four bounded
benign controls. It does not export fixture contents or scan arbitrary user
files.

The safety flags are mandatory. The JSON report can also be exported from the
Simulation Lab. GUI exports are written with mode `0600`.
