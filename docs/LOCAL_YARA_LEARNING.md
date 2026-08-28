# Local YARA Learning

MSAA can turn a locally held, pre-classified sample corpus into **review-only**
YARA and SHA-256 candidates. The workflow is offline, explainable, and does not
execute sample content.

## Safety boundary

The learner treats every corpus file as untrusted data. It does not import,
launch, mount, extract, unpack, or upload samples. It reads bounded byte windows
for printable-string features and streams the complete file only to calculate
SHA-256. Symlinks, non-regular files, empty files, oversized files, and output
paths inside the corpus are rejected or skipped.

The family name is derived from the sample's top-level corpus directory, but it
is retained only as an analyst-provided label. It is not independently verified.
Absolute and relative sample paths are not written to the manifest.

## Explainable model

Model `explainable-string-tfidf-jaccard-1.0` uses:

1. Jaccard similarity to form related groups within an analyst-labelled family.
2. Family prevalence and inverse-document-frequency scoring to identify stable,
   discriminating strings.
3. Cross-family prevalence limits to remove broadly shared features.
4. Optional known-good corpus features and compiled-rule negative controls to
   reduce false positives.

Each candidate records the selected features, feature scores, source sample
references, sample count, confidence, model version, and exact generated-rule
hash. This is statistical learning, not a claim that the family label or
malicious intent has been proven.

## Candidate classes

- `DEFINITION_CANDIDATE`: at least two related samples and at least three stable
  distinguishing features.
- `SUSPICIOUS_CANDIDATE`: weaker coverage, normally a single sample or fewer
  stable features.
- `LOCAL_UNVERIFIED_CORPUS`: exact SHA-256 of a local sample. It remains inactive
  because the sample's origin and label have not been independently verified.

All output includes `review_required=true` and `automatically_active=false`.
There is intentionally no automatic promotion path.

## Desktop workflow

Open **Malware Definitions → Local YARA Learning Lab**, select `Malware-main`,
and choose **Build Review Candidates**. Processing runs outside the GUI thread.
Every immutable run is stored under:

```text
~/Library/Application Support/MSAA/YaraCandidates/local-<timestamp>-<id>/
├── manifest.json
├── local-corpus-sha256.jsonl
└── candidates/
    └── local-yara-*.yar
```

Active definitions are not modified.

## CLI

```bash
.venv-new/bin/python3 -m mac_audit_agent.cli definitions \
  learn-local-yara Malware-main --json
```

Use a separate known-good corpus as negative control data:

```bash
.venv-new/bin/python3 -m mac_audit_agent.cli definitions \
  learn-local-yara Malware-main \
  --benign-corpus /path/to/known-good-macos-files \
  --maximum-files 2500 \
  --sample-bytes 2097152 \
  --json
```

Review candidates against representative clean macOS and application files,
inspect the selected strings, verify provenance, and run MSAA's YARA validation
suite before any separately authorized promotion into `definitions/custom/`.

Verify the immutable review bundle at any time:

```bash
.venv-new/bin/python3 -m mac_audit_agent.cli definitions \
  verify-local-yara "/path/to/local-<timestamp>-<id>" --json
```

## Operational limitations

String-based learning is deliberately transparent and conservative. Packed,
encrypted, or heavily obfuscated samples may yield no reliable rule. Containers
are not unpacked, so the learner sees only their on-disk bytes. A candidate with
high statistical confidence can still be wrong; confidence is not severity or
proof of malware.
