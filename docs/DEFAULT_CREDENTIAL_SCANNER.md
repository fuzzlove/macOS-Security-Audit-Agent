# Default Credential Scanner

MSAA's Default Credential Scanner validates documented vendor-default HTTP
credentials against a list of servers supplied by an authorized operator. It
is a blue-team remediation tool, not a network discovery or password-cracking
feature.

## Operational flow

1. The operator enters explicit `http://` or `https://` URLs. CIDR discovery,
   query strings, embedded credentials, and non-HTTP schemes are rejected.
2. The operator records an authorization reference and acknowledges that the
   test performs real authentication attempts.
3. MSAA checks for Nmap and a locally validated NNdefaccts fingerprint file.
4. A background worker invokes the single Nmap
   `+http-default-accounts` NSE script with a fixed argument vector,
   `shell=False`, one listed host, and one listed port at a time.
5. MSAA parses Nmap XML and retains only structured findings and bounded
   diagnostics. Displayed commands redact the fingerprint storage path.
6. Accepted credentials are encrypted in the scanner-specific SQLite store.
   General MSAA findings contain a redacted reference and never the password.
7. Password reveal and plaintext JSON, CSV, HTML, or TXT export require an
   explicit warning and confirmation. Exports are created mode `0600`.

The leading `+` in the Nmap selector forces only the named script to run when
an authenticated or nonstandard-port service cannot be labeled as HTTP by
version detection. It does not add scripts, targets, ports, or discovery.

## Source and license provenance

The production fingerprint data is downloaded over certificate-verified HTTPS
from [Default HTTP Login Hunter](https://github.com/InfosecMatter/default-http-login-hunter).
The underlying [NNdefaccts](https://github.com/nnposter/nndefaccts) data is
separately licensed from Nmap under GPL v3 or later. MSAA records the source
URL, retrieval time, SHA-256, size, HTTP metadata, and license statement. A
malformed, unexpectedly small, oversized, structurally invalid, or hash-mismatched
dataset does not become ready. Because Lua fingerprints are executable NSE
data, MSAA additionally pins MSAA-reviewed upstream SHA-256 values. An unsigned
upstream change fails closed until its new hash is reviewed and shipped by an
MSAA update; the last validated local copy remains available.

## Harmless acceptance fixture

Run the loopback-only fixture:

```bash
.venv-new/bin/python3 scripts/run_default_credential_test_server.py --port 18080
```

Then scan `http://127.0.0.1:18080/` with authorization reference
`LOCAL-BENIGN-FIXTURE`. The test-only fingerprint is at
`tests/fixtures/default_credentials/http-basic-fingerprints.lua` and recognizes
only this fixture. It accepts `admin/admin` deliberately. Do not deploy the
fixture on a real network.

The automated end-to-end acceptance test is:

```bash
.venv-new/bin/python3 -m pytest -q \
  tests/test_default_credential_scanner.py::test_loopback_fixture_acceptance_with_real_nmap
```

## Limitations

- Coverage depends on the current fingerprint dataset and the product's HTTP
  behavior.
- Authentication attempts may create audit entries or trigger poorly designed
  account-lockout controls.
- A successful login proves exposure at collection time; it does not prove
  compromise, attribution, or previous use.
- Remediation must preserve a recovery path and update dependent integrations
  through the approved secrets-management process.
