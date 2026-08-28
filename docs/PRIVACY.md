# Privacy

## Native assurance evidence

The native assurance package is local-only and makes no network requests. Evidence
contains allowlisted system metadata and pseudonymous host identifiers, not raw file
contents, credentials, tokens, environment dumps, browsing, email, clipboard,
keystrokes, screen content, or user document content. Export is an explicit user
action. Unexpected command output is bounded and redacted rather than persisted or
logged. No telemetry or analytics SDK is included.

## Local-Only Model

Mac Audit Agent stores data locally on the Mac by default.

The operational classification, RBAC, retention, export, audit, and privacy-impact rules are documented in [DATA_GOVERNANCE.md](DATA_GOVERNANCE.md). Unknown data types and external operational-data processing fail closed.

## Optional Purchase and Licensing

Security findings, evidence, inventories, and monitoring telemetry are never
sent to Stripe or the licensing service. When a user explicitly starts online
checkout, MSAA sends only its product identifier, a pseudonymous per-installation
fingerprint, a request nonce, and any customer email or display name the user
chooses to provide. Stripe separately processes the payment and billing details
entered into Stripe-hosted Checkout under the merchant's configured Stripe
terms and privacy disclosures.

The MSAA licensing service stores the order identifier, installation
fingerprint, fulfillment state, customer name/email returned by Checkout,
Stripe Customer/Subscription/Checkout identifiers, paid-through timestamp, and
processed webhook event identifiers. It does not store card or bank-account
details, the Stripe secret key, webhook secret, private signing key, or plaintext
activation codes in the order database. Service operators must define retention
and deletion periods for commercial records and protect or purge backups on the
same schedule. Offline licensing remains available when online processing is not
appropriate.

## Not Collected

- browser history
- private browsing state
- cookies
- passwords
- tokens
- keychains
- screen contents
- audio contents
- packet contents

## Redaction Support

The app supports redaction for:

- usernames
- IP addresses
- MAC addresses
- hostnames
- filesystem paths
- URL secrets

## Reports

Reports may contain sensitive system information. Export only what you are comfortable sharing, and use redaction when appropriate.

Sensitive and restricted exports additionally require an authorized role, explicit approval and destination, and verified protection evidence. Filesystem permissions are not represented as encryption.

## External Data

Apple advisory and CVE enrichment uses public sources. The app should not submit private local inventories to external services.
