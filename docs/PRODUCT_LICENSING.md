# MSAA Product Licensing Architecture

Status: implemented technical design; production issuer and final commercial
terms require owner and qualified-counsel approval before distribution.

## Security boundary

MSAA verifies license documents locally with Ed25519. Only public verification
keys ship with the product. Private license-signing keys must remain on an
access-controlled offline issuing workstation or an appropriately controlled
signing service and must never enter this repository, an MSAA application
bundle, CI artifact, support archive, or customer endpoint.

The licensing subsystem supports:

- signed offline JSON license import;
- Stripe-hosted Checkout with webhook-driven subscription or one-time-payment
  fulfillment;
- HTTPS online activation that returns the same signed license format;
- privacy-preserving per-installation binding without retaining a hardware
  serial number;
- explicit validity, expiry, device-mismatch, signature, trust-key, and clock
  rollback states;
- centralized feature decisions;
- atomic license storage and a hash-chained administrative audit log;
- a CLI and a non-blocking Settings panel.

## Demo Preview

An installation without a valid signed MSAA license starts in `DEMO_PREVIEW`.
The full navigation and explanatory content remain visible so a prospective
customer can evaluate the product. Passive presentation controls—including
Help, Details, Preview, Next, Previous, and the ClickFix awareness slide
catalog—remain available.

Operational GUI controls are disabled in Demo Preview. This includes scanning,
definition updates, exports, configuration changes, repair, installation,
containment, remediation, evidence capture, and state-changing training
records. Disabled controls explain that a signed offline license is required.
The licensing panel, device-code copy action, signed offline license import,
navigation, scrolling, help, and support links remain available.

The Demo Preview banner advertises the current offer as `$10/month`. When public
checkout and activation endpoints are configured, it opens Product Licensing's
Stripe flow; otherwise it provides the offline contact `pwn@mail.lv`. Pricing
and contact information are presentation metadata only; license validity
continues to be determined exclusively by the signed license document.

Importing a valid offline license or activating a valid Stripe-issued,
correctly device-bound license changes product access to `LICENSED` and restores
the operational controls without restarting MSAA. Invalid, expired, revoked,
wrong-product, or wrong-device documents leave Demo Preview active.

Licensing is not part of MSAA's protection trust boundary. Core protection,
alerting, integrity verification, incident response, and evidence preservation
remain available if a license is missing, invalid, expired, or temporarily
unverifiable. Commercial premium features fail closed.

## Operator workflow

Use a secure workstation outside the source tree to create an issuer key:

```bash
python scripts/msaa-license-authority.py init \
  --private-key /secure/offline/msaa-license-ed25519.pem \
  --public-trust-store /tmp/trusted_license_keys.json \
  --key-id msaa-commercial-2026-01
```

Review the public file, copy it into
`mac_audit_agent/assets/licensing/trusted_license_keys.json`, then rebuild and
sign MSAA. Never copy the private PEM into the project.

On the customer endpoint, obtain the privacy-preserving installation binding:

```bash
msaa licensing device-code --json
```

Issue an offline license on the issuing workstation:

```bash
python scripts/msaa-license-authority.py issue \
  --private-key /secure/offline/msaa-license-ed25519.pem \
  --key-id msaa-commercial-2026-01 \
  --licensed-to "Example Organization" \
  --edition COMMERCIAL \
  --days 365 \
  --device-fingerprint DEVICE_FINGERPRINT \
  --feature commercial_use \
  --feature professional_reports \
  --output /secure/outgoing/example-msaa-license.json
```

The customer imports it in Settings → Product Licensing or with:

```bash
msaa licensing import /path/example-msaa-license.json --json
```

The Stripe service and deployment procedure are documented in
[Stripe Licensing and Distribution](STRIPE_LICENSING.md). Customer builds use
the public Liquidsky checkout and activation endpoints by default;
`MSAA_LICENSE_CHECKOUT_URL` and `MSAA_LICENSE_ACTIVATION_URL` can override them
for staging. The activation endpoint must return a JSON object whose `license`
field contains a correctly signed document. Transport or payment-page success
alone never activates MSAA.

## Commands

```text
msaa licensing status [--json]
msaa licensing device-code [--json]
msaa licensing import LICENSE.json [--json]
msaa licensing checkout [--endpoint HTTPS_URL] [--email EMAIL] [--licensed-to NAME] [--json]
msaa licensing activate [--endpoint HTTPS_URL] [--json]
msaa licensing feature FEATURE [--json]
msaa licensing doctor [--json]
```

The default storage location is:

```text
~/Library/Application Support/MSAA/Licensing/
```

`MSAA_LICENSE_DIR` can select a managed location. Administrators must preserve
restrictive ownership and permissions. The CLI never requires or accepts the
issuer private key.

## Online service contract

The request includes the product identifier, installation fingerprint, a
one-time request nonce, client time, and activation code. The client rejects
plain HTTP, embedded URL credentials, nonstandard ports, unsafe redirects,
private/link-local/loopback destinations by default, invalid TLS, oversized
responses, malformed JSON, and unsigned or untrusted licenses. Activation
codes are not persisted or written to licensing audit records.

The server remains a separately deployed commercial service. This repository
contains the service implementation but no production credentials, issuer
private key, customer database, Stripe account data, or hosted endpoint.

## Release checklist

1. Confirm ownership or relicensing authority for every MSAA-owned file.
2. Complete a third-party dependency and data-license inventory.
3. Have qualified counsel approve the EULA, commercial license, privacy terms,
   export/sanctions terms, warranty limitations, governing law, and transition
   from previously released MIT versions.
4. Provision and back up the private issuer key outside the repository.
5. Add only its public key to the packaged trust store.
6. Configure and test the production HTTPS activation service.
7. Exercise valid, expired, revoked, wrong-device, wrong-product, unknown-key,
   tampered, offline, and service-outage paths.
8. Verify core security and evidence collection remain operational in every
   licensing failure state.
9. Sign, notarize, and integrity-verify the product release.
