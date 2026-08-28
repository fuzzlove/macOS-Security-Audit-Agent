# Stripe Licensing and Distribution

MSAA connects Stripe-hosted Checkout to the existing Ed25519 licensing
boundary. Stripe confirms payment; the separately deployed licensing service
records the paid term; and the desktop exchanges its device-bound activation
code for a signed license. Stripe credentials and the Ed25519 private issuer key
are never embedded in the macOS application.

## Flow

1. The desktop sends its privacy-preserving installation fingerprint to
   `POST /v1/checkout`.
2. The service creates a Stripe Checkout Session for the configured Price and
   returns the hosted Checkout URL plus an inactive, device-bound activation
   code.
3. Stripe sends a signed webhook. The service retrieves the Checkout Session,
   verifies live/test mode, product metadata, payment status, Price ID, and the
   subscription billing period before fulfilling the order.
4. The desktop sends the activation code to `POST /v1/activate` after payment.
   The service returns the same locally verifiable signed-license document used
   by offline licensing.
5. Each `invoice.paid` event extends the paid term. A renewed license is
   distributed the next time the same installation activates. Failed or ended
   subscriptions do not erase an already paid term; access naturally ends at
   the last paid period boundary.

Webhook processing is idempotent. Activation codes are HMAC-authenticated bearer
values and are not stored in plaintext in SQLite. Codes are also bound to the
installation fingerprint captured before Checkout.

The order database contains the pseudonymous installation fingerprint, order
and Stripe object identifiers, fulfillment state, customer name/email returned
by Checkout, paid-through time, and processed event IDs. It contains no payment
instrument data or plaintext Stripe/signing secrets. Set and enforce a retention
period for both the live database and its backups; see [Privacy](PRIVACY.md).

## Stripe setup

1. In Stripe, create the MSAA Product and a recurring monthly Price. Copy the
   `price_...` identifier into `STRIPE_PRICE_ID`. A one-time Price is also
   supported with `MSAA_STRIPE_CHECKOUT_MODE=payment`.
2. Register `https://YOUR_HOST/v1/webhooks/stripe` and subscribe it to:

   - `checkout.session.completed`
   - `checkout.session.async_payment_succeeded`
   - `checkout.session.async_payment_failed`
   - `invoice.paid`
   - `invoice.payment_failed`
   - `customer.subscription.deleted`

3. Copy the endpoint signing secret into `STRIPE_WEBHOOK_SECRET`.
4. Set `MSAA_STRIPE_LIVE_MODE=0` for a Stripe sandbox and `1` only for the live
   endpoint. Events from the wrong mode fail closed.

Stripe recommends webhook-driven fulfillment because redirects are not a
reliable payment signal. The service therefore never activates from the
Checkout success page alone and re-retrieves each Checkout Session before
fulfillment. The service includes informational `/checkout/success` and
`/checkout/cancel` landing pages for the template URLs; neither route changes
an order or issues a license.

## Signing and service configuration

Generate the issuer key on a controlled system using the workflow in
[Product Licensing](PRODUCT_LICENSING.md). Place only the public trust store in
the desktop build. Mount the private PEM into the licensing service at runtime.

Copy [the environment template](../config/stripe-licensing.example.env) to a
secret-managed deployment configuration, fill in the values, and generate the
activation-code secret with a cryptographically secure secret manager or a
command such as `openssl rand -hex 32`. Rotating that secret invalidates
unredeemed activation codes, so back it up separately from the SQLite database.

Install the isolated server dependencies:

```bash
python -m pip install -e '.[licensing-server]'
```

For local-only smoke testing, the included development server binds to loopback:

```bash
set -a
source /secure/path/stripe-licensing.env
set +a
msaa-stripe-licensing --host 127.0.0.1 --port 8787
```

Use a production WSGI server behind an HTTPS reverse proxy for deployment:

```bash
gunicorn --workers 2 --bind 127.0.0.1:8787 \
  'mac_audit_agent.licensing.stripe_service:create_app_from_env()'
```

The reverse proxy should enforce request-rate limits, a bounded request body,
modern TLS, and access logging that excludes request bodies and query secrets.
Back up the SQLite database and keep the service host, database, Stripe secrets,
and signing key out of desktop release artifacts and support bundles.

## Desktop configuration

The signed/notarized desktop distribution includes the Liquidsky public
endpoints. These optional environment variables override them for staging or a
private deployment:

```text
MSAA_LICENSE_CHECKOUT_URL=https://licenses.example.com/v1/checkout
MSAA_LICENSE_ACTIVATION_URL=https://licenses.example.com/v1/activate
```

Demo Preview shows **Buy with Stripe — $10/month**. Clicking the advertisement
creates a device-bound Checkout Session and opens Stripe's hosted page in the
browser. The activation code remains in the licensing panel, and **Activate
Online** verifies and stores the returned signed document. The equivalent CLI
workflow is:

```bash
msaa licensing checkout --json
msaa licensing activate --json
```

The checkout result contains a bearer activation code. Do not place it in shell
history, tickets, analytics, or logs. Omitting `--code` makes activation use a
hidden prompt.

## Test-mode verification

Use the Stripe CLI to forward sandbox events to the local webhook endpoint:

```bash
stripe listen --forward-to 127.0.0.1:8787/v1/webhooks/stripe
```

Use the temporary `whsec_...` value printed by the CLI, a sandbox secret key,
and a sandbox Price. An HTTPS development tunnel is still required for the
desktop checkout endpoint because the production client rejects HTTP and
private hosts. Confirm that duplicate event delivery creates only one order
grant, a wrong Price never fulfills, an unpaid/delayed method remains pending,
and the license verifies against the public key bundled in MSAA.

## Operational limits

- The service does not send email. Stripe can send receipts; MSAA distributes
  the license through its activation endpoint.
- A subscription renewal updates server state. The desktop must activate again
  to receive a license carrying the renewed expiry.
- Cancellation and payment failure do not retroactively revoke time already
  paid for. Keep the signed license duration aligned with the Stripe billing
  period to bound offline access.
- Refunds and disputes require an explicit commercial policy before automated
  revocation is added. They are intentionally not treated as authorization to
  rewrite or delete local security evidence.
- The merchant must expose a Stripe Customer Portal or another clear
  cancellation path and publish the applicable renewal, refund, tax, privacy,
  and support terms before enabling live recurring Checkout.
