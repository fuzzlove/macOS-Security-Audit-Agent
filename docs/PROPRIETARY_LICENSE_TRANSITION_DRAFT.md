# DRAFT — MSAA Proprietary License Transition

This document is a release-planning draft, not approved legal terms and not a
substitute for advice from qualified counsel.

## Existing MIT grants

MSAA source copies already distributed under the MIT License remain available
to their recipients under that license. A future proprietary release does not
retroactively cancel rights already granted for those copies.

Before a proprietary release, Liquidsky Network Security must confirm that it
owns, or has written authority to relicense, all code and other material it
intends to place under proprietary terms. Code, data, rules, fonts, images,
libraries, downloaded feeds, and tools governed by third-party terms remain
under those terms and must retain required notices and source/offer obligations.

## Proposed future-release model

For a specifically identified future MSAA release, counsel-approved terms are
expected to define:

- the exact legal licensor entity and contact information;
- editions, authorized installations, users, term, maintenance, support, and
  commercial-use grants;
- evaluation and research rights, if offered;
- restrictions on redistribution, sublicensing, circumvention, resale, and
  misuse while preserving applicable non-waivable rights;
- ownership and feedback provisions;
- activation, privacy, diagnostic, and offline-use behavior;
- suspension, termination, cure, and evidence-preservation behavior;
- warranty disclaimer, liability allocation, indemnity if applicable, export
  and sanctions compliance, governing law, venue, and order of precedence;
- treatment of open-source and other separately licensed components.

The package metadata for that approved distribution should use a custom SPDX
license reference such as `LicenseRef-MSAA-Proprietary`, and include the final
license file. It must not be changed while the distributed archive still
contains files that cannot truthfully be covered by that single expression.

## Current repository state

The current `1.0b0` development tree continues to declare MIT while the legal
transition is reviewed. The signed activation implementation can be tested now,
but activation alone does not remove MIT rights or create enforceable commercial
terms. Do not publish a proprietary artifact until the release checklist in
`docs/PRODUCT_LICENSING.md` is complete.
