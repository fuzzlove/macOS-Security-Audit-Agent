# ClickFix Guard permissions and deployment

Input Monitoring, Accessibility, clipboard access state, and notification authorization are tracked independently. Observe Mode needs Input Monitoring to receive the physical chord. Protect Mode needs Input Monitoring plus Accessibility for active interception and synthetic replay. Clipboard denial, prompt-required state, timeout, or unknown access produces a High unknown-safety event. Notification denial does not remove the in-app Critical alert.

Use the ClickFix Guard page buttons to open System Settings > Privacy & Security > Input Monitoring or Accessibility. Grant access to the signed `MSAA ClickFix Guard` component, not to a Python interpreter. Permission changes may require restarting the LaunchAgent. The agent remains per-user and must not run at the login window or as root.

Build and signing requirements:

- Developer ID Application identity with the approved MSAA Team Identifier.
- Stable IDs `com.macos-security-audit-agent.clickfix-guard` and `com.macos-security-audit-agent.clickfix-guard.xpc`.
- Hardened runtime, library validation, no JIT, no unsigned executable memory.
- Universal arm64/x86_64 build, sealed resources, notarization, and stapling.
- LaunchAgent installed in `~/Library/LaunchAgents`, limited to Aqua, with the Mach service declared.
- Agent and GUI code signatures must have the same Team Identifier; XPC also restricts the signing-identifier namespace.
- Production rule bundles must be signed offline and replace the development trust root. No private signing key belongs in the product.

No private entitlement grants Input Monitoring or Accessibility; macOS TCC user/MDM approval controls them. Endpoint Security containment separately requires Apple’s restricted `com.apple.developer.endpoint-security.client` entitlement and an approved system extension. This agent does not claim that entitlement.
