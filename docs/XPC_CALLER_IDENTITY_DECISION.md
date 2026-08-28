# XPC Caller Identity Decision

Selected transport: public low-level XPC listener/session APIs on macOS 14.4 or later. The listener applies `xpc_listener_set_peer_code_signing_requirement` before activation. Each received dictionary is independently resolved with public `SecCodeCreateWithXPCMessage` and checked against the same helper-owned requirement using `SecCodeCheckValidity`.

The SDK 15.5 headers declare both selected APIs. A native probe compiles, links and runs. No public raw caller-audit-token accessor was found for the selected listener/session API in these SDK headers. Raw caller audit-token extraction is therefore not claimed. It is not necessary for caller code authentication when both listener enforcement and message-bound dynamic-code validation succeed; target-process audit tokens remain separate and mandatory for containment identity.

Minimum active-containment helper OS is macOS 14.4. Older systems remain observation-only. Replays are controlled by connection-bound nonces, expiry, boot session and idempotency. Residual risk is that live signed-engine/XPC validation still requires installed Developer-ID artifacts. Private Foundation properties, KVC, selectors, `dlsym`, undocumented declarations and manual audit-token byte parsing are rejected.

External XPC security-engineer review and live wrong-client tests remain required before this blocker closes.
