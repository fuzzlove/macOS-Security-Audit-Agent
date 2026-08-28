# ClickFix Guard High Assurance policy

`DISABLED` installs no active event tap. `AUDIT` records and inspects but hides routine Medium popups unless enabled. `WARN` uses a listen-only tap and shows every required Medium/Critical alert. `PROTECT` suppresses the original chord, replays only after safe persistence, and does not replay risky content. `HIGH_ASSURANCE` adds fail-closed unavailable handling, visible quarantine enablement, mandatory Critical acknowledgment, extended retention, incident-response notification, and optional entitled Endpoint Security containment.

High Assurance must report degraded—not protected—when the native agent, event tap, Input Monitoring, same-Team XPC authentication, or signed classifier bundle is unavailable. Invalid proprietary rules never become a clean result: generic static classification continues, a health alert is written, and risky/unavailable shortcuts remain suppressed. Accessibility loss disables reliable replay. Notification loss never dismisses in-app Critical state.

No user bypass is permitted without an authenticated justification record. Containment leases are audit-session scoped, expire automatically, and may deny only high-confidence matching executions within Endpoint Security response deadlines. Global Terminal blocking and permanent deny rules are prohibited. If the ES sensor disconnects, MSAA must record the loss and must not claim a block.

The repository ships containment integration boundaries but no enabled ClickFix ES authorization policy because an Apple-approved entitlement and organization-specific release signing are external gates. Deployments must keep `CLICKFIX_EXECUTION_CONTAINMENT` off until those gates and disposable-host tests pass.
