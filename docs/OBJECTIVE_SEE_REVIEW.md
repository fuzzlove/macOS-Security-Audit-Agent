# Objective-See Review

This review uses Objective-See projects as design inspiration for macOS-native monitoring patterns, not as copy source.

Reviewed projects:

1. [ProcessMonitor](https://objective-see.org/blog/blog_0x47.html)
   - Relevant pattern: Endpoint Security process execution monitoring with process path, arguments, signing info, and parent/child context.
   - Applicable: yes.
   - Adaptation: use native macOS process events or a native helper to normalize process context before alerting.
   - License note: Objective-See source and tools are published under Objective-See repository licenses; do not reuse GPL code unless compatibility is verified and attribution is preserved.

2. [FileMonitor](https://objective-see.org/blog/blog_0x48.html)
   - Relevant pattern: Endpoint Security file event monitoring with source/destination context and process attribution.
   - Applicable: yes.
   - Adaptation: use file-system or Endpoint Security events for persistence and tamper evidence, then feed normalized events into the shared alert pipeline.
   - License note: same as above.

3. [BlockBlock](https://github.com/objective-see/BlockBlock)
   - Relevant pattern: persistence monitoring with user-facing alerts and clear remediation context.
   - Applicable: yes.
   - Adaptation: mirror the persistence alert workflow and provide evidence plus false-positive context.
   - License note: repository indicates GPL-3.0; do not copy code into this project unless compatibility is explicitly handled.

4. [KnockKnock](https://github.com/objective-see/KnockKnock)
   - Relevant pattern: persistence enumeration and comparison against baseline.
   - Applicable: yes.
   - Adaptation: keep baseline-diff style scanning separate from real-time alerts.
   - License note: review repository license before any reuse.

5. [TaskExplorer](https://objective-see.org/products/utilities.html)
   - Relevant pattern: process inspection, signing status, loaded dylibs, open files, and contextual evidence.
   - Applicable: yes.
   - Adaptation: enrich findings with process context and verification steps.
   - License note: use only design ideas, not copied implementation.

6. [OverSight](https://objective-see.org/products/utilities.html)
   - Relevant pattern: camera and microphone awareness with clear user-facing privacy indicators.
   - Applicable: yes.
   - Adaptation: treat confirmed camera/privacy events as high-value alerts with evidence and context.
   - License note: design inspiration only unless specific source licensing is verified.

Summary recommendation:

- Prefer native macOS event sources when available.
- Keep alert rendering separate from event collection.
- Normalize all detector aliases to canonical event types before policy evaluation.
- Preserve evidence and provenance for every alert.
- Make queue/cursor state visible in diagnostics so “one event then stops” can be traced to the exact stage.

Not applicable:

- Direct code reuse from GPL or unknown-licensed Objective-See components without explicit compatibility review.
- Browser history, cookies, or private browsing inspection.
- Offensive or stealth behavior.
