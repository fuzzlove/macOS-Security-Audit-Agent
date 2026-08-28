# MacRootKit Defensive Source Review

## Purpose and safety boundary

MSAA reviewed the bundled `MacRootKit` source as hostile research material. The review did not build, load, install, execute, or call the KEXT or its user client. MSAA's resulting checks are read-only and do not unload extensions, patch memory, change boot security, or invoke undocumented kernel interfaces.

The reviewed repository identifies its upstream as `dlevi309/MacRootKit`. The techniques are not proprietary to MSAA or Liquidsky Network Security. MSAA's contribution is the defensive correlation, evidence model, bounded implementation, and operator guidance derived from the review.

This source is a framework/proof of concept with incomplete paths. Its presence in the project is not evidence that the reported long-dormant intrusion used it, and a matching technique does not establish actor or malware-family attribution.

## Source-derived capability map

The relevant source, excluding vendored LLVM, SDK, Capstone, and Keystone material, demonstrates or declares:

| Capability | Source evidence | MSAA defensive signal |
|---|---|---|
| Root-stage KEXT persistence | `OSBundleRequired=Root` | Root-required third-party KEXT context |
| Broad service matching | `IOProviderClass=IOResources` | Broad provider combined with a user client |
| Kernel user-client bridge | `IOKernelRootKitUserClient` | Manifest and runtime IORegistry correlation |
| Unsupported kernel API use | `com.apple.kpi.unsupported` | Unsupported-KPI manifest indicator |
| Kernel and physical memory access | read/write, copyin/copyout, physical and virtual translation selectors | Bounded multi-marker capability group |
| Cross-process task memory | task-for-PID and Mach VM operations | Bounded task-memory capability group |
| Runtime patching | hooks, breakpoints, trampolines, kernel calls | Bounded runtime-patching capability group |
| Kernel address discovery | kernel base, slide, and symbol selectors | Bounded discovery capability group |
| Entitlement interception | hook around `IOUserClient::copyClientEntitlement` | Static extension-interception capability group; runtime confirmation requires deeper endpoint telemetry |
| KEXT load awareness | OSKext and kmod processing | Extension-interception capability group and inventory cross-check |
| Intel and Apple silicon patch mechanics | architecture-specific branch, jump, and breakpoint code | Architecture-independent behavioral grouping |

## Implemented MSAA detections

`mac_audit_agent.rootkit_detection.kernel_surface` adds:

1. Strict, size-bounded plist parsing for non-system KEXT bundles.
2. Combination scoring for root-stage loading, unsupported KPI use, a broad `IOResources` provider, and an exposed `IOUserClient`.
3. A bounded binary marker review with per-file and aggregate byte budgets. A capability group requires multiple markers; one ordinary Mach symbol is insufficient.
4. Exact source-identifier detection for the public bundle and IOService names.
5. Fixed, read-only IORegistry queries for reviewed service classes. MSAA never opens the service or invokes a selector.
6. Integration into the existing Rootkit & Advanced Persistence review, evidence exports, MITRE mappings, and incident guidance.

High severity requires a meaningful combination. A runtime exact service match is critical triage evidence, while static generic capabilities alone remain medium or high depending on loading state and corroboration. Findings explicitly say they are not proof of compromise.

## Incident-response interpretation

If MSAA reports a matching runtime service or a loaded high-risk KEXT combination:

1. Preserve the MSAA evidence package and Apple diagnostics before remediation.
2. Record loaded extensions, hashes, signatures, Team IDs, approval history, and recovery-security posture.
3. Isolate the endpoint under the organization's incident-response policy; avoid abrupt destructive actions that could lose volatile evidence.
4. Compare the KEXT against the approved software inventory and vendor distribution from a trusted system.
5. When kernel compromise remains plausible, acquire evidence from trusted recovery media and treat user-space observations as potentially incomplete.
6. Do not unload an unknown KEXT on a production system without an operational recovery plan.

## Limitations and future telemetry

- Static strings do not prove reachability or malicious intent.
- A renamed, stripped, encrypted, or memory-only implant may evade source identifiers and marker scanning.
- Modern macOS security makes third-party KEXT loading more constrained, but reduced security or previously approved extensions change exposure.
- Shell and user-space inventory can be misleading after kernel compromise. MSAA cross-checks sources but cannot create a tamper-proof boundary from user space.
- Runtime entitlement forgery and individual IOUserClient selector calls are not reliably visible to an ordinary unprivileged application.
- Stronger telemetry may require Apple's Endpoint Security entitlement, managed deployment, a properly approved System Extension/DriverKit architecture, or an established EDR. Endpoint Security alone does not expose every IOKit method call.
- A clean result reduces uncertainty; it does not prove absence of a rootkit or an unreleased exploit.

Future safe work should prioritize signed baselines for third-party KEXTs, offline comparison from recovery, process-view cross-checks using independent sources, and correlation of kernel panic/AMFI/watchdog diagnostics. It must not introduce live kernel probing, memory patching, exploit reproduction, or automatic KEXT removal.
