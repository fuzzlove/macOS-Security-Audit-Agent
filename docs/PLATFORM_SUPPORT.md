# Platform Support

MSAA targets macOS 12 or newer. Native `arm64` and native `x86_64` releases are separate qualified artifacts. Rosetta is detected and reported but is not accepted as native Apple Silicon or Intel release evidence. A universal2 app is release-eligible only when the interpreter and every embedded Mach-O contain both slices.

| Mode | Python | arm64 | x86_64 | Notes |
| --- | --- | --- | --- | --- |
| Doctor/bootstrap | 3.9–3.14 | Tested by CI/probes | Tested by Intel CI | 3.9 is doctor-only |
| CLI | 3.10–3.14 | Supported | Supported | Capability-specific fallbacks apply |
| GUI | 3.10–3.13 | Native PySide6 required | Native PySide6 required | 3.12/3.13 recommended |
| Packaged app | Embedded 3.12 | Native artifact | Native artifact | No external Python/Homebrew |
| Endpoint Security | Embedded signed helper | External entitlement gate | External entitlement gate | Observation-only until installed, entitled, approved |

Doctor distinguishes native hardware, process architecture, Rosetta translation, universal2 interpreter status, permissions, signing-related evidence, and unavailable sensors. Missing capabilities never imply active protection.
