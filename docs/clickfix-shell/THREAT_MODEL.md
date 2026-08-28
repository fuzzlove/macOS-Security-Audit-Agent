# Threat Model

Covered threats include retrieval/decoding into interpreters, clipboard-to-interpreter chains, staged temporary execution, AppleScript shell execution, trust weakening, persistence, credential-output relationships, obfuscation, and auto-submitting pasted newlines.

Shell startup files can be bypassed or modified. Noninteractive scripts, GUI-launched commands, Script Editor, URL-scheme execution, terminals configured to skip startup files, and a compromised account may bypass shell enforcement. Endpoint Security requires appropriate signing and entitlement. User education, browser filtering, EDR, DNS/network controls, least privilege, and application trust remain necessary.
