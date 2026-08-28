# DylibHijackScanner review and MSAA adaptation

## Licensing boundary

DylibHijackScanner is GPL-3.0. MSAA independently implements the relevant Mach-O and dyld analysis and does not copy its Objective-C parser or scanner.

## Implemented detection model

The bounded parser supports thin and universal Mach-O files and validates header, architecture, command-count, command-size, and file-size boundaries. It collects `LC_RPATH`, ordinary imports, weak imports, and re-exported libraries.

For executable images, MSAA expands `@executable_path`, `@loader_path`, and `@rpath` without invoking a shell. It reports:

- an active rpath-shadow candidate when multiple existing libraries satisfy one import and dyld chooses an earlier library whose trust does not match the executable;
- a suspicious weak-import library when optional-load behavior is combined with signature or writable-path risk;
- exposure, not active hijacking, when a writable earlier search slot is empty but could shadow the intended library.

Valid hardened-runtime executables with library validation enabled are suppressed from static rpath reporting. Running, unsigned, mismatched-Team-ID, and writable-path evidence raises severity. Findings map to MITRE ATT&CK T1574.006 and explicitly state that the evidence is not confirmation of a rootkit.

Quick rootkit review scans a bounded set of running executable paths. Permission or process-enumeration failures become limitations rather than a clean result. High/critical native sensor events can use `dylib_loaded_from_shadowed_rpath` or `suspicious_dylib_loaded`, normalized to `dylib_hijack_detected` for durable alerting.
