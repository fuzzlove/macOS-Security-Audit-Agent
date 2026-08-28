# KextViewr review and MSAA rogue extension evolution

## Source and licensing boundary

The added KextViewr tree does not contain an explicit open-source license file. MSAA therefore treats it as an architectural reference only and does not copy its Objective-C implementation.

## Useful historical design

KextViewr evolved from legacy `kextstat` enumeration to collection-aware `kmutil showloaded` queries. It separately requests Boot, System, and Auxiliary collections and displays bundle identity, resolved bundle path, load address, size, architecture, and collection. Search by Apple/non-Apple origin, path, bundle ID, collection, address, and architecture is useful for analyst review.

## Modern limitations corrected in MSAA

- Boot/System collection membership is context, not cryptographic proof of Apple origin.
- Auxiliary collection membership is expected for approved third-party kexts and is not inherently suspicious.
- Kernel extensions are only part of current coverage; System Extensions, Endpoint Security extensions, Network Extensions, and DriverKit `.dext` bundles also matter.
- A bundle identifier must come from `Info.plist`, not just a filename or a loosely matched command line.
- Loaded inventory needs cross-checking against on-disk bundles and vice versa.
- Trust requires signature/Team ID, ownership, permissions, executable presence, approval provenance, and baseline context.

## Implemented MSAA improvements

MSAA now queries all available kernel collections with a generic `kmutil showloaded` fallback, retains collection/address/architecture metadata, inventories current extension locations, parses bundle metadata, resolves declared executables, verifies strict code signatures, captures Team IDs, and merges loaded and filesystem visibility sources.

Modern sealed-system kext stubs under `/System/Library/Extensions` may intentionally contain metadata without a standalone executable and can report as unsigned to `codesign` because executable code resides in a protected kernel collection. MSAA marks these filesystem stubs as `platform_protected` instead of generating hundreds of unsigned or missing-executable false positives; loaded collection visibility remains a separate signal.

Risk flags cover invalid/unsigned signatures, missing executables or invalid plists, non-root ownership in privileged locations, group/world-writable bundles, unusual writable locations, and loaded non-Apple bundle IDs without a matching on-disk bundle in the bounded inventory. Findings continue to say that a rogue module is suspected—not that a rootkit is confirmed.

Native helpers may emit `kernel_extension_loaded` or `kext_loaded` metadata events, normalized by MSAA to the existing suspicious-kernel-extension security event. Removal remains vendor-supported and confirmation-gated; MSAA does not unload kernel modules automatically.
