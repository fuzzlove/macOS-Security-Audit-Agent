# Testing

All malicious-looking commands are inert strings using `example.invalid`. Encoded fixtures decode only to harmless markers and are never executed. Run `python -m pytest -q tests/test_clickfix_shell_guard.py tests/test_clickfix_guard.py`. PTY and shell-framework compatibility must be repeated on each supported macOS/Bash/zsh release before managed block rollout.

The automated suite covers relationship detections, benign single-tool use, Unicode/control normalization, command and decoder bounds, literal gzip and depth-two decoding, JSON privacy, locked concurrent event writes, managed-policy precedence, administrator-only hash exceptions, startup-file preservation, installation validation, adapter lifecycle/integrity events, challenge expiry, raw-terminal restoration, signal-forwarding code paths, and uninstallation. It does not replace interactive qualification of vi/emacs modes, foreground editors, SSH, job control, terminal resizing, or crash recovery across each supported terminal and macOS release.

Validated commands for this implementation pass:

```text
.venv/bin/python -m pytest -q tests/test_clickfix_shell_guard.py tests/test_clickfix_guard.py mac_audit_agent/tests/test_clickfix_guard_ui.py tests/anti_ransomware/test_prototype_system_daemon.py
CLANG_MODULE_CACHE_PATH=/tmp/msaa-clang-cache SWIFTPM_MODULECACHE_OVERRIDE=/tmp/msaa-swift-module-cache swift build --disable-sandbox --package-path native/ClickFixGuard
zsh -n mac_audit_agent/clickfix/shell_integration/msaa-clickfix.zsh
bash -n mac_audit_agent/clickfix/shell_integration/msaa-clickfix.bash
plutil -lint packaging/clickfix/com.msaa.clickfix.plist
```

`swift test` additionally requires an Xcode/Command Line Tools installation containing XCTest that matches the selected SDK.
