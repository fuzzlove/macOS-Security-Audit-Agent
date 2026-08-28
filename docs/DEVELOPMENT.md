# Native Assurance Development

Build and test with a matching Xcode/Command Line Tools installation:

```text
cd native/MSAAAssurance
swift build
swift test
.build/debug/msaa-verify /path/to/bundle
.build/debug/msaa-verify /path/to/bundle --json
```

Tests and validation must use temporary MSAA-owned fixtures, make no network calls,
and never change security settings. Do not add arbitrary command definitions,
scripting engines, raw telemetry, or private entitlements. The verifier is designed
to operate offline with public material only.
