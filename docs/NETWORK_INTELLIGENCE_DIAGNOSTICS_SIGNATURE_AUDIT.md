# Network Intelligence Diagnostics Signature Audit

## Failure

Runtime error:

`TypeError: build_network_intelligence_diagnostics() got an unexpected keyword argument 'extra'`

## Function Definition

File: `mac_audit_agent/network_intelligence/diagnostics.py`

Previous signature:

```python
def build_network_intelligence_diagnostics(snapshot=None, *, settings=None)
```

The builder accepted only `snapshot` and `settings`.

## Caller

File: `mac_audit_agent/ui/main_window.py`

`MainWindow.refresh_network_intelligence()` called:

```python
build_network_intelligence_diagnostics(
    snapshot,
    settings=settings,
    extra={
        "db_write_success": "pending",
        "alert_pipeline_success": "...",
        "normalized_event_count": event_count,
    },
)
```

This was the only call site passing `extra`.

## Root Cause

The UI refresh path evolved to add runtime diagnostics metadata, but the diagnostics builder API was not updated. Because the diagnostics generation happened inside the main refresh `try` block, the TypeError made the entire Network Intelligence refresh look failed even though collection may have succeeded.

## Fix

The diagnostics builder now accepts:

```python
def build_network_intelligence_diagnostics(snapshot=None, *, settings=None, extra=None, **kwargs)
```

Behavior:

- `extra` is optional and defaults to `{}`.
- Known `extra` keys are merged into the diagnostics payload.
- Unknown `extra` keys are preserved under `extra`.
- Future unknown kwargs are logged with `NetworkDiagnosticsErrorContext` and ignored safely.
- Snapshot access uses `getattr` where appropriate so partial snapshots degrade gracefully.

## UI Refresh Hardening

`MainWindow.refresh_network_intelligence()` now validates the collector output and isolates diagnostics generation in its own `try` block. If diagnostics generation fails:

- refresh continues
- snapshot is still recorded/rendered
- diagnostics panel shows `Diagnostics failed to generate. See logs.`
- failure context is stored in the snapshot diagnostics

## Regression Coverage

- `test_network_diagnostics_builder_accepts_snapshot_only_and_extra`
- `test_network_diagnostics_builder_ignores_unknown_kwargs_safely`
- `test_network_intelligence_refresh_uses_fallback_when_diagnostics_fail`
