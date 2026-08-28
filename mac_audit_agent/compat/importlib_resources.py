"""Resource API that prefers the standard library and degrades explicitly."""

try:
    from importlib.resources import as_file, files
except ImportError:  # pragma: no cover - Python older than the supported range
    from importlib_resources import as_file, files

__all__ = ["as_file", "files"]
