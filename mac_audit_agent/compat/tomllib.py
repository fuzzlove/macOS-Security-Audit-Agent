"""TOML reader compatibility for Python 3.10."""

try:
    from tomllib import TOMLDecodeError, load, loads
except ImportError:  # Python 3.10
    try:
        from tomli import TOMLDecodeError, load, loads
    except ImportError as exc:
        raise ImportError(
            "TOML parsing on Python 3.10 requires the 'tomli' core dependency; "
            "do not install unrelated stdlib backports."
        ) from exc

__all__ = ["TOMLDecodeError", "load", "loads"]
