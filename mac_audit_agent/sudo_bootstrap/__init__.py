"""Standard-library-only sudo bootstrap support.

This package must remain safe to import before GUI, database, or monitoring code.
"""

from .identity import InvokingUser, InvocationMode, IdentityError, resolve_invocation
from .result import BootstrapResult, BootstrapErrorCode

__all__ = ["BootstrapErrorCode", "BootstrapResult", "IdentityError", "InvocationMode", "InvokingUser", "resolve_invocation"]
