"""Small dependency-free bridge for foregrounding source-launched Qt on macOS."""

from __future__ import annotations

import ctypes
import os
import sys


def activate_as_regular_application() -> tuple[bool, str]:
    if sys.platform != "darwin":
        return False, "not macOS"
    if os.environ.get("QT_QPA_PLATFORM", "").lower() in {"offscreen", "minimal"}:
        return False, "non-native Qt test backend"
    try:
        objc = ctypes.cdll.LoadLibrary("/usr/lib/libobjc.A.dylib")
        objc.objc_getClass.restype = ctypes.c_void_p
        objc.objc_getClass.argtypes = [ctypes.c_char_p]
        objc.sel_registerName.restype = ctypes.c_void_p
        objc.sel_registerName.argtypes = [ctypes.c_char_p]
        send = objc.objc_msgSend
        send.restype = ctypes.c_void_p
        send.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

        application_class = objc.objc_getClass(b"NSApplication")
        shared_selector = objc.sel_registerName(b"sharedApplication")
        application = send(application_class, shared_selector)
        if not application:
            return False, "NSApplication unavailable"

        set_policy = objc.sel_registerName(b"setActivationPolicy:")
        send.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_long]
        policy_changed = bool(send(application, set_policy, 0))  # NSApplicationActivationPolicyRegular

        activate = objc.sel_registerName(b"activateIgnoringOtherApps:")
        send.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_bool]
        send(application, activate, True)
        return True, "regular policy requested" if policy_changed else "regular policy already active; activation requested"
    except (AttributeError, OSError, TypeError, ValueError) as exc:
        return False, f"{type(exc).__name__}: {exc}"


__all__ = ["activate_as_regular_application"]
