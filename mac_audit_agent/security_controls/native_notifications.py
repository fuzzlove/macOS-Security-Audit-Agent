from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class NotificationResult:
    requested: bool
    accepted: bool
    error_code: str
    delivery_guaranteed: bool = False


class MacOSUserNotificationBridge:
    """UserNotifications bridge. Canonical events always remain in MSAA."""
    def __init__(self,privacy_safe:bool=True)->None:self.privacy_safe=privacy_safe

    def authorization_status(self)->str:
        try: import UserNotifications  # type: ignore[import-not-found] # noqa:F401
        except ImportError:return "bridge_unavailable"
        return "authorization_query_required"

    def request(self,*,event_id:str,severity:str,title:str,body:str)->NotificationResult:
        try:
            import UserNotifications  # type: ignore[import-not-found]
        except ImportError:
            return NotificationResult(False,False,"USER_NOTIFICATIONS_BRIDGE_UNAVAILABLE")
        # PyObjC callbacks require an active Cocoa run loop. The application
        # integration injects the approved dispatcher; headless code fails
        # explicitly instead of pretending presentation succeeded.
        return NotificationResult(False,False,"USER_NOTIFICATIONS_DISPATCHER_NOT_CONNECTED")
