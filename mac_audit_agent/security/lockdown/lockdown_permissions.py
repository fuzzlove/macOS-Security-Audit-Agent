from __future__ import annotations

import os
from dataclasses import asdict, dataclass

CONFIRMATION_PHRASE = "ENABLE MSAA EMERGENCY PROTECTION"


@dataclass(frozen=True)
class ActivationAuthorization:
    operator: str
    incident_reason: str
    ticket_number: str
    confirmed: bool
    confirmation_phrase: str
    effective_uid: int

    def validate(self, *, require_root: bool = True) -> None:
        if not self.confirmed or self.confirmation_phrase != CONFIRMATION_PHRASE:
            raise PermissionError("LOCKDOWN_AUTH_CONFIRMATION_REQUIRED: explicit warning acknowledgement and exact confirmation phrase are required.")
        if not self.operator.strip() or not self.incident_reason.strip() or not self.ticket_number.strip():
            raise PermissionError("LOCKDOWN_AUTH_FIELDS_REQUIRED: operator, incident reason, and ticket number are required.")
        if require_root and self.effective_uid != 0:
            raise PermissionError("LOCKDOWN_ADMIN_REQUIRED: activation changes protected macOS configuration and must run through an administrator-approved root workflow.")

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload.pop("confirmation_phrase", None)
        return payload


def authorization(operator: str, reason: str, ticket: str, confirmed: bool, phrase: str) -> ActivationAuthorization:
    return ActivationAuthorization(operator, reason, ticket, confirmed, phrase, os.geteuid())
