"""Type-specific IOC aging; hashes outlive shared infrastructure indicators."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

from .models import DefinitionLifecycle, DefinitionType, ThreatDefinition, utc_now

DEFAULT_TTLS = {
    DefinitionType.IPV4: timedelta(days=7), DefinitionType.IPV6: timedelta(days=7),
    DefinitionType.CIDR: timedelta(days=7), DefinitionType.URL: timedelta(days=30),
    DefinitionType.DOMAIN: timedelta(days=45), DefinitionType.HOSTNAME: timedelta(days=45),
    DefinitionType.CERTIFICATE_IDENTITY: timedelta(days=90), DefinitionType.CERTIFICATE_HASH: timedelta(days=365),
    DefinitionType.MD5: timedelta(days=730), DefinitionType.SHA1: timedelta(days=730),
    DefinitionType.SHA256: timedelta(days=1825),
}


def apply_default_expiration(definition: ThreatDefinition) -> ThreatDefinition:
    if definition.expires_at or definition.definition_type not in DEFAULT_TTLS:
        return definition
    baseline = definition.last_seen or definition.first_seen or definition.imported_at
    return replace(definition, expires_at=baseline + DEFAULT_TTLS[definition.definition_type])


def evaluate_lifecycle(definition: ThreatDefinition) -> ThreatDefinition:
    if definition.lifecycle in {DefinitionLifecycle.REVOKED, DefinitionLifecycle.FALSE_POSITIVE, DefinitionLifecycle.DISABLED, DefinitionLifecycle.SUPERSEDED}:
        return definition
    if definition.expires_at and definition.expires_at <= utc_now():
        return replace(definition, lifecycle=DefinitionLifecycle.EXPIRED)
    return replace(definition, lifecycle=DefinitionLifecycle.ACTIVE)


__all__ = ["DEFAULT_TTLS", "apply_default_expiration", "evaluate_lifecycle"]
