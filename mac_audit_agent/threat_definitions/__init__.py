"""Versioned, provenance-preserving threat definition management for MSAA."""

from .local_yara_learning import (
    LocalYaraLearningPolicy,
    learn_local_yara_candidates,
    verify_local_yara_run,
)
from .manager import MalwareDefinitionUpdateManager, ThreatIntelligenceManager
from .models import (
    DefinitionAction,
    DefinitionFreshness,
    DefinitionHealthState,
    DefinitionLifecycle,
    DefinitionTrustLevel,
    DefinitionType,
    ThreatDefinition,
    TrustClass,
)

__all__ = [
    "DefinitionAction",
    "DefinitionFreshness",
    "DefinitionHealthState",
    "DefinitionLifecycle",
    "DefinitionTrustLevel",
    "DefinitionType",
    "LocalYaraLearningPolicy",
    "MalwareDefinitionUpdateManager",
    "ThreatDefinition",
    "ThreatIntelligenceManager",
    "TrustClass",
    "learn_local_yara_candidates",
    "verify_local_yara_run",
]
