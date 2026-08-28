from __future__ import annotations

from dataclasses import dataclass, replace

from mac_audit_agent.telemetry.models import NormalizedTelemetryEvent


@dataclass(frozen=True)
class WorkstationProfile:
    """Declared device role used alongside, never instead of, the local baseline."""

    name: str
    description: str
    expected_activity: tuple[str, ...]
    unexpected_traits: frozenset[str] = frozenset()


_GENERAL = WorkstationProfile(
    name="Balanced",
    description="General-purpose Mac with normal interactive application, network, and user activity.",
    expected_activity=("interactive applications", "ordinary network access", "occasional administration"),
    unexpected_traits=frozenset({"RESEARCH_ACTIVITY", "FUZZING_ACTIVITY", "SERVER_SERVICE_ACTIVITY"}),
)

WORKSTATION_PROFILES: dict[str, WorkstationProfile] = {
    "Balanced": _GENERAL,
    "Office": replace(
        _GENERAL,
        name="Office",
        description="Office productivity workstation without routine development, fuzzing, or server workloads.",
        expected_activity=("signed productivity applications", "business network access", "managed software changes"),
        unexpected_traits=frozenset(
            {"DEVELOPMENT_TOOLING", "RESEARCH_ACTIVITY", "FUZZING_ACTIVITY", "SERVER_SERVICE_ACTIVITY"}
        ),
    ),
    "High Security": replace(
        _GENERAL,
        name="High Security",
        description="Restricted workstation where development, research, unsigned execution, and remote access require review.",
        expected_activity=("approved signed applications", "restricted network access", "controlled administrative change"),
        unexpected_traits=frozenset(
            {
                "DEVELOPMENT_TOOLING",
                "RESEARCH_ACTIVITY",
                "FUZZING_ACTIVITY",
                "SERVER_SERVICE_ACTIVITY",
                "UNSIGNED_EXECUTION",
                "TEMPORARY_EXECUTION",
                "REMOTE_ACCESS",
                "EXTERNAL_DEVICE_ACTIVITY",
            }
        ),
    ),
    "Developer": replace(
        _GENERAL,
        name="Developer",
        description="Software-development workstation where shells, interpreters, compilers, and build activity are expected.",
        expected_activity=("developer tools", "shells and interpreters", "local builds", "source-control network access"),
        unexpected_traits=frozenset({"RESEARCH_ACTIVITY", "FUZZING_ACTIVITY", "SERVER_SERVICE_ACTIVITY"}),
    ),
    "Research": replace(
        _GENERAL,
        name="Research",
        description="Authorized security-research workstation with explicit research and fuzzing context.",
        expected_activity=("developer tools", "debuggers", "fuzzing", "research tooling", "controlled executable memory"),
        unexpected_traits=frozenset({"SERVER_SERVICE_ACTIVITY"}),
    ),
    "Enterprise": replace(
        _GENERAL,
        name="Enterprise",
        description="Managed enterprise endpoint where software and security changes should follow organizational policy.",
        expected_activity=("managed signed applications", "enterprise services", "approved administrative workflows"),
        unexpected_traits=frozenset({"RESEARCH_ACTIVITY", "FUZZING_ACTIVITY"}),
    ),
    "Server": replace(
        _GENERAL,
        name="Server",
        description="Service-oriented Mac where daemon and non-interactive network workloads are expected.",
        expected_activity=("service accounts", "listeners", "scheduled jobs", "stable network services"),
        unexpected_traits=frozenset({"RESEARCH_ACTIVITY", "FUZZING_ACTIVITY", "EXTERNAL_DEVICE_ACTIVITY"}),
    ),
}


TRAIT_REASON_CODES = {
    "DEVELOPMENT_TOOLING": "PROFILE_UNEXPECTED_DEVELOPMENT_TOOLING",
    "RESEARCH_ACTIVITY": "PROFILE_UNEXPECTED_RESEARCH_ACTIVITY",
    "FUZZING_ACTIVITY": "PROFILE_UNEXPECTED_FUZZING_ACTIVITY",
    "SERVER_SERVICE_ACTIVITY": "PROFILE_UNEXPECTED_SERVER_ACTIVITY",
    "UNSIGNED_EXECUTION": "PROFILE_UNEXPECTED_UNSIGNED_EXECUTION",
    "TEMPORARY_EXECUTION": "PROFILE_UNEXPECTED_TEMPORARY_EXECUTION",
    "REMOTE_ACCESS": "PROFILE_UNEXPECTED_REMOTE_ACCESS",
    "EXTERNAL_DEVICE_ACTIVITY": "PROFILE_UNEXPECTED_EXTERNAL_DEVICE",
}


def workstation_profile(name: str) -> WorkstationProfile:
    return WORKSTATION_PROFILES.get(str(name or "").strip(), WORKSTATION_PROFILES["Balanced"])


def apply_workstation_profile(event: NormalizedTelemetryEvent, profile_name: str) -> NormalizedTelemetryEvent:
    """Add bounded role-deviation features without making a malware judgement."""

    profile = workstation_profile(profile_name)
    declared = event.security_context.get("behavior_traits", [])
    traits = {str(item) for item in declared} if isinstance(declared, list) else set()
    unexpected = sorted(traits.intersection(profile.unexpected_traits))

    # An unsigned executable in a temporary/download location is outside the
    # declared norm even on developer and research machines. A lone unsigned
    # local build remains baseline context rather than a profile violation.
    if (
        "UNSIGNED_EXECUTION" in traits
        and traits.intersection({"TEMPORARY_EXECUTION", "DOWNLOAD_EXECUTION"})
        and profile.name not in {"High Security"}
    ):
        unexpected.append("UNSIGNED_TEMPORARY_EXECUTION")
    unexpected = list(dict.fromkeys(unexpected))
    if not unexpected:
        context = dict(event.security_context)
        context["workstation_profile"] = profile.name
        return replace(event, security_context=context)

    features = dict(event.features)
    features["workstation_profile_deviation_count"] = 1.0
    for trait in unexpected:
        slug = trait.lower()
        features[f"profile_deviation_{slug}_count"] = 1.0
    context = dict(event.security_context)
    context.update(
        {
            "workstation_profile": profile.name,
            "workstation_profile_deviation": True,
            "profile_deviation_traits": unexpected,
            "profile_deviation_reason_codes": [
                "PROFILE_UNEXPECTED_UNSIGNED_EXECUTION"
                if trait == "UNSIGNED_TEMPORARY_EXECUTION"
                else TRAIT_REASON_CODES.get(trait, "WORKSTATION_PROFILE_DEVIATION")
                for trait in unexpected
            ],
        }
    )
    return replace(
        event,
        features=features,
        security_context=context,
        baseline_training_eligible=False,
    )


__all__ = [
    "TRAIT_REASON_CODES",
    "WORKSTATION_PROFILES",
    "WorkstationProfile",
    "apply_workstation_profile",
    "workstation_profile",
]
