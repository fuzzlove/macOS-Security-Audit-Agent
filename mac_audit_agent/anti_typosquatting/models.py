from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class AssetType(str, Enum):
    DOMAIN = "domain"
    PACKAGE = "package"


class PackageEcosystem(str, Enum):
    NPM = "npm"
    PYPI = "pypi"
    CRATES_IO = "crates-io"
    RUBYGEMS = "rubygems"
    NUGET = "nuget"
    MAVEN_CENTRAL = "maven-central"
    GO_MODULE = "go-module"
    PACKAGIST = "packagist"


class InvestigationStatus(str, Enum):
    UNREVIEWED = "Unreviewed Lookalike"
    OWNER_PENDING = "Owner Verification Pending"
    AUTHORIZED = "Authorized Organization Asset"
    DEFENSIVE = "Approved Defensive Asset"
    LEGITIMATE_THIRD_PARTY = "Legitimate Third-Party Project"
    UNRELATED = "Unrelated Name Collision"
    HISTORICAL = "Deprecated or Historical Official Asset"
    SUSPICIOUS = "Suspicious and Requires Further Investigation"
    PROBABLE = "Probable Impersonation"
    CONFIRMED = "Confirmed Fraudulent by Authoritative Evidence"
    REPORT_SUBMITTED = "Registry Report Submitted"
    ACTION_CONFIRMED = "Registry Action Confirmed"
    CLOSED = "Closed Without Action"


@dataclass(frozen=True)
class NamespaceComponent:
    name: str
    value: str
    security_role: str


@dataclass(frozen=True)
class ParsedIdentifier:
    ecosystem: PackageEcosystem
    display: str
    canonical: str
    comparison_key: str
    lookup_key: str
    components: tuple
    projections: tuple = ()
    private: bool = False


@dataclass(frozen=True)
class ProviderCapabilities:
    exact_lookup: bool = True
    similar_search: bool = False
    owner_metadata: bool = False
    verified_identity: bool = False
    provenance: bool = False
    publication_time: bool = False
    version_history: bool = False
    yank_or_unlist: bool = False
    deprecation: bool = False
    download_count: bool = False
    abuse_workflow: bool = False
    network_privacy_sensitive: bool = False
    publisher_namespace: bool = False
    efficient_bulk_access: bool = False
    private_lookup: bool = False
    direct_source_repository: bool = False


@dataclass(frozen=True)
class LocalDependencyOccurrence:
    ecosystem: PackageEcosystem
    declared_identifier: str
    manifest_path: str
    dependency_type: str
    structured_location: str
    source: str = "default registry"
    production: bool = True


@dataclass
class LocalProjectAudit:
    schema_version: str
    root: str
    occurrences: List[LocalDependencyOccurrence]
    findings: List[Dict[str, Any]]
    errors: List[Dict[str, str]]
    files_scanned: int


class LookupStatus(str, Enum):
    NOT_REQUESTED = "Lookup Not Requested"
    PENDING = "Lookup Pending"
    REGISTERED = "Registered"
    PUBLISHED = "Published"
    NO_REGISTRATION_DATA = "No Registration Data Found"
    NOT_PUBLISHED = "Not Currently Published"
    POLICY_UNKNOWN = "Registry Reservation or Policy Status Unknown"
    RATE_LIMITED = "Rate Limited"
    PROVIDER_UNAVAILABLE = "Provider Unavailable"
    INVALID = "Invalid Candidate"
    ERROR = "Lookup Error"


@dataclass(frozen=True)
class ProtectedAsset:
    asset_type: AssetType
    canonical_name: str
    ecosystem: Optional[PackageEcosystem] = None
    display_name: str = ""
    organization: str = ""
    product_family: str = ""
    business_criticality: int = 50
    visibility: str = "public"
    lifecycle_state: str = "production"
    canonical_repository: str = ""
    canonical_homepage: str = ""
    expected_namespace: str = ""
    legitimate_aliases: Tuple[str, ...] = ()
    defensive_registrations: Tuple[str, ...] = ()
    notes: str = ""

    def __post_init__(self) -> None:
        if not 0 <= self.business_criticality <= 100:
            raise ValueError("Business criticality must be from 0 through 100.")


@dataclass(frozen=True)
class CandidateReason:
    rule_id: str
    explanation: str
    category: str
    locale: str = "generic"


@dataclass(frozen=True)
class ScoreBreakdown:
    total: int
    contributions: Dict[str, int] = field(default_factory=dict)


@dataclass
class Candidate:
    candidate_id: str
    canonical_asset: str
    display_name: str
    normalized_name: str
    ascii_name: str
    asset_type: str
    ecosystem: str = ""
    identifier_components: Dict[str, str] = field(default_factory=dict)
    identifier_projections: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    reasons: List[CandidateReason] = field(default_factory=list)
    edit_operations: List[str] = field(default_factory=list)
    locale_profiles: List[str] = field(default_factory=list)
    unicode_scripts: List[str] = field(default_factory=list)
    unicode_code_points: List[str] = field(default_factory=list)
    confusable_skeleton: str = ""
    human_typo: ScoreBreakdown = field(default_factory=lambda: ScoreBreakdown(0))
    impersonation: ScoreBreakdown = field(default_factory=lambda: ScoreBreakdown(0))
    namespace_confusion: ScoreBreakdown = field(default_factory=lambda: ScoreBreakdown(0))
    visual_impersonation: ScoreBreakdown = field(default_factory=lambda: ScoreBreakdown(0))
    name_closeness: ScoreBreakdown = field(default_factory=lambda: ScoreBreakdown(0))
    attacker_use_assumption: ScoreBreakdown = field(default_factory=lambda: ScoreBreakdown(0))
    risk_band: str = "review"
    supply_chain_reachability: ScoreBreakdown = field(default_factory=lambda: ScoreBreakdown(0))
    ownership_confidence: ScoreBreakdown = field(default_factory=lambda: ScoreBreakdown(0))
    defensive_registration: ScoreBreakdown = field(default_factory=lambda: ScoreBreakdown(0))
    investigation: ScoreBreakdown = field(default_factory=lambda: ScoreBreakdown(0))
    validation_state: str = "valid"
    lookup_status: str = LookupStatus.NOT_REQUESTED.value
    lookup_evidence: Dict[str, Any] = field(default_factory=dict)
    recommended_action: str = "Review this explainable candidate against authorized ownership records."
    registration_guidance: str = "Check authoritative registry status and ownership before considering defensive registration."

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class GenerationConfiguration:
    locales: tuple = ("en-US-qwerty",)
    typing_profiles: tuple = ("desktop",)
    include_human_typos: bool = True
    include_keyboard: bool = True
    include_phonetic: bool = True
    include_unicode: bool = True
    include_tld_confusion: bool = True
    include_service_words: bool = True
    include_package_confusion: bool = True
    include_two_error: bool = False
    offline_only: bool = True
    result_limit: int = 25
    pre_dedup_limit: int = 500
    post_dedup_limit: int = 100


@dataclass
class AnalysisRun:
    schema_version: str
    run_id: str
    asset: ProtectedAsset
    configuration: GenerationConfiguration
    candidates: List[Candidate]
    data_versions: Dict[str, str]
    generated_at: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
