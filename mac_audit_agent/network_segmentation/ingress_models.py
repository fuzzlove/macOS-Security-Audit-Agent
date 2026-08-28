from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import uuid4


class ExpectedAction(StrEnum):
    ALLOW="allow"; DENY="deny"


class SegmentationResult(StrEnum):
    PASS_EXPECTED_ALLOW="PASS_EXPECTED_ALLOW"; PASS_EXPECTED_DENY="PASS_EXPECTED_DENY"
    FAIL_UNEXPECTED_ALLOW="FAIL_UNEXPECTED_ALLOW"; FAIL_UNEXPECTED_DENY="FAIL_UNEXPECTED_DENY"
    NETWORK_REACHABLE_SERVICE_CLOSED="NETWORK_REACHABLE_SERVICE_CLOSED"
    NETWORK_REACHABLE_SERVICE_REJECTED="NETWORK_REACHABLE_SERVICE_REJECTED"
    INFERRED_ALLOWED="INFERRED_ALLOWED"; INFERRED_BLOCKED="INFERRED_BLOCKED"
    INDETERMINATE="INDETERMINATE"; NOT_TESTED="NOT_TESTED"; TEST_ERROR="TEST_ERROR"
    OUT_OF_SCOPE_REJECTED="OUT_OF_SCOPE_REJECTED"; CANCELLED="CANCELLED"; EXPIRED="EXPIRED"


@dataclass(frozen=True)
class Engagement:
    engagement_id: str; name: str; client: str; authorization_reference: str; authorized_tester: str; approver: str
    starts_at: str; ends_at: str; source_cidrs: tuple[str,...]; destination_cidrs: tuple[str,...]
    excluded_cidrs: tuple[str,...]=(); restricted_protocols: tuple[str,...]=(); maximum_packet_rate: int=20
    maximum_connections: int=4; maximum_retries: int=3; emergency_contact: str=""; retention_classification: str="internal"
    sensitive_data_context: str="none declared"; stop_conditions: str="Any adverse impact or client request"; acknowledgement: bool=False

    @classmethod
    def create(cls,**kwargs):return cls(engagement_id=str(uuid4()),**kwargs)


@dataclass(frozen=True)
class ExpectedFlow:
    flow_id: str; source_zone: str; source: str; destination_zone: str; destination: str; direction: str
    address_family: int; protocol: str; expected_action: ExpectedAction; port_start: int|None=None; port_end: int|None=None
    icmp_type: int|None=None; icmp_code: int|None=None; ip_protocol: int|None=None; business_justification: str=""
    data_classification: str=""; system_criticality: str="moderate"; policy_owner: str=""; policy_reference: str=""
    change_reference: str=""; framework_tags: tuple[str,...]=(); expiration_date: str=""; analyst_notes: str=""


@dataclass(frozen=True)
class Observation:
    observed: bool|None; observer_healthy: bool; response: str=""; source_ip: str=""; destination_ip: str=""
    nonce: str=""; test_case_id: str=""; attempts: int=0; capture_overflow: bool=False; interface_matches: bool=True


@dataclass(frozen=True)
class ClassifiedResult:
    result: SegmentationResult; confidence: str; rationale: tuple[str,...]; severity: str


@dataclass
class TestPlan:
    plan_id: str; engagement_id: str; created_at: str; flows: list[ExpectedFlow]=field(default_factory=list); pinned_dns: dict[str,tuple[str,...]]=field(default_factory=dict)

    @classmethod
    def create(cls,engagement_id:str,flows:list[ExpectedFlow]):return cls(str(uuid4()),engagement_id,datetime.now(timezone.utc).isoformat(),flows)
    def to_dict(self)->dict[str,Any]:return asdict(self)
