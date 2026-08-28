from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from mac_audit_agent.network_segmentation import APPROVED_PROVIDERS, ProviderState, provider_by_id
from mac_audit_agent.network_segmentation.qualification import make_record, qualification_state
from mac_audit_agent.network_segmentation.rdap import filter_by_rir, parse_rdap
from mac_audit_agent.network_segmentation.resolver import destination_is_public
from mac_audit_agent.network_segmentation.validation import make_nonce, validate_echo


def test_registry_has_all_six_dynamic_public_providers():
    assert {item.provider_id for item in APPROVED_PROVIDERS} == {"letmeoutofyour", "portquiz", "egresser", "tcpbin_com", "tcpbin_org", "allports_exposed"}
    assert all(not any(char.isdigit() for char in item.hostname.split(".")) for item in APPROVED_PROVIDERS)


def test_uncertain_providers_are_disabled_and_unqualified():
    for provider_id in ("egresser", "allports_exposed"):
        item = provider_by_id(provider_id)
        assert item.qualification_required
        assert not item.enabled_by_default
        assert item.initial_state is ProviderState.UNQUALIFIED


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "fc00::1", "fe80::1", "224.0.0.1"])
def test_private_metadata_link_local_and_multicast_destinations_rejected(address):
    assert not destination_is_public(address)


def test_nonce_echo_is_exact_and_not_transform_tolerant():
    nonce = make_nonce()
    assert nonce.startswith(b"MSAA-EGRESS-TEST:")
    assert validate_echo(nonce, nonce)
    assert not validate_echo(nonce, nonce + b"x")


def test_rdap_parsing_uses_authoritative_metadata_not_country():
    item = parse_rdap({"country": "US", "handle": "TEST-NET", "cidr0_cidrs": [{"v4prefix": "192.0.2.0", "length": 24}]}, server="https://rdap.db.ripe.net")
    assert item.rir == "RIPE NCC"
    assert item.country == "US"
    assert item.prefix == "192.0.2.0/24"


def test_rir_filter_never_substitutes_another_registry():
    arin = parse_rdap({}, server="https://rdap.arin.net")
    with pytest.raises(LookupError, match="NO_QUALIFIED_DESTINATION_FOR_RIR"):
        filter_by_rir({"192.0.2.1": arin}, "RIPE NCC")


def test_qualification_state_and_expiration_are_bounded():
    assert qualification_state(dns_ok=True, transport_ok=True, response_ok=True, rdap_ok=True) is ProviderState.HEALTHY
    assert qualification_state(dns_ok=True, transport_ok=True, response_ok=False, rdap_ok=True) is ProviderState.DEGRADED
    record = make_record("test", dns_ok=False, transport_ok=False, response_ok=False, rdap_ok=False)
    assert record.state is ProviderState.FAILED
    assert record.expires_at <= datetime.now(timezone.utc) + timedelta(minutes=31)
