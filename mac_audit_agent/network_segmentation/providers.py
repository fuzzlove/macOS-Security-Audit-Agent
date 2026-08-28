from __future__ import annotations

from .models import EgressService, Provider, ProviderState


def service(service_id: str, host: str, port: int | None, transport: str, validation: str, *, port_range=None) -> EgressService:
    return EgressService(service_id, host, port, transport, validation, port_range=port_range)


APPROVED_PROVIDERS: tuple[Provider, ...] = (
    Provider("letmeoutofyour", "letmeoutofyour.net", "letmeoutofyour.net", ("tcp", "udp"), "https://github.com/sensepost/go-out", "Primary broad-port service. Runtime qualification and response correlation are required; w00tw00t alone is not authentication.", enabled_by_default=True, capabilities=frozenset({"tcp", "udp", "broad_ports", "ipv4", "ipv6"}), services=(service("all_ports_tcp", "letmeoutofyour.net", None, "tcp", "protocol_response", port_range=(1, 65535)), service("all_ports_udp", "letmeoutofyour.net", None, "udp", "protocol_response", port_range=(1, 65535))), initial_state=ProviderState.UNKNOWN),
    Provider("portquiz", "PortQuiz", "portquiz.net", ("tcp",), "https://portquiz.net/", "Broad TCP and HTTP-compatible response testing. Full range is never automatic.", enabled_by_default=True, capabilities=frozenset({"tcp", "http", "broad_ports", "ipv4", "ipv6"}), services=(service("tcp_range", "portquiz.net", None, "tcp", "tcp_connect", port_range=(1, 65535)),), initial_state=ProviderState.UNKNOWN),
    Provider("egresser", "Cyberis Egresser", "egresser.labs.cyberis.co.uk", ("tcp",), "https://github.com/cyberisltd/egresser", "Source address, source port, and NAT analysis where currently supported. Must qualify before use.", qualification_required=True, capabilities=frozenset({"tcp", "nat", "ipv4", "ipv6"}), initial_state=ProviderState.UNQUALIFIED),
    Provider("tcpbin_com", "tcpbin.com", "tcpbin.com", ("tcp", "tls", "mtls"), "https://tcpbin.com/", "Echo services. mTLS requires a dedicated operator-selected test identity.", enabled_by_default=True, capabilities=frozenset({"tcp", "tls", "mtls", "echo"}), services=(service("tcp_echo", "tcpbin.com", 4242, "tcp", "echo"), service("tls_echo", "tcpbin.com", 4243, "tls", "tls_echo"), service("mtls", "tcpbin.com", 4244, "mtls", "mutual_tls")), initial_state=ProviderState.UNKNOWN),
    Provider("tcpbin_org", "tcpbin.org", "tcpbin.org", ("tcp", "udp"), "https://tcpbin.org/", "TCP/UDP echo and connection-information services; runtime availability is not assumed.", enabled_by_default=True, capabilities=frozenset({"tcp", "udp", "echo", "nat"}), services=(service("tcp_echo", "tcpbin.org", 30000, "tcp", "echo"), service("tcp_connection_info", "tcpbin.org", 30001, "tcp", "connection_info"), service("udp_echo", "tcpbin.org", 40000, "udp", "echo"), service("udp_connection_info", "tcpbin.org", 40001, "udp", "connection_info")), initial_state=ProviderState.UNKNOWN),
    Provider("allports_exposed", "allports.exposed", "allports.exposed", ("tcp",), "https://allports.exposed/", "Legacy secondary broad TCP endpoint. Availability and coverage are unqualified.", qualification_required=True, capabilities=frozenset({"tcp", "broad_ports"}), services=(service("tcp_range", "allports.exposed", None, "tcp", "tcp_connect", port_range=(1, 65535)),), initial_state=ProviderState.UNQUALIFIED),
)

_ALIASES = {"sensepost-letmeout": "letmeoutofyour", "sensepost-allports": "allports_exposed"}


def provider_by_id(provider_id: str) -> Provider:
    provider_id = _ALIASES.get(provider_id, provider_id)
    for provider in APPROVED_PROVIDERS:
        if provider.provider_id == provider_id:
            return provider
    raise ValueError("provider is not in the approved provider registry")
