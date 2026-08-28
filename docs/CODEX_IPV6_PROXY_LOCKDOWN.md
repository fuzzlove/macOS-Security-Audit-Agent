# Codex IPv6 Proxy Lockdown

`scripts/setup_codex_ipv6_proxy.sh` creates a local forward proxy architecture in which Codex connects to Squid over IPv4 loopback and only Squid's dedicated service identity may originate new application IPv6 web connections.

## Security boundary

- Squid listens only on `127.0.0.1:43128`.
- Squid allows only ports 80/443 and the configured OpenAI, ChatGPT, and static-content domain suffixes.
- No TLS interception or locally trusted proxy CA is configured.
- PF permits outbound IPv6 TCP ports 80/443 only for `_codexproxy`.
- All other new IPv6 application ingress and egress is blocked.
- Only the minimum ICMPv6 control-plane messages needed for neighbor discovery, router discovery, error reporting, and path-MTU handling are allowed.
- The script does not disable IPv6 on the interface because doing so would also prevent Squid from using IPv6.

macOS PF can associate TCP/UDP sockets with an effective user, but it cannot securely match an executable path. Squid also cannot determine which local executable opened a loopback proxy connection. The wrapper is therefore the intended Codex entry point, but it is not a kernel-enforced binary whitelist. A signed Network Extension/content filter, separate VM, or external enforcement gateway is required for binary-identity enforcement.

## Installation

Install Squid using the organization's approved package-management process. Then run:

```bash
sudo scripts/setup_codex_ipv6_proxy.sh check
sudo scripts/setup_codex_ipv6_proxy.sh install
```

Start Codex through:

```bash
/usr/local/bin/codex-via-ipv6-proxy
```

Inspect status and effective rules:

```bash
sudo scripts/setup_codex_ipv6_proxy.sh status
sudo pfctl -a com.msaa.codex-ipv6 -sr
```

Rollback:

```bash
sudo scripts/setup_codex_ipv6_proxy.sh uninstall
```

The installer validates Squid configuration and PF syntax before activation. It then confirms a new direct IPv6 HTTPS connection is blocked and that the IPv4-loopback proxy works. Failed enforcement triggers automatic rollback. Existing PF connection states are not flushed because that would terminate unrelated connections; restart long-lived applications or reboot during an approved maintenance window.

## Operational cautions

- Test from local console, not solely through remote administration.
- VPN, endpoint filtering, MDM, and third-party firewall software may override or conflict with PF behavior.
- OpenAI service domains can change. Review Squid denials before adding a narrowly scoped domain; do not replace the domain ACL with an unrestricted wildcard.
- Do not expose port `43128` on a non-loopback address.
- Do not enable TLS interception for OpenAI credentials or Codex traffic.
