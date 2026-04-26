"""SSRF target-host validation for the Settings test-* endpoints.

The dashboard exposes /api/setup/test-elasticsearch, test-unifi,
test-opnsense, test-firewalla, test-openvas, and test-ollama. Each
takes an operator-supplied URL or host and issues an outbound
HTTP/TLS request. Without validation those endpoints are SSRF
primitives that can reach cloud metadata
(http://169.254.169.254/latest/...), IPv6 link-local services, and
internal hosts that aren't part of the dashboard's own infrastructure.

The threat-model rule is **"deny what's never legitimate; allow what
is."**

  Denied (always):
    - 169.254.0.0/16  — IPv4 link-local + cloud metadata
                        (AWS/Azure/GCP IMDS lives here)
    - 0.0.0.0/8       — "this network" / unspecified
    - fe80::/10       — IPv6 link-local
    - Multicast / unspecified IPv6

  Allowed (homelab use cases):
    - 127.0.0.0/8     — loopback (operator running ES locally)
    - 10/8, 172.16/12, 192.168/16  — RFC1918 LAN
    - Docker DNS aliases (homelab-openvas, opnsense, etc.) — these
      resolve to a docker bridge IP that lands in 172.16/12, which
      is RFC1918-allowed
    - Public hostnames — any IP not in the denied set
                         (Firewalla MSP cloud, Ollama remote, etc.)

DNS-rebinding caveat: this module resolves the hostname once and
validates the resolved IP. The actual httpx call uses the same
hostname and may re-resolve between our check and the request. A
DNS-rebinding attacker who controls a domain can flip the resolution
in that sub-second window. For a homelab tool this is an acceptable
trade-off — the window is small, and the alternative (rebinding the
URL to use the resolved IP literal) sacrifices TLS SNI / Host header
correctness against legitimate services. Document the window; don't
pretend it's closed.

Reviews → F-002 in reviews/FINAL_REPORT.md.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Iterable
from urllib.parse import urlparse


class TargetValidationError(ValueError):
    """Raised when a target host fails SSRF validation. The message is
    safe for return in an HTTP 400 response — it never echoes raw
    response data, only the policy decision."""


# IPv4 / IPv6 networks we never let outbound requests touch, regardless
# of how the operator configured the dashboard.
_DENY_NETS_ALWAYS: tuple[ipaddress._BaseNetwork, ...] = (
    ipaddress.ip_network("169.254.0.0/16"),    # IPv4 link-local + cloud IMDS
    ipaddress.ip_network("0.0.0.0/8"),         # "this network" / unspecified
    ipaddress.ip_network("fe80::/10"),         # IPv6 link-local
    ipaddress.ip_network("ff00::/8"),          # IPv6 multicast
    ipaddress.ip_network("::/128"),            # IPv6 unspecified
    ipaddress.ip_network("::ffff:169.254.0.0/112"),  # v4-mapped link-local
)


def _looks_like_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _resolve(host: str) -> list[ipaddress._BaseAddress]:
    """Resolve `host` to all IPv4 + IPv6 addresses it could reach.
    Empty list when the name doesn't resolve.
    """
    if _looks_like_ip(host):
        return [ipaddress.ip_address(host)]
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return []
    out: list[ipaddress._BaseAddress] = []
    for info in infos:
        sockaddr = info[4]
        # IPv4 sockaddr is (ip, port); IPv6 is (ip, port, flow, scope)
        ip_str = sockaddr[0]
        try:
            out.append(ipaddress.ip_address(ip_str))
        except ValueError:
            continue
    return out


def _is_denied(ip: ipaddress._BaseAddress) -> bool:
    return any(ip in net for net in _DENY_NETS_ALWAYS)


def parse_host(host_or_url: str) -> str:
    """Pull the host portion out of a value that might be either
    "host[:port]" or a full "scheme://host[:port]/path" URL.

    The Settings test endpoints take inconsistent shapes — some accept
    a bare host (test-elasticsearch, test-openvas), others a full URL
    (test-unifi, test-opnsense). We canonicalise here so the validator
    sees the same thing either way.
    """
    s = (host_or_url or "").strip()
    if not s:
        raise TargetValidationError("host is required")
    # If it parses as a URL with a scheme, pull the netloc's host.
    if "://" in s:
        parsed = urlparse(s)
        host = parsed.hostname or ""
    else:
        # bare "host" or "host:port"
        host = s.split(":", 1)[0]
    host = host.strip().strip("[]")  # bracket-strip for IPv6 literals
    if not host:
        raise TargetValidationError("host is empty after parsing")
    return host


def validate_outbound_target(host_or_url: str) -> str:
    """Validate the target host for the /api/setup/test-* endpoints.

    Returns the parsed hostname on success (so callers can build the
    httpx request from it). Raises TargetValidationError on any deny
    rule or unresolvable name.

    See module docstring for the policy. In short: deny link-local +
    cloud metadata + IPv6 link-local + multicast / unspecified;
    allow everything else.
    """
    host = parse_host(host_or_url)

    addrs = _resolve(host)
    if not addrs:
        raise TargetValidationError(
            f"could not resolve host {host!r} to any IP — "
            "check the value and network reachability"
        )

    # Reject if ANY resolved address falls in a denied net. We don't
    # take "the first non-denied one" — DNS-rebinding mitigation
    # requires that every potential resolution be safe, otherwise an
    # attacker can have getaddrinfo return [denied, allowed] and the
    # actual TCP connect race between resolutions is exploitable.
    for ip in addrs:
        if _is_denied(ip):
            raise TargetValidationError(
                f"host {host!r} resolves to {ip} which is in a denied range "
                "(link-local / cloud metadata / link-local IPv6). The "
                "Settings test endpoints don't accept those targets."
            )

    return host


def is_target_ok(host_or_url: str) -> bool:
    """Convenience: True iff validate_outbound_target would succeed.
    Useful when the caller wants to fall back rather than raise.
    """
    try:
        validate_outbound_target(host_or_url)
        return True
    except TargetValidationError:
        return False


# Exposed for tests that want to feed in synthetic IP lists.
def _check_resolved_addrs(addrs: Iterable[ipaddress._BaseAddress]) -> None:
    for ip in addrs:
        if _is_denied(ip):
            raise TargetValidationError(
                f"resolved address {ip} is in a denied range"
            )
