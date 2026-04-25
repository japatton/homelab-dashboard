"""
IP pattern expansion used by the Scan Credentials test endpoint.

Accepts:
  - Single IP:        "192.168.1.50"
  - Comma list:       "192.168.1.50, 192.168.1.51, 10.0.0.5"
  - Last-octet range: "192.168.1.5-10"
  - CIDR:             "192.168.1.16/29"
  - Wildcard:         "*"  (returned as-is; caller decides behavior)

Caps expansion at EXPAND_MAX_HOSTS so a fat-fingered "10.0.0.0/8" can't
spawn a 16M-host SSH sweep.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Iterator

# Keep this small — the test endpoint opens a TCP connection per host, and
# anything bigger than a /27 starts to feel like nmap, not a credential test.
EXPAND_MAX_HOSTS = 64

_LAST_OCTET_RANGE = re.compile(
    r"^(?P<prefix>\d{1,3}\.\d{1,3}\.\d{1,3})\.(?P<start>\d{1,3})-(?P<end>\d{1,3})$"
)


class ExpandError(ValueError):
    """Raised when a pattern is malformed or would exceed the host cap."""


def expand_targets(pattern: str) -> list[str]:
    """Parse a target pattern into a concrete list of IPv4 addresses.

    Preserves input order for comma lists; ranges/CIDRs are emitted in
    numeric order. Raises ExpandError on a malformed pattern or overflow.
    """
    pattern = (pattern or "").strip()
    if not pattern:
        raise ExpandError("empty target pattern")
    if pattern == "*":
        raise ExpandError("wildcard '*' cannot be tested — add a specific target")

    out: list[str] = []
    seen: set[str] = set()

    for part in (p.strip() for p in pattern.split(",") if p.strip()):
        for ip in _expand_part(part):
            if ip not in seen:
                seen.add(ip)
                out.append(ip)
            if len(out) > EXPAND_MAX_HOSTS:
                raise ExpandError(
                    f"pattern expands to more than {EXPAND_MAX_HOSTS} hosts — "
                    f"narrow the range"
                )
    if not out:
        raise ExpandError(f"pattern {pattern!r} expanded to zero hosts")
    return out


def _expand_part(part: str) -> Iterator[str]:
    # Last-octet range syntax: "a.b.c.x-y"
    m = _LAST_OCTET_RANGE.match(part)
    if m:
        prefix = m.group("prefix")
        start = int(m.group("start"))
        end = int(m.group("end"))
        if start > end or start < 0 or end > 255:
            raise ExpandError(f"invalid last-octet range {part!r}")
        for i in range(start, end + 1):
            ip = f"{prefix}.{i}"
            _validate_ipv4(ip, part)
            yield ip
        return

    # CIDR
    if "/" in part:
        try:
            net = ipaddress.ip_network(part, strict=False)
        except ValueError as e:
            raise ExpandError(f"invalid CIDR {part!r}: {e}") from e
        if net.version != 4:
            raise ExpandError(f"only IPv4 is supported (got {part!r})")
        # Use hosts() so /31 and /32 still yield something usable; for
        # small (/30 and smaller) subnets hosts() returns all addresses.
        # Iterate lazily — the caller enforces EXPAND_MAX_HOSTS.
        for addr in net.hosts():
            yield str(addr)
        return

    # Plain IP
    _validate_ipv4(part, part)
    yield part


def _validate_ipv4(ip: str, original: str) -> None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError as e:
        raise ExpandError(f"invalid IP {original!r}: {e}") from e
    if addr.version != 4:
        raise ExpandError(f"only IPv4 is supported (got {original!r})")
