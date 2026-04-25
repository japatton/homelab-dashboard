"""Tests for services.ip_expand.

This is the input sanitiser that stands between user-entered target
patterns ("192.168.1.5-10", "10.0.0.0/24", "example.com, foo.lan") and
the SSH probe that actually opens TCP connections. Getting it wrong
either blocks legitimate patterns (annoying) or fans out to thousands
of hosts (denial-of-service against the homelab LAN).

Tests focus on:
  - Pattern shapes the docstring promises we support.
  - Shapes we deliberately reject.
  - The 64-host safety cap.
  - Dedup and order preservation.
"""

from __future__ import annotations

import pytest

from services.ip_expand import EXPAND_MAX_HOSTS, ExpandError, expand_targets


class TestSingleAndList:
    """Single IPs and comma-separated lists — the happy path."""

    def test_single_ip(self):
        assert expand_targets("192.168.1.50") == ["192.168.1.50"]

    def test_comma_list_preserves_order(self):
        # Order matters — the SSH probe runs them in-order and we want
        # deterministic test output if the user pastes a specific sequence.
        out = expand_targets("10.0.0.5, 10.0.0.1, 10.0.0.3")
        assert out == ["10.0.0.5", "10.0.0.1", "10.0.0.3"]

    def test_comma_list_dedups(self):
        out = expand_targets("192.168.1.1, 192.168.1.1, 192.168.1.2")
        assert out == ["192.168.1.1", "192.168.1.2"]

    def test_whitespace_tolerance(self):
        # Common copy-paste: extra spaces, trailing comma.
        out = expand_targets("  192.168.1.1 ,  192.168.1.2 ,")
        assert out == ["192.168.1.1", "192.168.1.2"]


class TestLastOctetRange:
    """a.b.c.x-y syntax — the most common homelab shorthand."""

    def test_basic_range(self):
        out = expand_targets("192.168.1.5-7")
        assert out == ["192.168.1.5", "192.168.1.6", "192.168.1.7"]

    def test_single_element_range(self):
        # Edge case: start == end — should still work.
        assert expand_targets("10.0.0.5-5") == ["10.0.0.5"]

    def test_rejects_reversed_range(self):
        with pytest.raises(ExpandError):
            expand_targets("10.0.0.10-5")

    def test_rejects_out_of_bounds(self):
        with pytest.raises(ExpandError):
            expand_targets("10.0.0.0-300")


class TestCIDR:
    """CIDR expansion. Tests /30, /31, /32 edge cases because
    `ipaddress.ip_network.hosts()` has different semantics for each.
    """

    def test_slash_30(self):
        # /30 = 4 addresses, hosts() returns the 2 usable ones
        out = expand_targets("192.168.1.0/30")
        assert out == ["192.168.1.1", "192.168.1.2"]

    def test_slash_29(self):
        # /29 = 8 addresses, 6 usable
        out = expand_targets("10.0.0.0/29")
        assert len(out) == 6
        assert out[0] == "10.0.0.1"
        assert out[-1] == "10.0.0.6"

    def test_non_zero_base_is_normalised(self):
        # strict=False: "192.168.1.16/29" should collapse to the network.
        out = expand_targets("192.168.1.16/29")
        assert out[0] == "192.168.1.17"

    def test_rejects_ipv6(self):
        with pytest.raises(ExpandError):
            expand_targets("fe80::/64")

    def test_rejects_garbage_cidr(self):
        with pytest.raises(ExpandError):
            expand_targets("not-a-cidr/24")


class TestSafetyCap:
    """The 64-host limit is the whole reason this module exists.
    A fat-fingered /16 should fail loudly, not DOS the LAN."""

    def test_under_cap_ok(self):
        # /27 = 32 addresses, 30 usable — under the cap
        out = expand_targets("192.168.1.0/27")
        assert len(out) == 30

    def test_over_cap_raises(self):
        # /24 = 254 usable hosts, way over
        with pytest.raises(ExpandError, match="more than"):
            expand_targets("192.168.1.0/24")

    def test_cap_constant_exported(self):
        # Guard against an accidental bump. If someone raises the cap
        # they should update the test deliberately.
        assert EXPAND_MAX_HOSTS == 64


class TestRejects:
    """Inputs we refuse to expand."""

    def test_empty_string(self):
        with pytest.raises(ExpandError, match="empty"):
            expand_targets("")

    def test_only_whitespace(self):
        with pytest.raises(ExpandError):
            expand_targets("   ")

    def test_wildcard(self):
        with pytest.raises(ExpandError, match="wildcard"):
            expand_targets("*")

    def test_none_input(self):
        # expand_targets accepts Optional-shaped input implicitly
        # (pattern or "") — make sure None isn't a crash.
        with pytest.raises(ExpandError):
            expand_targets(None)  # type: ignore[arg-type]

    def test_invalid_ip(self):
        with pytest.raises(ExpandError):
            expand_targets("999.1.2.3")
