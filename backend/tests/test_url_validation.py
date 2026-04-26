"""F-002: SSRF target-host validation for the Settings test-* endpoints.

The validator's job: reject hosts that resolve to link-local /
cloud-metadata / IPv6-link-local addresses; allow everything else (RFC1918,
loopback, public hosts) so the homelab use case keeps working.

DNS-based tests are kept light to avoid CI flakiness — most coverage runs
against IP literals and the synthetic _check_resolved_addrs helper. See
the module docstring in services/url_validation.py for the policy.
"""

from __future__ import annotations

import ipaddress

import pytest

from services.url_validation import (
    TargetValidationError,
    _check_resolved_addrs,
    parse_host,
    validate_outbound_target,
)


# ─── parse_host ─────────────────────────────────────────────────────────


class TestParseHost:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("example.com", "example.com"),
            ("192.168.1.50", "192.168.1.50"),
            ("192.168.1.50:9200", "192.168.1.50"),
            ("https://example.com:8443/path", "example.com"),
            ("http://10.0.0.5", "10.0.0.5"),
            # IPv6 in URL form is bracketed
            ("http://[fe80::1]:80/", "fe80::1"),
            # Trailing whitespace is stripped
            ("  10.0.0.5  ", "10.0.0.5"),
        ],
    )
    def test_parses_supported_shapes(self, raw, expected):
        assert parse_host(raw) == expected

    @pytest.mark.parametrize("bad", ["", "   ", "://"])
    def test_rejects_empty_or_malformed(self, bad):
        with pytest.raises(TargetValidationError):
            parse_host(bad)


# ─── _check_resolved_addrs (synthetic IPs, no DNS) ──────────────────────


class TestDenyRules:
    """Pure denylist tests that don't touch DNS — feed in addresses that
    we built directly, verify the policy decision."""

    @pytest.mark.parametrize(
        "ip_str",
        [
            # Cloud metadata IPs — the headline target
            "169.254.169.254",  # AWS / Azure / GCP IMDS
            "169.254.169.123",  # anywhere in IPv4 link-local
            "169.254.0.1",
            "169.254.255.255",
            # Other IPv4 link-local boundary
            "0.0.0.0",
            "0.1.2.3",
            # IPv6 link-local
            "fe80::1",
            "fe80::abcd:ef01",
            # IPv6 multicast
            "ff02::1",
            # IPv6 unspecified
            "::",
        ],
    )
    def test_denied_ranges(self, ip_str):
        with pytest.raises(TargetValidationError):
            _check_resolved_addrs([ipaddress.ip_address(ip_str)])

    @pytest.mark.parametrize(
        "ip_str",
        [
            # Loopback — operator running ES locally
            "127.0.0.1",
            "127.1.2.3",
            # RFC1918 — the homelab default
            "10.0.0.5",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.1.50",
            # Public — Firewalla MSP cloud, Ollama remote, etc.
            "8.8.8.8",
            "104.21.5.5",
            # IPv6 loopback + ULA
            "::1",
            "fc00::1",  # Unique local address (private IPv6)
        ],
    )
    def test_allowed_ranges(self, ip_str):
        # Should not raise.
        _check_resolved_addrs([ipaddress.ip_address(ip_str)])

    def test_any_denied_in_list_blocks(self):
        # If a hostname resolves to [allowed, denied] (DNS-rebinding-shaped
        # answer), we reject — we never trust "the first non-denied one"
        # because the kernel can pick a different element on the actual
        # connect.
        addrs = [
            ipaddress.ip_address("10.0.0.5"),
            ipaddress.ip_address("169.254.169.254"),
        ]
        with pytest.raises(TargetValidationError):
            _check_resolved_addrs(addrs)


# ─── validate_outbound_target (end-to-end, IP literal path) ─────────────


class TestValidateOutboundTarget:
    def test_accepts_ipv4_literal_in_allowed_range(self):
        assert validate_outbound_target("10.0.0.5") == "10.0.0.5"

    def test_accepts_loopback(self):
        assert validate_outbound_target("127.0.0.1") == "127.0.0.1"

    def test_accepts_rfc1918_with_port(self):
        # parse_host strips the port, validate_outbound_target returns
        # just the host string.
        assert validate_outbound_target("192.168.1.50:9200") == "192.168.1.50"

    def test_accepts_url_with_scheme(self):
        assert (
            validate_outbound_target("http://192.168.1.50:9200/_cat") == "192.168.1.50"
        )

    def test_rejects_aws_imds_literal(self):
        with pytest.raises(TargetValidationError) as ei:
            validate_outbound_target("169.254.169.254")
        # Error message must NOT contain raw response data — it's
        # the policy decision only. Spot-check by ensuring the
        # message references the deny rule.
        assert "denied range" in str(ei.value)

    def test_rejects_url_pointing_at_imds(self):
        with pytest.raises(TargetValidationError):
            validate_outbound_target("http://169.254.169.254/latest/meta-data/")

    def test_rejects_ipv6_link_local(self):
        with pytest.raises(TargetValidationError):
            validate_outbound_target("fe80::1")

    def test_rejects_ipv6_link_local_url(self):
        with pytest.raises(TargetValidationError):
            validate_outbound_target("http://[fe80::1]:80/")

    def test_rejects_empty_input(self):
        with pytest.raises(TargetValidationError):
            validate_outbound_target("")

    def test_rejects_unresolvable_name(self):
        # A name that won't resolve via getaddrinfo. Use a name we
        # know cannot be a real DNS record. The .invalid TLD is
        # reserved per RFC 2606 specifically for this purpose —
        # public DNS will never have a record for it.
        with pytest.raises(TargetValidationError) as ei:
            validate_outbound_target("nonexistent.invalid")
        assert "could not resolve" in str(ei.value)


# ─── Integration with /api/setup/test-* endpoints ───────────────────────


class TestSetupEndpointsRejectIMDS:
    """End-to-end: the test-* endpoints must 400 when given a denied
    target. We exercise the Elasticsearch one because it's the
    canonical SSRF target (returns response body) — the other
    endpoints share the same _gate helper, so this single integration
    test verifies the wire-up shape."""

    def test_test_elasticsearch_blocks_imds(self, api_client):
        r = api_client.post(
            "/api/setup/test-elasticsearch",
            json={
                "host": "169.254.169.254",
                "port": 80,
                "user": "",
                "password": "",
            },
        )
        assert r.status_code == 400
        # Body content must NOT include any response data — only the
        # policy reason.
        body = r.json()
        assert "denied range" in body.get("detail", "")

    def test_test_elasticsearch_blocks_ipv6_link_local(self, api_client):
        r = api_client.post(
            "/api/setup/test-elasticsearch",
            json={
                "host": "fe80::1",
                "port": 9200,
                "user": "",
                "password": "",
            },
        )
        assert r.status_code == 400

    def test_test_unifi_blocks_imds_url(self, api_client):
        r = api_client.post(
            "/api/setup/test-unifi",
            json={
                "url": "http://169.254.169.254/api",
                "user": "x",
                "password": "x",
            },
        )
        assert r.status_code == 400
