"""Tests for integrations.opnsense.

OPNsense's REST API has a few version-dependent quirks we carry
workarounds for. These tests exercise the shape-normalisation paths
without standing up a real firewall — httpx calls are intercepted
by respx.

Focus:
  - Lease parsing handles both old and new field names.
  - ARP endpoint fallback: get_arp (25.7+) → getArp (pre-25.7).
  - Alert parsing: Suricata eve.json shape with and without _source wrap.
  - Alert fingerprint determinism (dedup depends on it being stable).
  - test_connection status-code discrimination (401 → auth-error message).
"""
from __future__ import annotations

import httpx
import pytest
import respx

from integrations.opnsense import (
    OPNsenseAlert,
    OPNsenseIntegration,
    OPNsenseLease,
)


pytestmark = pytest.mark.asyncio

_URL = "https://10.0.0.1"


def _integ(ids_enabled: bool = True) -> OPNsenseIntegration:
    return OPNsenseIntegration(
        url=_URL,
        api_key="test-key",
        api_secret="test-secret",
        verify_ssl=False,
        ids_enabled=ids_enabled,
    )


class TestLeaseParsing:
    @respx.mock
    async def test_parses_search_lease_envelope(self):
        respx.get(f"{_URL}/api/dhcpv4/leases/search_lease").mock(
            return_value=httpx.Response(
                200,
                headers={"content-type": "application/json"},
                json={
                    "total": 2, "rowCount": 2, "current": 1,
                    "rows": [
                        {
                            "address": "10.0.0.50",
                            "mac": "AA:BB:CC:DD:EE:FF",
                            "hostname": "raspberry",
                            "state": "active",
                            "descr": "Pi hole",
                            "if": "em1",
                            "if_descr": "LAN",
                            "man": "Raspberry Pi Foundation",
                        },
                        {
                            "address": "10.0.0.51",
                            "mac": "11:22:33:44:55:66",
                            "hostname": "",
                            "state": "expired",
                        },
                    ],
                },
            )
        )
        async with _integ()._client() as c:
            leases = await _integ().fetch_leases(c)
        assert len(leases) == 2
        assert leases[0].mac == "aa:bb:cc:dd:ee:ff"   # lowercased
        assert leases[0].hostname == "raspberry"
        assert leases[0].description == "Pi hole"
        assert leases[0].interface == "em1"
        assert leases[0].interface_description == "LAN"

    @respx.mock
    async def test_skips_rows_without_mac_or_ip(self):
        respx.get(f"{_URL}/api/dhcpv4/leases/search_lease").mock(
            return_value=httpx.Response(200, headers={"content-type": "application/json"}, json={
                "rows": [
                    {"address": "", "mac": ""},           # both blank
                    {"address": "10.0.0.10"},             # missing mac
                    {"mac": "aa:bb:cc:00:00:01"},         # missing ip
                    {"address": "10.0.0.11", "mac": "aa:bb:cc:00:00:02"},
                ],
            })
        )
        async with _integ()._client() as c:
            leases = await _integ().fetch_leases(c)
        assert len(leases) == 1
        assert leases[0].mac == "aa:bb:cc:00:00:02"

    @respx.mock
    async def test_dhcp_404_falls_back_to_kea(self):
        respx.get(f"{_URL}/api/dhcpv4/leases/search_lease").mock(
            return_value=httpx.Response(404)
        )
        respx.get(f"{_URL}/api/kea/leases4/search").mock(
            return_value=httpx.Response(
                200, headers={"content-type": "application/json"},
                json={"rows": [{"ip_address": "10.0.0.60", "hwaddr": "aa:bb:cc:00:00:03"}]},
            )
        )
        async with _integ()._client() as c:
            leases = await _integ().fetch_leases(c)
        assert len(leases) == 1
        assert leases[0].address == "10.0.0.60"
        assert leases[0].mac == "aa:bb:cc:00:00:03"


class TestArpEndpointFallback:
    @respx.mock
    async def test_uses_get_arp_first(self):
        # 25.7+ path works → we never reach the legacy alias.
        respx.get(f"{_URL}/api/diagnostics/interface/get_arp").mock(
            return_value=httpx.Response(
                200, headers={"content-type": "application/json"},
                json=[
                    {"mac": "AA:BB:CC:00:00:10", "ip": "10.0.0.10", "intf": "LAN", "permanent": "no"},
                ],
            )
        )
        async with _integ()._client() as c:
            arp = await _integ().fetch_arp(c)
        assert len(arp) == 1
        assert arp[0].mac == "aa:bb:cc:00:00:10"
        assert arp[0].interface == "LAN"
        assert arp[0].permanent is False

    @respx.mock
    async def test_falls_back_to_legacy_get_arp_on_404(self):
        respx.get(f"{_URL}/api/diagnostics/interface/get_arp").mock(
            return_value=httpx.Response(404)
        )
        respx.get(f"{_URL}/api/diagnostics/interface/getArp").mock(
            return_value=httpx.Response(
                200, headers={"content-type": "application/json"},
                json=[{"mac_address": "aa:bb:cc:00:00:11", "ip_address": "10.0.0.11"}],
            )
        )
        async with _integ()._client() as c:
            arp = await _integ().fetch_arp(c)
        assert len(arp) == 1
        assert arp[0].mac == "aa:bb:cc:00:00:11"

    @respx.mock
    async def test_both_404_returns_empty(self):
        respx.get(f"{_URL}/api/diagnostics/interface/get_arp").mock(
            return_value=httpx.Response(404)
        )
        respx.get(f"{_URL}/api/diagnostics/interface/getArp").mock(
            return_value=httpx.Response(404)
        )
        async with _integ()._client() as c:
            arp = await _integ().fetch_arp(c)
        assert arp == []


class TestAlertParsing:
    @respx.mock
    async def test_parses_eve_style_alert(self):
        respx.post(f"{_URL}/api/ids/service/query_alerts").mock(
            return_value=httpx.Response(
                200, headers={"content-type": "application/json"},
                json={"rows": [
                    {
                        "_source": {
                            "timestamp": "2026-04-21T18:40:12.123456+0000",
                            "src_ip": "192.168.1.50",
                            "dest_ip": "1.1.1.1",
                            "proto": "TCP",
                            "alert": {
                                "signature": "ET TROJAN Possible Emotet HTTP",
                                "category": "A Network Trojan was detected",
                                "severity": 1,
                            },
                        },
                    },
                ]},
            )
        )
        async with _integ()._client() as c:
            alerts = await _integ().fetch_alerts(c)
        assert len(alerts) == 1
        a = alerts[0]
        assert a.signature == "ET TROJAN Possible Emotet HTTP"
        assert a.src_ip == "192.168.1.50"
        assert a.dst_ip == "1.1.1.1"
        assert a.severity == 1
        # Fingerprint shape: src|dst|sig|minute_bucket (YYYY-MM-DDTHH:MM)
        assert a.fingerprint == "192.168.1.50|1.1.1.1|ET TROJAN Possible Emotet HTTP|2026-04-21T18:40"

    @respx.mock
    async def test_alert_fingerprint_is_deterministic(self):
        # Same input → same fingerprint (required for dedup to work).
        payload = {"rows": [
            {
                "timestamp": "2026-04-21T18:40:12.123+0000",
                "src_ip": "192.168.1.50",
                "dest_ip": "1.1.1.1",
                "alert": {"signature": "ET TROJAN Test", "severity": 2, "category": "Trojan"},
            },
        ]}
        respx.post(f"{_URL}/api/ids/service/query_alerts").mock(
            return_value=httpx.Response(200, headers={"content-type": "application/json"}, json=payload)
        )
        async with _integ()._client() as c:
            a1 = await _integ().fetch_alerts(c)
            a2 = await _integ().fetch_alerts(c)
        assert a1[0].fingerprint == a2[0].fingerprint

    @respx.mock
    async def test_alert_skips_blank_signature(self):
        respx.post(f"{_URL}/api/ids/service/query_alerts").mock(
            return_value=httpx.Response(
                200, headers={"content-type": "application/json"},
                json={"rows": [
                    {"alert": {"signature": ""}, "src_ip": "1.1.1.1", "dest_ip": "2.2.2.2"},
                    {"alert": {"signature": "valid"}, "src_ip": "1.1.1.1", "dest_ip": "2.2.2.2",
                     "timestamp": "2026-04-21T18:40+00:00"},
                ]},
            )
        )
        async with _integ()._client() as c:
            alerts = await _integ().fetch_alerts(c)
        assert len(alerts) == 1
        assert alerts[0].signature == "valid"

    @respx.mock
    async def test_alerts_disabled_returns_empty_without_call(self):
        # When ids_enabled=False, no HTTP call is made. If one were to
        # happen, respx would raise (no route configured).
        integ = _integ(ids_enabled=False)
        async with integ._client() as c:
            alerts = await integ.fetch_alerts(c)
        assert alerts == []

    @respx.mock
    async def test_alerts_404_returns_empty(self):
        # IDS plugin not installed → 404 → empty, not exception.
        respx.post(f"{_URL}/api/ids/service/query_alerts").mock(
            return_value=httpx.Response(404)
        )
        async with _integ()._client() as c:
            alerts = await _integ().fetch_alerts(c)
        assert alerts == []


class TestTestConnection:
    @respx.mock
    async def test_401_returns_auth_error_message(self):
        # The test_connection path discriminates 401/403 into a
        # user-friendly message so the Settings UI can render it
        # verbatim without a lookup table.
        respx.get(f"{_URL}/api/core/firmware/status").mock(
            return_value=httpx.Response(401, json={"detail": "unauthorised"})
        )
        res = await _integ().test_connection()
        assert res.ok is False
        assert "authent" in res.message.lower()

    async def test_missing_creds_fails_fast(self):
        integ = OPNsenseIntegration(url="", api_key="", api_secret="")
        res = await integ.test_connection()
        assert res.ok is False
        assert "required" in res.message.lower()

    @respx.mock
    async def test_success_surfaces_product_version(self):
        respx.get(f"{_URL}/api/core/firmware/status").mock(
            return_value=httpx.Response(
                200, headers={"content-type": "application/json"},
                json={"product_name": "OPNsense", "product_version": "24.7.4"},
            )
        )
        respx.get(f"{_URL}/api/diagnostics/system/system_information").mock(
            return_value=httpx.Response(
                200, headers={"content-type": "application/json"},
                json={"name": "fw01", "versions": {"product_version": "24.7.4"}},
            )
        )
        res = await _integ().test_connection()
        assert res.ok is True
        assert "24.7.4" in res.message
