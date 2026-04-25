"""Tests for integrations.firewalla.

Firewalla's MSP API has a bunch of small idiosyncrasies we absorb at
parse time. Most importantly:

  - Auth header is `Authorization: Token <pat>`, NOT `Bearer <pat>`.
    Getting this wrong returns a deceptively generic 401. The
    `_headers()` helper centralises it; we assert the exact shape.
  - Alarm `type` is a numeric code that maps to our 5-level severity
    vocabulary. The `_type_to_severity` map is the source of truth
    for the Security page colour palette.
  - Cursor pagination loops with a hard safety cap.
  - Alarm fingerprint shape: `gid|mac|type|minute_bucket`.
"""
from __future__ import annotations

import httpx
import pytest
import respx

from integrations.firewalla import (
    FirewallaIntegration,
    _parse_alarm,
    _type_to_label,
    _type_to_severity,
)


# asyncio_mode=auto in pytest.ini detects `async def` tests automatically;
# we don't apply a module-level asyncio mark because that spuriously
# flags sync tests (e.g. the pure-parsing cases below).

_DOMAIN = "acme.firewalla.net"
_BASE = f"https://{_DOMAIN}/v2"


def _integ() -> FirewallaIntegration:
    return FirewallaIntegration(
        mode="msp",
        msp_domain=_DOMAIN,
        msp_token="pat_abc123",
        verify_ssl=False,
    )


class TestAuthHeader:
    """The single rule that's easy to mess up and breaks everything:
    `Authorization: Token <pat>`, not `Bearer <pat>`."""

    def test_msp_uses_token_scheme_not_bearer(self):
        headers = _integ()._headers()
        auth = headers["Authorization"]
        assert auth.startswith("Token "), f"wrong auth scheme: {auth!r}"
        assert not auth.startswith("Bearer "), "must be Token, not Bearer"
        assert auth == "Token pat_abc123"

    def test_local_mode_sends_both_auth_headers(self):
        integ = FirewallaIntegration(
            mode="local",
            local_url="http://10.0.0.1:8833",
            local_token="fireguard_xyz",
        )
        headers = integ._headers()
        assert headers["Authorization"] == "Token fireguard_xyz"
        # Community projects differ on header name; we send both.
        assert headers["X-Auth-Token"] == "fireguard_xyz"

    def test_empty_token_produces_empty_header_dict(self):
        integ = FirewallaIntegration(mode="msp", msp_domain=_DOMAIN, msp_token="")
        assert integ._headers() == {}


class TestIsConfigured:
    def test_msp_requires_domain_and_token(self):
        assert _integ().is_configured() is True
        assert FirewallaIntegration(mode="msp", msp_domain="x", msp_token="").is_configured() is False
        assert FirewallaIntegration(mode="msp", msp_domain="", msp_token="x").is_configured() is False

    def test_local_requires_url(self):
        assert FirewallaIntegration(mode="local", local_url="http://1.2.3.4").is_configured() is True
        assert FirewallaIntegration(mode="local").is_configured() is False


class TestSeverityMap:
    """The type_code → severity map is exposed through _type_to_severity
    and must stay stable — the Security page palette and the severity
    filter both depend on this vocabulary."""

    def test_known_codes_map_correctly(self):
        # Spot-check the five severity bands.
        assert _type_to_severity("1") == "high"        # Security Activity
        assert _type_to_severity("2") == "medium"      # Abnormal Upload
        assert _type_to_severity("3") == "low"         # Large Bandwidth
        assert _type_to_severity("5") == "info"        # New Device
        assert _type_to_severity("14") == "medium"     # Open Port
        assert _type_to_severity("15") == "high"       # Internet Connectivity

    def test_unknown_code_falls_back_to_info(self):
        # Never drop an alarm on the floor; surface unknown types as info.
        assert _type_to_severity("999") == "info"
        assert _type_to_severity(None) == "info"
        assert _type_to_severity("") == "info"

    def test_int_and_str_keys_both_accepted(self):
        # The API returns string codes on most endpoints and ints on
        # others. _type_to_severity normalises.
        assert _type_to_severity(1) == _type_to_severity("1")
        assert _type_to_severity(14) == _type_to_severity("14")

    def test_label_lookup_has_human_strings(self):
        assert _type_to_label("1") == "Security Activity"
        assert _type_to_label("5") == "New Device"
        # Unknown code falls back to "Type N" for display.
        assert _type_to_label("999").startswith("Type ")


class TestAlarmParsing:
    @staticmethod
    def _raw(**overrides) -> dict:
        base = {
            "aid": "alarm-uuid-1",
            "gid": "gid-abc123",
            "type": "1",
            "status": "active",
            "ts": 1_712_345_678.0,  # 2024-04-05T19:34:38 UTC
            "message": "Suspicious connection blocked",
            "device": {"id": "aa:bb:cc:dd:ee:01", "name": "Couch TV", "ip": "192.168.1.50"},
            "remote": {"ip": "80.82.77.139", "domain": ""},
            "direction": "outbound",
            "protocol": "tcp",
        }
        base.update(overrides)
        return base

    def test_parse_minimal_alarm(self):
        a = _parse_alarm(self._raw())
        assert a is not None
        assert a.severity == "high"
        assert a.category == "Security Activity"
        assert a.message == "Suspicious connection blocked"
        assert a.src_ip == "192.168.1.50"
        assert a.dst_ip == "80.82.77.139"
        assert a.device_id == "aa:bb:cc:dd:ee:01"
        assert a.device_name == "Couch TV"

    def test_fingerprint_shape(self):
        # gid | mac | type | minute_bucket
        a = _parse_alarm(self._raw())
        parts = a.fingerprint.split("|")
        assert parts[0] == "gid-abc123"
        assert parts[1] == "aa:bb:cc:dd:ee:01"
        assert parts[2] == "1"
        # Minute bucket matches the ts: 2024-04-05T19:34 UTC
        assert parts[3] == "2024-04-05T19:34"

    def test_fingerprint_is_deterministic(self):
        r = self._raw()
        assert _parse_alarm(r).fingerprint == _parse_alarm(r).fingerprint

    def test_non_active_status_skipped(self):
        # Even though our query filters to status:active, belt-and-braces
        # the parser drops non-active rows.
        assert _parse_alarm(self._raw(status="archived")) is None
        assert _parse_alarm(self._raw(status="resolved")) is None

    def test_blank_message_synthesised(self):
        a = _parse_alarm(self._raw(message=""))
        assert a is not None
        assert "Security Activity" in a.message

    def test_missing_message_and_type_is_rejected(self):
        # Nothing to render → parser returns None so we don't insert a
        # blank row.
        raw = self._raw(message="")
        raw.pop("type")
        raw["type"] = None
        assert _parse_alarm(raw) is None


class TestFetchAlarmsPagination:
    @respx.mock
    async def test_walks_cursor_pages(self):
        # Two pages. The first response has next_cursor set; the second
        # doesn't, which terminates the loop.
        route = respx.get(f"{_BASE}/alarms").mock(
            side_effect=[
                httpx.Response(
                    200, headers={"content-type": "application/json"},
                    json={"results": [
                        {"aid": "a1", "gid": "g", "type": "1", "status": "active",
                         "device": {"id": "aa:bb:cc:00:00:01"}, "remote": {}, "ts": 1_712_345_678, "message": "m1"},
                    ], "next_cursor": "page2"},
                ),
                httpx.Response(
                    200, headers={"content-type": "application/json"},
                    json={"results": [
                        {"aid": "a2", "gid": "g", "type": "2", "status": "active",
                         "device": {"id": "aa:bb:cc:00:00:02"}, "remote": {}, "ts": 1_712_345_700, "message": "m2"},
                    ]},
                ),
            ]
        )
        async with _integ()._client() as c:
            alarms = await _integ().fetch_alarms(c)
        assert len(alarms) == 2
        assert route.call_count == 2

    @respx.mock
    async def test_rate_limit_stops_gracefully(self):
        respx.get(f"{_BASE}/alarms").mock(
            return_value=httpx.Response(429, json={"error": "rate-limited"})
        )
        async with _integ()._client() as c:
            alarms = await _integ().fetch_alarms(c)
        # 429 is handled gracefully — empty result, no exception.
        assert alarms == []


class TestFetchBoxes:
    @respx.mock
    async def test_parses_box_roster(self):
        respx.get(f"{_BASE}/boxes").mock(
            return_value=httpx.Response(
                200, headers={"content-type": "application/json"},
                json={"results": [
                    {
                        "gid": "box-gid-1",
                        "name": "HomeLab Firewalla Gold",
                        "model": "Gold",
                        "online": True,
                        "version": "1.975",
                        "publicIP": "1.2.3.4",
                        "lastSeen": 1_712_345_678,
                        "deviceCount": 42,
                        "alarmCount": 7,
                    },
                    {"gid": "", "name": "empty-gid-skipped"},
                ]},
            )
        )
        async with _integ()._client() as c:
            boxes = await _integ().fetch_boxes(c)
        assert len(boxes) == 1   # empty-gid row dropped
        b = boxes[0]
        assert b.gid == "box-gid-1"
        assert b.model == "Gold"
        assert b.online is True
        assert b.device_count == 42


class TestTestConnection:
    @respx.mock
    async def test_success_reports_box_count(self):
        respx.get(f"{_BASE}/boxes").mock(
            return_value=httpx.Response(
                200, headers={"content-type": "application/json"},
                json={"results": [
                    {"gid": "g1", "name": "Box A", "online": True},
                    {"gid": "g2", "name": "Box B", "online": False},
                ]},
            )
        )
        res = await _integ().test_connection()
        assert res.ok is True
        assert res.detail["box_count"] == 2

    @respx.mock
    async def test_401_reports_auth_error(self):
        respx.get(f"{_BASE}/boxes").mock(return_value=httpx.Response(401, json={"error": "unauth"}))
        res = await _integ().test_connection()
        assert res.ok is False
        assert "authent" in res.message.lower() or "token" in res.message.lower()

    async def test_unconfigured_fails_fast(self):
        integ = FirewallaIntegration(mode="msp")
        res = await integ.test_connection()
        assert res.ok is False
