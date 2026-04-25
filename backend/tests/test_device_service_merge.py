"""Tests for services.device_service merger functions.

Focus on the precedence rules that the docstrings promise — getting one
of them wrong causes visible data-quality regressions on the Devices
page. In particular:

  - UniFi confidence=1.0 must not be downgraded by a subsequent gateway
    merge (rule #2).
  - DHCP description (user-set "Alex's iPad") beats DHCP hostname
    (auto-generated "iPhone-von-Alex") — rule #3.
  - Metadata merges under the integration's own subkey; it never
    clobbers keys owned by other sources — rule #5.
  - Gateway merges never flip is_online from True to False (rule #4).
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Optional

import pytest

from services.device_service import (
    get_all_devices,
    merge_firewalla_devices,
    merge_gateway_leases,
)


pytestmark = pytest.mark.asyncio


# ─── Duck-typed fixtures mirroring the integration dataclasses ──────────


@dataclass
class FakeLease:
    mac: str
    address: str
    hostname: Optional[str] = None
    description: str = ""
    state: str = "active"
    interface: str = ""
    interface_description: str = ""
    manufacturer: str = ""


@dataclass
class FakeArp:
    mac: str
    ip: str
    hostname: Optional[str] = None
    interface: str = ""


@dataclass
class FakeFirewallaDevice:
    mac: str
    ip: str = ""
    name: str = ""
    vendor: str = ""
    online: bool = False
    gid: str = ""
    last_seen: Optional[float] = None
    network_name: str = ""
    group_name: str = ""


# ─── merge_gateway_leases ───────────────────────────────────────────────


async def test_lease_creates_new_device(initialised_db):
    await merge_gateway_leases(
        source="opnsense",
        source_label="OPNsense 24.7",
        leases=[FakeLease(mac="aa:bb:cc:dd:ee:ff", address="10.0.0.50", hostname="raspberry")],
    )
    devices = await get_all_devices()
    assert len(devices) == 1
    d = devices[0]
    assert d.mac == "aa:bb:cc:dd:ee:ff"
    assert d.ip == "10.0.0.50"
    assert d.hostname == "raspberry"
    assert d.device_type == "unknown"
    # Confidence 0.2 = "we saw a MAC but nothing else" — leaves room for
    # Nmap/UniFi to overwrite later.
    assert 0.1 < d.confidence <= 0.3
    assert d.is_online is True


async def test_lease_description_beats_hostname(initialised_db):
    # User-set description "Alex's iPad" wins over auto DHCP hostname
    # "iPhone-von-Alex" — rule #3.
    await merge_gateway_leases(
        source="opnsense",
        source_label="OPNsense",
        leases=[FakeLease(
            mac="aa:bb:cc:11:22:33",
            address="10.0.0.10",
            hostname="iPhone-von-Alex",
            description="Alex's iPad",
        )],
    )
    devices = await get_all_devices()
    assert devices[0].hostname == "Alex's iPad"


async def test_lease_does_not_downgrade_unifi_device(initialised_db):
    # Seed a UniFi-merged device with confidence=1.0 and a real device
    # type, then run a gateway lease merge at the same MAC. The gateway
    # merge must NOT overwrite device_type or lower the confidence.
    from database import get_db

    mac = "aa:bb:cc:dd:ee:01"
    device_id = f"dev-{mac.replace(':', '').lower()}"
    async with get_db() as db:
        await db.execute(
            """INSERT INTO devices
               (id, mac, ip, hostname, device_type, confidence, metadata,
                is_online, first_seen, last_seen)
               VALUES (?, ?, ?, ?, 'gateway', 1.0, '{"unifi_managed": true}', 1,
                       '2026-04-20T00:00:00+00:00', '2026-04-20T00:00:00+00:00')""",
            (device_id, mac, "10.0.0.1", "USG"),
        )
        await db.commit()

    await merge_gateway_leases(
        source="opnsense",
        source_label="OPNsense",
        leases=[FakeLease(
            mac=mac,
            address="10.0.0.1",
            hostname="iot-noise",
        )],
    )
    devices = await get_all_devices()
    assert len(devices) == 1
    d = devices[0]
    # Type unchanged, confidence preserved — rule #2. The merger never
    # UPDATES device_type or confidence on an existing row.
    assert d.device_type == "gateway"
    assert d.confidence == 1.0
    # Metadata merge adds our section without clobbering unifi_managed.
    assert d.metadata.get("unifi_managed") is True
    assert "opnsense_gateway" in d.metadata
    assert "opnsense" in d.metadata.get("seen_by", [])


async def test_arp_only_entry_fills_missing_fields(initialised_db):
    # ARP-only (no lease) is a valid path — static IPs that never
    # touched the DHCP server.
    await merge_gateway_leases(
        source="opnsense",
        source_label="OPNsense",
        leases=[],
        arp=[FakeArp(mac="11:22:33:44:55:66", ip="10.0.0.77", hostname="static-host", interface="LAN")],
    )
    devices = await get_all_devices()
    assert len(devices) == 1
    d = devices[0]
    assert d.ip == "10.0.0.77"
    assert d.hostname == "static-host"


async def test_lease_and_arp_lease_wins_for_overlapping_mac(initialised_db):
    # Same MAC in both lists — the lease entry is richer and should win.
    mac = "aa:bb:cc:dd:ee:02"
    await merge_gateway_leases(
        source="opnsense",
        source_label="OPNsense",
        leases=[FakeLease(mac=mac, address="10.0.0.20", hostname="lease-host", description="Lease Name")],
        arp=[FakeArp(mac=mac, ip="10.0.0.99", hostname="arp-host")],
    )
    devices = await get_all_devices()
    assert len(devices) == 1
    d = devices[0]
    # Lease's description ("Lease Name") wins over ARP's hostname.
    assert d.hostname == "Lease Name"
    # IP from the lease takes precedence over ARP.
    assert d.ip == "10.0.0.20"


async def test_lease_skips_rows_missing_mac(initialised_db):
    # No MAC = no device key. Skip rather than insert a half-useful row.
    await merge_gateway_leases(
        source="opnsense",
        source_label="OPNsense",
        leases=[FakeLease(mac="", address="10.0.0.100"), FakeLease(mac="aa:bb:cc:ee:ff:00", address="10.0.0.101")],
    )
    devices = await get_all_devices()
    assert len(devices) == 1
    assert devices[0].mac == "aa:bb:cc:ee:ff:00"


async def test_gateway_metadata_merge_preserves_other_integrations_keys(initialised_db):
    # Simulate UniFi having written a chunk, then Firewalla arrives.
    # Both integration sub-sections must coexist in metadata.
    mac = "aa:bb:cc:dd:ee:03"
    await merge_gateway_leases(
        source="opnsense",
        source_label="OPNsense",
        leases=[FakeLease(mac=mac, address="10.0.0.50")],
    )
    await merge_firewalla_devices(
        source_label="Firewalla Gold",
        devices=[FakeFirewallaDevice(mac=mac, ip="10.0.0.50", name="Couch TV", vendor="LG")],
    )
    devices = await get_all_devices()
    assert len(devices) == 1
    meta = devices[0].metadata
    assert "opnsense_gateway" in meta
    assert "firewalla_gateway" in meta
    # seen_by chip list contains both sources.
    seen_by = meta.get("seen_by", [])
    assert "opnsense" in seen_by
    assert "firewalla" in seen_by


# ─── merge_firewalla_devices ────────────────────────────────────────────


async def test_firewalla_online_flips_to_true(initialised_db):
    # A positive online sighting from Firewalla should commit is_online=1.
    await merge_firewalla_devices(
        source_label="Firewalla Gold",
        devices=[FakeFirewallaDevice(
            mac="aa:bb:cc:00:00:01",
            ip="10.0.0.10",
            name="Phone",
            online=True,
        )],
    )
    devices = await get_all_devices()
    assert devices[0].is_online is True


async def test_firewalla_offline_does_not_overwrite_true(initialised_db):
    # Rule #4: Firewalla-reported offline must NOT flip an existing
    # is_online=1 back to 0.
    from database import get_db

    mac = "aa:bb:cc:00:00:02"
    device_id = f"dev-{mac.replace(':', '').lower()}"
    async with get_db() as db:
        await db.execute(
            """INSERT INTO devices
               (id, mac, ip, hostname, device_type, confidence, metadata,
                is_online, first_seen, last_seen)
               VALUES (?, ?, ?, ?, 'unknown', 0.3, '{}', 1,
                       '2026-04-20T00:00:00+00:00', '2026-04-20T00:00:00+00:00')""",
            (device_id, mac, "10.0.0.10", "Existing"),
        )
        await db.commit()

    await merge_firewalla_devices(
        source_label="Firewalla Gold",
        devices=[FakeFirewallaDevice(mac=mac, ip="10.0.0.10", online=False)],
    )
    devices = await get_all_devices()
    assert devices[0].is_online is True  # still online per earlier sighting


async def test_firewalla_stores_metadata_under_namespaced_key(initialised_db):
    await merge_firewalla_devices(
        source_label="Firewalla Gold",
        devices=[FakeFirewallaDevice(
            mac="aa:bb:cc:00:00:03",
            ip="10.0.0.15",
            name="Nest Hub",
            vendor="Google",
            gid="gid-xyz",
            network_name="IoT",
            group_name="Smart Home",
            online=True,
            last_seen=1_712_345_678.0,
        )],
    )
    devices = await get_all_devices()
    fw = devices[0].metadata["firewalla_gateway"]
    assert fw["vendor"] == "Google"
    assert fw["network"] == "IoT"
    assert fw["group"] == "Smart Home"
    assert fw["gid"] == "gid-xyz"
    assert fw["firewalla_online"] is True
    assert fw["last_seen_ts"] == 1_712_345_678.0


async def test_firewalla_empty_input_is_noop(initialised_db):
    # Returns all devices (empty) without raising.
    devices = await merge_firewalla_devices(source_label="x", devices=[])
    assert devices == []


async def test_firewalla_skips_blank_mac(initialised_db):
    await merge_firewalla_devices(
        source_label="Firewalla",
        devices=[
            FakeFirewallaDevice(mac="", ip="10.0.0.1"),
            FakeFirewallaDevice(mac="aa:bb:cc:00:00:04", ip="10.0.0.2"),
        ],
    )
    devices = await get_all_devices()
    assert len(devices) == 1
    assert devices[0].mac == "aa:bb:cc:00:00:04"
