"""F-009: device-table allowlist on /api/vulns/credentials/test.

Without this gate, a token-bearing caller can probe arbitrary LAN
IPs by submitting a range pattern — the dashboard would dutifully
SSH to all of them. The fix bounds targets to IPs already in the
devices table (i.e. discovered via Nmap / UniFi / OPNsense /
Firewalla). IPs outside the inventory are filtered out and reported
in `unknown_targets`.

We exercise the endpoint via api_client so the DB layer + auth
middleware behave the same as production. probe_many is monkey-
patched to a stub that records the IPs it was asked to probe — we
never want a real SSH connection in tests.

Implementation note: the api_client TestClient drives the FastAPI app
synchronously and runs its own event loop for the lifespan. The
api-client tests here are synchronous functions to avoid event-loop
overlap with pytest-asyncio. The DB seeding uses stdlib sqlite3
(also sync) to match.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone

import aiosqlite
import pytest


# Minimal stand-in for services.ssh_probe.ProbeResult — avoids importing
# the real one through services.ssh_probe (which pulls asyncssh and
# would couple unrelated test paths to that dep).
@dataclass
class _FakeProbeResult:
    ip: str
    status: str = "ok"
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "status": self.status,
            "detail": self.detail,
            "ok": self.ok,
        }


def _seed_devices_sync(db_path: str, ips: list[str]) -> None:
    """Insert one row per IP using stdlib sqlite3 (synchronous).

    Note: the api_client fixture's lifespan calls init_db, but
    database.DB_PATH is a module-level constant bound at first import
    — subsequent tests don't re-bind it even though they reload main.
    So the api_client's init_db may have run against the *first*
    test's tmp_path, leaving later tests' tmp_path DBs empty. We
    ensure the schema exists here directly via CREATE TABLE IF NOT
    EXISTS — the production schema also uses that idiom, so we
    aren't drifting from the real DDL.
    """
    now = datetime.now(timezone.utc).isoformat()
    # Pull the canonical schema from the database module so this seed
    # helper stays in lockstep with future schema changes.
    from database import SCHEMA

    with sqlite3.connect(db_path) as db:
        db.executescript(SCHEMA)
        for i, ip in enumerate(ips):
            db.execute(
                """INSERT INTO devices
                       (id, mac, ip, hostname, first_seen, last_seen, is_online)
                   VALUES (?,?,?,?,?,?,1)""",
                (
                    f"dev-cred-test-{i}",
                    f"aa:bb:cc:dd:ee:{i:02x}",
                    ip,
                    f"host-{i}",
                    now,
                    now,
                ),
            )
        db.commit()


def _stub_probe_many(monkeypatch):
    """Replace probe_many with a stub that returns 'ok' for every IP it's
    asked to probe and records the call in `recorded`. Returns the list
    so each test can inspect what reached the SSH layer."""
    recorded: list[list[str]] = []

    async def fake(ips, username, **kwargs):
        recorded.append(list(ips))
        return [_FakeProbeResult(ip=ip, status="ok", detail="") for ip in ips]

    # The endpoint does `from services.ssh_probe import probe_many` inside
    # the handler body — patching the symbol on the module works whether
    # the test file imports it before or after.
    monkeypatch.setattr("services.ssh_probe.probe_many", fake)
    return recorded


def _post_test_credential(client, **body):
    return client.post(
        "/api/vulns/credentials/test",
        json={
            "username": "ops",
            "auth_type": "password",
            "password": "hunter2",
            **body,
        },
    )


def test_probes_only_ips_in_devices_table(api_client, monkeypatch, tmp_path):
    """Submit a range that includes both known and unknown IPs.
    The endpoint should probe only the known ones and return the
    others in unknown_targets."""
    db_path = str(tmp_path / "api-test.db")
    _seed_devices_sync(db_path, ["10.0.0.5", "10.0.0.7"])

    recorded = _stub_probe_many(monkeypatch)

    r = _post_test_credential(api_client, target_ip="10.0.0.5-10")
    assert r.status_code == 200, r.text
    body = r.json()

    # Only the two seeded IPs should have reached probe_many
    assert recorded == [["10.0.0.5", "10.0.0.7"]]
    # Filtered IPs are surfaced in unknown_targets so the operator sees
    # what got dropped
    assert sorted(body["unknown_targets"]) == [
        "10.0.0.10",
        "10.0.0.6",
        "10.0.0.8",
        "10.0.0.9",
    ]
    assert body["host_count"] == 2
    assert body["ok_count"] == 2
    assert body["all_ok"] is True


def test_400_when_no_targets_in_inventory(api_client, monkeypatch, tmp_path):
    """When *every* expanded IP is unknown, return 400 with a helpful
    detail. Otherwise the endpoint would 200 with host_count=0, which
    is a misleading "success" for an attempted spray."""
    # No devices seeded — every IP is unknown.
    recorded = _stub_probe_many(monkeypatch)

    r = _post_test_credential(api_client, target_ip="10.0.0.50-52")
    assert r.status_code == 400
    detail = r.json()["detail"]
    assert "no targets in the devices table" in detail
    # Filtered list (capped at 10) appears in the error message so the
    # operator knows which IPs got dropped.
    assert "10.0.0.50" in detail

    # And probe_many must NEVER have been called — the spray surface
    # is gated entirely.
    assert recorded == []


def test_single_known_target_works(api_client, monkeypatch, tmp_path):
    """Plain single-IP submission against a known device — the common
    case the F-009 fix must not break."""
    db_path = str(tmp_path / "api-test.db")
    _seed_devices_sync(db_path, ["192.168.1.50"])

    recorded = _stub_probe_many(monkeypatch)

    r = _post_test_credential(api_client, target_ip="192.168.1.50")
    assert r.status_code == 200
    body = r.json()
    assert recorded == [["192.168.1.50"]]
    assert body["unknown_targets"] == []
    assert body["all_ok"] is True


@pytest.mark.asyncio
async def test_known_device_ips_helper(initialised_db):
    """Direct unit test for services.device_service.known_device_ips —
    isolates the SQL from the API plumbing."""
    from services.device_service import known_device_ips

    now = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(initialised_db) as db:
        await db.execute(
            """INSERT INTO devices
                   (id, mac, ip, hostname, first_seen, last_seen, is_online)
               VALUES (?,?,?,?,?,?,1)""",
            ("dev-known-1", "11:22:33:44:55:66", "10.0.0.1", "h1", now, now),
        )
        await db.execute(
            """INSERT INTO devices
                   (id, mac, ip, hostname, first_seen, last_seen, is_online)
               VALUES (?,?,?,?,?,?,1)""",
            ("dev-known-2", "11:22:33:44:55:77", "10.0.0.2", "h2", now, now),
        )
        await db.commit()

    found = await known_device_ips(["10.0.0.1", "10.0.0.2", "10.0.0.99"])
    assert found == {"10.0.0.1", "10.0.0.2"}

    # Empty input short-circuits without a DB roundtrip
    assert await known_device_ips([]) == set()
