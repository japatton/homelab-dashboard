"""F-004: foreign_keys PRAGMA + orphan cleanup.

Up through v1.1.0 the schema declared `ON DELETE CASCADE` on
device_services but `PRAGMA foreign_keys` defaulted OFF, so the cascade
never fired and a deleted device's rows orphaned forever. The fix
flips the PRAGMA on per connection in init_db() and get_db(), and
runs a one-shot orphan-cleanup migration on startup.

These tests verify both:
  - the PRAGMA is actually set on a get_db() connection (not just on
    init_db's transient one)
  - device_services cascade fires on a real device delete
  - orphan rows that pre-date the migration get cleaned up by
    init_db's cleanup pass and counted for the audit log
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import aiosqlite
import pytest


pytestmark = pytest.mark.asyncio


async def test_pragma_foreign_keys_is_on_for_get_db(initialised_db):
    """get_db() must set foreign_keys=ON every time. The PRAGMA is
    connection-scoped — init_db's setting doesn't carry over to a fresh
    aiosqlite.connect() in the request path."""
    from database import get_db

    async with get_db() as db:
        cur = await db.execute("PRAGMA foreign_keys")
        row = await cur.fetchone()
        assert row[0] == 1, "foreign_keys is OFF on get_db connections"


async def test_cascade_fires_on_device_delete(initialised_db):
    """ON DELETE CASCADE on device_services should now actually fire.
    Without F-004 this test would leave the service row orphaned."""
    from database import get_db

    async with get_db() as db:
        # Insert a device + a service row pointing at it
        await db.execute(
            """INSERT INTO devices (id, mac, ip, hostname, first_seen, last_seen,
                                    is_online)
               VALUES (?,?,?,?,?,?,1)""",
            (
                "dev-fktest",
                "aa:bb:cc:dd:ee:ff",
                "10.0.0.5",
                "fk-test-host",
                datetime.now(timezone.utc).isoformat(),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        await db.execute(
            """INSERT INTO device_services
                  (device_id, port, protocol, name, version)
               VALUES (?,?,?,?,?)""",
            ("dev-fktest", 22, "tcp", "ssh", "OpenSSH_8.4"),
        )
        await db.commit()

        # Sanity check the service was inserted
        cur = await db.execute(
            "SELECT COUNT(*) FROM device_services WHERE device_id = ?",
            ("dev-fktest",),
        )
        assert (await cur.fetchone())[0] == 1

        # Delete the device — cascade should remove the service
        await db.execute("DELETE FROM devices WHERE id = ?", ("dev-fktest",))
        await db.commit()

        cur = await db.execute(
            "SELECT COUNT(*) FROM device_services WHERE device_id = ?",
            ("dev-fktest",),
        )
        assert (await cur.fetchone())[0] == 0, "cascade did not fire"


async def test_init_db_cleans_up_pre_migration_orphans(tmp_path, monkeypatch):
    """Simulate a v1.1.0-and-prior database where foreign_keys was OFF
    and orphans accumulated. Then init_db should detect and remove
    them, returning counts to the audit log."""
    db_path = tmp_path / "orphans.db"
    monkeypatch.setenv("DB_PATH", str(db_path))

    # Bootstrap an old-style DB (no FK enforcement, orphans seeded by
    # hand) — bypass init_db's cleanup by setting up the schema
    # directly with foreign_keys OFF.
    import database
    import importlib

    importlib.reload(database)

    async with aiosqlite.connect(db_path) as db:
        # No PRAGMA foreign_keys = ON — simulate the old behaviour.
        await db.executescript(database.SCHEMA)
        # Insert a device + four child rows, then delete the device by
        # hand without cascade firing. Net result: four orphans.
        await db.execute(
            """INSERT INTO devices (id, mac, ip, first_seen, last_seen, is_online)
               VALUES ('dev-orphan', 'ab:ab:ab:ab:ab:ab', '10.9.9.9', ?, ?, 0)""",
            (
                datetime.now(timezone.utc).isoformat(),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        await db.execute(
            """INSERT INTO device_services (device_id, port, protocol, name)
               VALUES ('dev-orphan', 80, 'tcp', 'http')"""
        )
        await db.execute(
            """INSERT INTO scan_results (id, device_id, scan_type)
               VALUES ('sr-1', 'dev-orphan', 'nmap')"""
        )
        await db.execute(
            """INSERT INTO vuln_results
                  (id, device_id, severity, score, cve_id, name, port, protocol)
               VALUES ('vr-1', 'dev-orphan', 'low', 1.0, 'CVE-X', 'X', 80, 'tcp')"""
        )
        await db.execute(
            """INSERT INTO latency_samples (device_id, ts, latency_ms, success)
               VALUES ('dev-orphan', ?, 5.0, 1)""",
            (datetime.now(timezone.utc).isoformat(),),
        )
        await db.execute("DELETE FROM devices WHERE id = 'dev-orphan'")
        await db.commit()

    # Now run init_db — its _cleanup_orphans pass should remove all four.
    await database.init_db()

    async with aiosqlite.connect(db_path) as db:
        # All four child tables should be empty now
        for table in (
            "device_services",
            "scan_results",
            "vuln_results",
            "latency_samples",
        ):
            cur = await db.execute(f"SELECT COUNT(*) FROM {table}")
            assert (await cur.fetchone())[0] == 0, f"{table} still has orphans"

        # And the audit log should have a foreign_key_cleanup row
        cur = await db.execute(
            "SELECT detail FROM audit_log WHERE action = 'foreign_key_cleanup'"
        )
        rows = await cur.fetchall()
        assert len(rows) == 1, "expected exactly one audit row for cleanup"
        detail = json.loads(rows[0][0])
        assert detail["orphans_removed"]["device_services"] == 1
        assert detail["orphans_removed"]["scan_results"] == 1
        assert detail["orphans_removed"]["vuln_results"] == 1
        assert detail["orphans_removed"]["latency_samples"] == 1
