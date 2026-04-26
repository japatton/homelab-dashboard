from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator

import aiosqlite

DB_PATH = Path(os.getenv("DB_PATH", "/data/homelab.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    id          TEXT PRIMARY KEY,
    mac         TEXT UNIQUE,
    ip          TEXT,
    hostname    TEXT,
    label       TEXT,
    device_type TEXT DEFAULT 'unknown',
    confidence  REAL DEFAULT 0.0,
    metadata    TEXT DEFAULT '{}',
    position_x  REAL DEFAULT 0.0,
    position_y  REAL DEFAULT 0.0,
    first_seen  TEXT,
    last_seen   TEXT,
    is_online   INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS device_services (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id  TEXT NOT NULL,
    port       INTEGER NOT NULL,
    protocol   TEXT NOT NULL DEFAULT 'tcp',
    name       TEXT DEFAULT '',
    version    TEXT DEFAULT '',
    launch_url TEXT,
    updated_at TEXT,
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE,
    UNIQUE(device_id, port, protocol)
);

CREATE TABLE IF NOT EXISTS scan_results (
    id           TEXT PRIMARY KEY,
    device_id    TEXT,
    scan_type    TEXT,
    status       TEXT DEFAULT 'completed',
    target_count INTEGER DEFAULT 0,
    result_count INTEGER DEFAULT 0,
    started_at   TEXT,
    completed_at TEXT,
    raw_output   TEXT,
    parsed_json  TEXT DEFAULT '{}',
    FOREIGN KEY (device_id) REFERENCES devices(id)
);

CREATE TABLE IF NOT EXISTS vuln_results (
    id          TEXT PRIMARY KEY,
    device_id   TEXT,
    cve_id      TEXT DEFAULT '',
    severity    TEXT,
    score       REAL DEFAULT 0.0,
    name        TEXT DEFAULT '',
    description TEXT,
    solution    TEXT,
    port        INTEGER DEFAULT 0,
    protocol    TEXT DEFAULT 'tcp',
    cve_ids     TEXT DEFAULT '[]',
    scan_job_id TEXT,
    first_seen  TEXT,
    detected_at TEXT,
    FOREIGN KEY (device_id) REFERENCES devices(id)
);

CREATE TABLE IF NOT EXISTS claude_staged_changes (
    id              TEXT PRIMARY KEY,
    triggered_at    TEXT,
    device_id       TEXT,
    device_context  TEXT DEFAULT '{}',
    reason          TEXT,
    diff_preview    TEXT,
    generated_files TEXT DEFAULT '[]',
    status          TEXT DEFAULT 'pending',
    reviewed_at     TEXT,
    FOREIGN KEY (device_id) REFERENCES devices(id)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id          TEXT PRIMARY KEY,
    timestamp   TEXT,
    actor       TEXT,
    action      TEXT,
    detail      TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS scheduler_state (
    job_id  TEXT PRIMARY KEY,
    last_run TEXT,
    status  TEXT DEFAULT 'idle',
    detail  TEXT
);

CREATE TABLE IF NOT EXISTS scan_credentials (
    id             TEXT PRIMARY KEY,
    target_ip      TEXT NOT NULL,
    username       TEXT NOT NULL,
    -- auth_type decides which of password / private_key is meaningful.
    -- Left blank on legacy rows; treated as 'password' at read time.
    auth_type      TEXT DEFAULT 'password',
    password       TEXT DEFAULT '',
    private_key    TEXT DEFAULT '',
    key_passphrase TEXT DEFAULT '',
    note           TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS latency_samples (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id  TEXT,
    ts         TEXT NOT NULL,
    latency_ms REAL,
    success    INTEGER DEFAULT 1,
    FOREIGN KEY (device_id) REFERENCES devices(id)
);

-- Unified alarms feed for gateway integrations (OPNsense Suricata,
-- Firewalla IDS + custom rules). One row per distinct security event;
-- identical fingerprints from the same source collapse into one row
-- with a bumped `count` and refreshed `last_seen_at` (dedup is handled
-- in services.alarm_service).
--
-- Intentionally denormalized: we store source_name/device_ip/etc
-- inline rather than JOINing against devices.id at read time because
-- the Security page wants chronological order across all sources and
-- the devices table is the wrong JOIN grain (alarms may reference
-- hosts that were never discovered by Nmap/UniFi).
CREATE TABLE IF NOT EXISTS gateway_alarms (
    id             TEXT PRIMARY KEY,
    source         TEXT NOT NULL,              -- 'opnsense' | 'firewalla'
    -- Human-readable source label for the UI ("OPNsense 24.7" or
    -- "Firewalla Gold"); filled in on insert from system info so the
    -- UI doesn't need to cross-reference config at render time.
    source_label   TEXT DEFAULT '',
    severity       TEXT NOT NULL DEFAULT 'info',  -- critical|high|medium|low|info
    category       TEXT DEFAULT '',            -- 'ids' | 'intrusion' | 'policy' | 'device_new' | ...
    signature      TEXT DEFAULT '',            -- short rule/signature name
    message        TEXT NOT NULL,              -- human-facing body
    src_ip         TEXT DEFAULT '',
    dst_ip         TEXT DEFAULT '',
    device_id      TEXT,                        -- optional FK into devices(id)
    device_name    TEXT DEFAULT '',
    fingerprint    TEXT NOT NULL,              -- src+dst+sig+minute bucket
    first_seen_at  TEXT NOT NULL,
    last_seen_at   TEXT NOT NULL,
    count          INTEGER NOT NULL DEFAULT 1, -- # of dedup-merged hits
    acknowledged   INTEGER NOT NULL DEFAULT 0,
    acknowledged_at TEXT,
    dismissed      INTEGER NOT NULL DEFAULT 0,
    dismissed_at   TEXT,
    raw_json       TEXT DEFAULT '{}'           -- source-specific payload for drill-down
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_gateway_alarms_fp
    ON gateway_alarms(source, fingerprint);
CREATE INDEX IF NOT EXISTS idx_gateway_alarms_last_seen
    ON gateway_alarms(last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_gateway_alarms_active
    ON gateway_alarms(dismissed, last_seen_at DESC);

CREATE TABLE IF NOT EXISTS analysis_reports (
    id            TEXT PRIMARY KEY,
    generated_at  TEXT NOT NULL,
    period_start  TEXT NOT NULL,
    period_end    TEXT NOT NULL,
    model         TEXT,
    status        TEXT DEFAULT 'completed',   -- completed | failed | running
    summary_md    TEXT,                        -- markdown body returned by the model
    input_json    TEXT DEFAULT '{}',           -- aggregated stats we sent to the model
    raw_prompt    TEXT,                        -- prompt we sent (for debugging/tuning)
    raw_response  TEXT,                        -- full provider response for debugging
    error         TEXT,                        -- present iff status = 'failed'
    duration_ms   INTEGER
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_creds_ip ON scan_credentials(target_ip);
CREATE INDEX IF NOT EXISTS idx_latency_device_ts ON latency_samples(device_id, ts);
CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac);
CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip);
CREATE INDEX IF NOT EXISTS idx_device_services_device ON device_services(device_id);
CREATE INDEX IF NOT EXISTS idx_scan_results_device ON scan_results(device_id);
CREATE INDEX IF NOT EXISTS idx_vuln_results_device ON vuln_results(device_id);
-- Covering index for the severity-breakdown query on the device detail
-- endpoint (GET /api/devices/{id}). With only idx_vuln_results_device,
-- SQLite had to read every matching row to filter by severity. This
-- composite lets the GROUP BY severity execute as an index-only scan.
CREATE INDEX IF NOT EXISTS idx_vuln_results_device_severity
    ON vuln_results(device_id, severity);
-- Content identity for a finding: same (device, CVE, name, port, protocol)
-- means "same unresolved issue" across re-scans. The UPSERT in
-- services/vuln_service.py relies on this index to merge repeat findings
-- instead of inserting a new row each scan.
CREATE UNIQUE INDEX IF NOT EXISTS idx_vuln_results_unique
    ON vuln_results(device_id, cve_id, name, port, protocol);
CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_analysis_reports_generated ON analysis_reports(generated_at DESC);
"""


async def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(DB_PATH) as db:
        # F-004: SQLite defaults `foreign_keys = OFF`, which silently
        # disables every ON DELETE CASCADE the schema declares — so up
        # through v1.1.0 a deleted device's services / vulns / latency
        # samples orphan forever. Turn the PRAGMA on once here for the
        # init connection, and again in get_db() for every runtime
        # connection (the PRAGMA is connection-scoped, not DB-scoped).
        await db.execute("PRAGMA foreign_keys = ON")

        # Migrations that have to run BEFORE the schema executescript creates
        # the new UNIQUE index on vuln_results — otherwise the index creation
        # fails on any DB that already contains duplicate findings.
        await _migrate_vuln_results(db)
        await db.executescript(SCHEMA)
        # Column-add migrations run AFTER executescript: CREATE TABLE IF NOT
        # EXISTS never adds new columns to an existing table, so the SCHEMA
        # change above is a no-op on upgraded DBs. _migrate_scan_credentials
        # backfills the missing columns with ALTER TABLE.
        await _migrate_scan_credentials(db)

        # F-004 followup: clean up any orphaned rows that accumulated
        # while foreign_keys was off. Audit-log the count so the
        # operator sees what happened on the upgrade boot rather than
        # discovering "the Vulnerabilities page lost rows" via support
        # ticket. Delete BEFORE the commit so the cleanup is atomic
        # with the schema apply.
        orphan_counts = await _cleanup_orphans(db)

        await db.commit()

    # Audit-log the cleanup outside the schema-init transaction so an
    # audit-write failure doesn't roll back the schema migration.
    if any(orphan_counts.values()):
        try:
            from services.audit_service import write_audit

            await write_audit(
                "foreign_key_cleanup",
                "system",
                {
                    "rationale": (
                        "F-004: PRAGMA foreign_keys=ON enabled; deleted rows "
                        "orphaned by previous foreign_keys=OFF default"
                    ),
                    "orphans_removed": orphan_counts,
                },
            )
        except Exception as e:
            # Don't gate startup on audit-write hiccups.
            import logging as _log

            _log.getLogger(__name__).warning(
                "audit_log write for foreign_key_cleanup failed: %s", e
            )


async def _cleanup_orphans(db: aiosqlite.Connection) -> dict[str, int]:
    """Delete rows whose foreign-key parent no longer exists.

    Runs in init_db() exactly once per process startup. Idempotent —
    re-running on a clean DB is a no-op (every DELETE returns 0
    rowcount). Returns counts per table for the audit-log entry so
    the operator can see what got cleaned up on the upgrade boot.

    The four child tables that reference devices(id):
      - device_services  — ON DELETE CASCADE declared, never fired
      - scan_results     — no cascade
      - vuln_results     — no cascade
      - latency_samples  — no cascade
    """
    out: dict[str, int] = {}
    for table in (
        "device_services",
        "scan_results",
        "vuln_results",
        "latency_samples",
    ):
        cur = await db.execute(
            f"DELETE FROM {table} "  # noqa: S608 - table name is hardcoded
            f"WHERE device_id NOT IN (SELECT id FROM devices)"
        )
        out[table] = cur.rowcount or 0
    return out


async def _migrate_vuln_results(db: aiosqlite.Connection) -> None:
    """One-time cleanup of vuln_results so the UNIQUE content-identity index
    (device_id, cve_id, name, port, protocol) can be built.

    Prior versions wrote a fresh UUID per finding per scan, so every repeat
    scan of an unresolved vuln produced a duplicate row. We:
      1. Add the first_seen column if it's missing (ALTER is not in SCHEMA
         because CREATE TABLE IF NOT EXISTS won't add columns to existing
         tables).
      2. Coerce NULL values in the identity columns to non-null defaults —
         SQLite treats NULLs as distinct in a UNIQUE index, which would
         defeat the whole point.
      3. Delete duplicate rows, keeping the newest per identity group.
      4. Backfill first_seen = detected_at for pre-migration rows.

    Safe to run repeatedly — every step is idempotent.
    """
    # Skip everything if the table doesn't exist yet (fresh install).
    row = await (
        await db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='vuln_results'"
        )
    ).fetchone()
    if row is None:
        return

    # 1. Add first_seen column if missing. SQLite has no IF NOT EXISTS for
    #    ALTER TABLE ADD COLUMN, so we swallow the duplicate-column error.
    try:
        await db.execute("ALTER TABLE vuln_results ADD COLUMN first_seen TEXT")
    except aiosqlite.OperationalError as e:
        if "duplicate column" not in str(e).lower():
            raise

    # 2. Coerce NULLs in identity columns.
    await db.execute("UPDATE vuln_results SET cve_id   = '' WHERE cve_id   IS NULL")
    await db.execute("UPDATE vuln_results SET name     = '' WHERE name     IS NULL")
    await db.execute("UPDATE vuln_results SET port     = 0  WHERE port     IS NULL")
    await db.execute("UPDATE vuln_results SET protocol = 'tcp' WHERE protocol IS NULL")

    # 3. Deduplicate. For each (device_id, cve_id, name, port, protocol)
    #    group, keep the row with the latest detected_at, tie-broken by
    #    rowid so the delete is deterministic.
    await db.execute("""
        DELETE FROM vuln_results
         WHERE rowid IN (
           SELECT r1.rowid FROM vuln_results r1
           INNER JOIN vuln_results r2
              ON r1.device_id = r2.device_id
             AND r1.cve_id    = r2.cve_id
             AND r1.name      = r2.name
             AND r1.port      = r2.port
             AND r1.protocol  = r2.protocol
             AND (
                   r1.detected_at <  r2.detected_at
                OR (r1.detected_at = r2.detected_at AND r1.rowid < r2.rowid)
             )
         )
    """)

    # 4. Backfill first_seen so the UI doesn't show blanks on pre-migration
    #    rows. first_seen defaults to detected_at — we can't reconstruct the
    #    true first-sighting time from the old schema.
    await db.execute(
        "UPDATE vuln_results SET first_seen = detected_at WHERE first_seen IS NULL"
    )

    await db.commit()


async def _migrate_scan_credentials(db: aiosqlite.Connection) -> None:
    """Add auth_type / private_key / key_passphrase columns to the
    scan_credentials table for SSH-key-auth support.

    Also loosens the legacy `password NOT NULL` constraint implicitly — new
    key-auth rows store an empty string for password. Old password-only rows
    keep working because auth_type defaults to 'password'.

    Idempotent: each ALTER is guarded by a duplicate-column catch.
    """
    # Skip if the table isn't there (fresh install — schema handled it).
    row = await (
        await db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='scan_credentials'"
        )
    ).fetchone()
    if row is None:
        return

    for col, ddl in (
        (
            "auth_type",
            "ALTER TABLE scan_credentials ADD COLUMN auth_type TEXT DEFAULT 'password'",
        ),
        (
            "private_key",
            "ALTER TABLE scan_credentials ADD COLUMN private_key TEXT DEFAULT ''",
        ),
        (
            "key_passphrase",
            "ALTER TABLE scan_credentials ADD COLUMN key_passphrase TEXT DEFAULT ''",
        ),
    ):
        try:
            await db.execute(ddl)
        except aiosqlite.OperationalError as e:
            if "duplicate column" not in str(e).lower():
                raise

    # Backfill: any row with a non-empty password but a NULL/blank auth_type
    # is a pre-migration password row. Mark it explicitly.
    await db.execute(
        "UPDATE scan_credentials SET auth_type = 'password' "
        "WHERE auth_type IS NULL OR auth_type = ''"
    )


@asynccontextmanager
async def get_db() -> AsyncGenerator[aiosqlite.Connection, None]:
    async with aiosqlite.connect(DB_PATH) as db:
        # F-004: PRAGMA foreign_keys is connection-scoped, not
        # database-scoped — every fresh aiosqlite.connect() comes back
        # with foreign_keys=OFF regardless of what init_db did. Setting
        # it here makes ON DELETE CASCADE actually fire for runtime
        # writes. Cost is one round-trip per connection (~µs); worth
        # it for not silently orphaning rows.
        await db.execute("PRAGMA foreign_keys = ON")
        db.row_factory = aiosqlite.Row
        yield db
