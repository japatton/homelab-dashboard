"""Tests for services.audit_service.

Two things that really must not break:

  1. **Secrets never get persisted.** The audit log is a UI-visible
     table; if a password leaks into `detail` it appears on the Audit
     Log page. We guard both ways: by key name (substring match per
     F-016) and by SecretStr type.

  2. **Retention is age-based, not count-based** (F-024). Rows older
     than AUDIT_RETENTION_DAYS get dropped on each write. A
     token-stealing attacker can no longer compress the audit window
     by writing N+1 trivial actions — the calendar wins.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import aiosqlite
import pytest
from pydantic import SecretStr

from services.audit_service import (
    AUDIT_LIST_MAX,
    AUDIT_RETENTION_DAYS,
    list_audit,
    write_audit,
)


pytestmark = pytest.mark.asyncio


async def test_write_and_list_roundtrip(initialised_db):
    await write_audit("test_action", "user", {"foo": "bar"})
    rows = await list_audit()
    assert len(rows) == 1
    r = rows[0]
    assert r["action"] == "test_action"
    assert r["actor"] == "user"
    assert r["detail"] == {"foo": "bar"}


async def test_scrubs_sensitive_keys(initialised_db):
    await write_audit(
        "settings_save",
        "user",
        {
            "username": "alice",
            "password": "hunter2",
            "api_key": "k-xyz",
            "token": "pat_abc",
            "nested": {"private_key": "-----BEGIN RSA-----..."},
        },
    )
    rows = await list_audit()
    d = rows[0]["detail"]
    assert d["username"] == "alice"  # non-sensitive passes through
    assert d["password"] == "***"
    assert d["api_key"] == "***"
    assert d["token"] == "***"
    assert d["nested"]["private_key"] == "***"
    # Raw secret values must not appear anywhere in the persisted blob.
    serialised = str(d)
    for secret in ("hunter2", "k-xyz", "pat_abc", "BEGIN RSA"):
        assert secret not in serialised


async def test_scrubs_compound_sensitive_keys_via_substring(initialised_db):
    """F-016: previously the scrubber matched keys exactly, so real
    schema fields slipped through:

      api_secret      (OPNsense)
      msp_token       (Firewalla MSP)
      local_token     (Firewalla local)
      key_passphrase  (scan_credentials SSH key)

    The substring matcher catches all of these without needing to add
    each new field to an allowlist. The non-sensitive `name` /
    `host` / `port` keys must still pass through unchanged.
    """
    await write_audit(
        "settings_save",
        "user",
        {
            # Compound names that the old exact-match list missed
            "api_secret": "opnsense-secret-abc",
            "msp_token": "firewalla-pat-def",
            "local_token": "firewalla-fireguard-ghi",
            "key_passphrase": "ssh-key-passphrase-jkl",
            "ssh_key": "----PRIV----",
            # Non-sensitive keys that must NOT be scrubbed
            "host": "opnsense.lan",
            "port": 9090,
            "name": "edge-router",
            "enabled": True,
        },
    )
    rows = await list_audit()
    d = rows[0]["detail"]

    # All compound-sensitive keys redacted
    assert d["api_secret"] == "***"
    assert d["msp_token"] == "***"
    assert d["local_token"] == "***"
    assert d["key_passphrase"] == "***"
    assert d["ssh_key"] == "***"

    # Non-sensitive keys preserved
    assert d["host"] == "opnsense.lan"
    assert d["port"] == 9090
    assert d["name"] == "edge-router"
    assert d["enabled"] is True

    # And no raw secret string appears in the persisted blob
    serialised = str(d)
    for secret in (
        "opnsense-secret-abc",
        "firewalla-pat-def",
        "firewalla-fireguard-ghi",
        "ssh-key-passphrase-jkl",
        "PRIV",
    ):
        assert secret not in serialised


async def test_scrubs_secretstr_values(initialised_db):
    # Even when the KEY isn't on the sensitive list, a SecretStr value
    # must be redacted — defence against the "someone forgot to rename"
    # case where a config is dumped whole into the audit detail.
    await write_audit(
        "settings_save",
        "user",
        {
            "custom_field": SecretStr("oops-plaintext-in-audit"),
        },
    )
    rows = await list_audit()
    d = rows[0]["detail"]
    assert d["custom_field"] == "***"
    assert "oops-plaintext" not in str(d)


async def test_age_based_retention_drops_rows_older_than_window(
    initialised_db,
):
    """F-024: rows older than AUDIT_RETENTION_DAYS get trimmed on each
    new write. Use a hand-inserted "ancient" row, then trigger a fresh
    write and confirm the old one is gone."""
    # Insert a row dated well outside the retention window — we go through
    # raw SQL so we can backdate the timestamp (write_audit always uses
    # "now").
    ancient_ts = (
        datetime.now(timezone.utc) - timedelta(days=AUDIT_RETENTION_DAYS + 5)
    ).isoformat()
    async with aiosqlite.connect(initialised_db) as db:
        await db.execute(
            "INSERT INTO audit_log (id, timestamp, actor, action, detail) "
            "VALUES (?,?,?,?,?)",
            ("ancient-id", ancient_ts, "system", "old_action", "{}"),
        )
        await db.commit()

    # Sanity: the ancient row is currently in the table.
    async with aiosqlite.connect(initialised_db) as db:
        cur = await db.execute("SELECT COUNT(*) FROM audit_log")
        assert (await cur.fetchone())[0] == 1

    # A fresh write triggers the trim — ancient row should drop.
    await write_audit("new_action", "system", {"k": "v"})

    rows = await list_audit()
    actions = [r["action"] for r in rows]
    assert "old_action" not in actions, "row past retention window should be trimmed"
    assert "new_action" in actions


async def test_retention_keeps_rows_within_window(initialised_db):
    """A row inserted "yesterday" must survive the trim. The point of
    age-based retention is to preserve the audit trail across normal
    activity bursts — only calendar-old rows get dropped."""
    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    async with aiosqlite.connect(initialised_db) as db:
        await db.execute(
            "INSERT INTO audit_log (id, timestamp, actor, action, detail) "
            "VALUES (?,?,?,?,?)",
            ("yesterday-id", yesterday, "user", "yesterday_action", "{}"),
        )
        await db.commit()

    await write_audit("today_action", "system", {})

    rows = await list_audit()
    actions = [r["action"] for r in rows]
    assert "yesterday_action" in actions
    assert "today_action" in actions


async def test_high_volume_within_window_does_not_compress_audit_trail(
    initialised_db,
):
    """The pre-F-024 100-row cap let an attacker erase tracks by writing
    101 trivial rows. Under age-based retention, writing 200 rows in
    one go keeps all 200 — the calendar is the cap, not the count."""
    for i in range(200):
        await write_audit("flood", "user", {"i": i})

    rows = await list_audit(limit=AUDIT_LIST_MAX)
    assert len(rows) == 200, "all in-window writes must be retained"


async def test_list_limit_capped(initialised_db):
    """list_audit clamps limit to [1, AUDIT_LIST_MAX] (page-level read
    cap, separate from on-disk retention)."""
    for i in range(10):
        await write_audit("x", "system", {"i": i})
    assert len(await list_audit(limit=0)) == 1  # clamped up to 1
    assert len(await list_audit(limit=10_000)) == 10  # only 10 rows exist
    assert len(await list_audit(limit=3)) == 3


async def test_write_never_raises_on_bad_detail(initialised_db):
    # _AuditEncoder falls back to str() for weird types. An object that
    # isn't JSON-native shouldn't crash the write.
    class Opaque:
        def __repr__(self):
            return "Opaque()"

    # Should not raise — if it did the caller would lose the event.
    await write_audit("weird", "system", {"obj": Opaque()})
    rows = await list_audit()
    assert rows[0]["detail"]["obj"] == "Opaque()"
