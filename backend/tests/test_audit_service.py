"""Tests for services.audit_service.

Two things that really must not break:

  1. **Secrets never get persisted.** The audit log is a UI-visible
     table; if a password leaks into `detail` it appears on the Audit
     Log page. We guard both ways: by key name and by SecretStr type.

  2. **Retention is bounded.** The Audit Log page shows a rolling
     100-row window. One accidental loop that writes 10k rows shouldn't
     blow SQLite; the trim-on-insert keeps the table capped.
"""
from __future__ import annotations

import pytest
from pydantic import SecretStr

from services.audit_service import AUDIT_MAX_ENTRIES, list_audit, write_audit


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
    await write_audit("settings_save", "user", {
        "username": "alice",
        "password": "hunter2",
        "api_key": "k-xyz",
        "token": "pat_abc",
        "nested": {"private_key": "-----BEGIN RSA-----..."},
    })
    rows = await list_audit()
    d = rows[0]["detail"]
    assert d["username"] == "alice"          # non-sensitive passes through
    assert d["password"] == "***"
    assert d["api_key"] == "***"
    assert d["token"] == "***"
    assert d["nested"]["private_key"] == "***"
    # Raw secret values must not appear anywhere in the persisted blob.
    serialised = str(d)
    for secret in ("hunter2", "k-xyz", "pat_abc", "BEGIN RSA"):
        assert secret not in serialised


async def test_scrubs_secretstr_values(initialised_db):
    # Even when the KEY isn't on the sensitive list, a SecretStr value
    # must be redacted — defence against the "someone forgot to rename"
    # case where a config is dumped whole into the audit detail.
    await write_audit("settings_save", "user", {
        "custom_field": SecretStr("oops-plaintext-in-audit"),
    })
    rows = await list_audit()
    d = rows[0]["detail"]
    assert d["custom_field"] == "***"
    assert "oops-plaintext" not in str(d)


async def test_retention_trims_oldest(initialised_db):
    # Write one more than the cap; the oldest should fall off.
    for i in range(AUDIT_MAX_ENTRIES + 5):
        await write_audit("bulk", "system", {"n": i})
    rows = await list_audit()
    assert len(rows) == AUDIT_MAX_ENTRIES
    # Newest first: the most recent writes survive. The last N=max_entries
    # writes (n = 5..104) should be present, n=0..4 gone.
    ns = sorted([r["detail"]["n"] for r in rows])
    assert ns[0] == 5           # oldest survivor
    assert ns[-1] == AUDIT_MAX_ENTRIES + 4


async def test_list_limit_capped(initialised_db):
    # list_audit clamps limit to [1, AUDIT_MAX_ENTRIES].
    for i in range(10):
        await write_audit("x", "system", {"i": i})
    assert len(await list_audit(limit=0)) == 1  # clamped up
    assert len(await list_audit(limit=10_000)) == 10  # clamped down to cap, but we only have 10
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
