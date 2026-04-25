from __future__ import annotations

"""
Scan credentials store.

Manages SSH credentials used by OpenVAS for credentialed scans. Stored in the
local SQLite `scan_credentials` table, keyed by target IP. A `target_ip` value
of `*` acts as a wildcard default applied to any device without a more-specific
entry.

Two auth flavours:

  * auth_type = "password"   — stores `password`; `private_key` is unused.
  * auth_type = "key"        — stores `private_key` (PEM text) and optional
                                `key_passphrase`; `password` is unused.

The returned dict always includes both pairs so callers (OpenVAS integration,
SSH probe) can pick whichever auth_type a row is tagged with without having to
reissue the query.
"""

import logging
import uuid
from typing import Optional

log = logging.getLogger(__name__)


def _row_to_cred(row) -> dict:
    """Shape a scan_credentials row into the dict callers expect."""
    d = dict(row)
    auth_type = d.get("auth_type") or "password"
    return {
        "id": d["id"],
        "target_ip": d["target_ip"],
        "username": d["username"],
        "auth_type": auth_type,
        "ssh_username": d["username"],
        "ssh_password": d.get("password") or "",
        "ssh_private_key": d.get("private_key") or "",
        "ssh_key_passphrase": d.get("key_passphrase") or "",
        "note": d.get("note") or "",
    }


async def get_scan_credential(device_ip: str) -> Optional[dict]:
    """Look up stored scan credentials for a device IP.

    Returns a dict with auth_type + both password and key material, or None.
    Falls back to the wildcard `*` row when no device-specific row exists.
    """
    from database import get_db
    async with get_db() as db:
        row = await (await db.execute(
            """SELECT id, target_ip, username, auth_type, password,
                      private_key, key_passphrase, note
                 FROM scan_credentials
                WHERE target_ip = ? OR target_ip = '*'
                ORDER BY target_ip DESC LIMIT 1""",
            (device_ip,),
        )).fetchone()
    return _row_to_cred(row) if row else None


async def list_scan_credentials() -> list[dict]:
    """List all stored credentials. Secret material is stripped — the UI only
    needs to know which rows exist and what auth type they use."""
    from database import get_db
    async with get_db() as db:
        rows = await (await db.execute(
            """SELECT id, target_ip, username, auth_type, note
                 FROM scan_credentials
                ORDER BY target_ip"""
        )).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        out.append({
            "id": d["id"],
            "target_ip": d["target_ip"],
            "username": d["username"],
            "auth_type": d.get("auth_type") or "password",
            "note": d.get("note") or "",
        })
    return out


async def upsert_scan_credential(
    target_ip: str,
    username: str,
    *,
    auth_type: str = "password",
    password: str = "",
    private_key: str = "",
    key_passphrase: str = "",
    note: str = "",
) -> str:
    """Create or replace the row for `target_ip`.

    target_ip is the row key (UNIQUE index) — one credential per IP/pattern.
    Updating preserves the existing row id.
    """
    from database import get_db

    if auth_type not in ("password", "key"):
        raise ValueError(f"invalid auth_type {auth_type!r}")

    cred_id = str(uuid.uuid4())
    async with get_db() as db:
        existing = await (await db.execute(
            "SELECT id FROM scan_credentials WHERE target_ip = ?", (target_ip,)
        )).fetchone()
        if existing:
            cred_id = existing["id"]
            await db.execute(
                """UPDATE scan_credentials
                      SET username=?, auth_type=?, password=?, private_key=?,
                          key_passphrase=?, note=?
                    WHERE id=?""",
                (username, auth_type, password, private_key,
                 key_passphrase, note, cred_id),
            )
        else:
            await db.execute(
                """INSERT INTO scan_credentials
                     (id, target_ip, username, auth_type, password,
                      private_key, key_passphrase, note)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (cred_id, target_ip, username, auth_type, password,
                 private_key, key_passphrase, note),
            )
        await db.commit()
    return cred_id


async def delete_scan_credential(cred_id: str) -> bool:
    from database import get_db
    async with get_db() as db:
        result = await db.execute(
            "DELETE FROM scan_credentials WHERE id = ?", (cred_id,)
        )
        await db.commit()
    return result.rowcount > 0
