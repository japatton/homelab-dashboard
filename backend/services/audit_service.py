"""
Centralised audit-log writer.

All UI-driven mutations (settings saves, credential changes, manual scan
triggers, analysis triggers, Claude change approvals, etc.) should flow
through `write_audit` so the Audit Log page sees them and retention stays
bounded.

Retention is a rolling cap: once the table exceeds `max_entries`, the oldest
rows are trimmed in the same transaction as the insert — the table never
briefly exceeds the cap, and there is no separate sweeper job to keep in
sync with the scheduler.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import SecretStr

from database import get_db


# Keys whose values are always scrubbed before persistence, regardless of
# type. Callers are *supposed* to filter these out themselves (complete_setup
# does), but this is a defence-in-depth catch for the "someone forgot" case.
# Match is case-insensitive on the final path segment.
_SENSITIVE_KEYS = frozenset(
    {
        "password",
        "pass",
        "passwd",
        "api_key",
        "apikey",
        "token",
        "secret",
        "auth",
        "credential",
        "credentials",
        "private_key",
        "ssh_password",
    }
)

_SCRUBBED = "***"


def _scrub(value: Any) -> Any:
    """Recursively replace SecretStr → '***' and scrub known sensitive keys.

    Leaves untouched values (strings, numbers, non-sensitive dicts/lists) alone.
    """
    if isinstance(value, SecretStr):
        return _SCRUBBED
    if isinstance(value, dict):
        return {
            k: (_SCRUBBED if k.lower() in _SENSITIVE_KEYS else _scrub(v))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_scrub(v) for v in value]
    return value


class _AuditEncoder(json.JSONEncoder):
    """Last-line-of-defence JSON encoder. `_scrub` runs first, but if an
    oddball type (Pydantic model, datetime, etc.) slips through we fall
    back to str() instead of blowing up the audit insert."""

    def default(self, obj: Any) -> Any:  # type: ignore[override]
        if isinstance(obj, SecretStr):
            return _SCRUBBED
        return str(obj)


log = logging.getLogger(__name__)

# Cap the visible audit log. Older entries are dropped oldest-first once the
# count exceeds this number. Chosen small on purpose — the Audit Log page is
# for "what changed recently", not a forensic archive. Tune here if you want
# more history.
AUDIT_MAX_ENTRIES = 100


async def write_audit(action: str, actor: str, detail: dict[str, Any]) -> None:
    """Insert an audit row, then trim the table back to AUDIT_MAX_ENTRIES.

    `actor` is a short label — "user" for UI-driven changes, "scheduler" /
    "system" for background events. `detail` is a JSON-serialisable dict;
    never include passwords or secret material.
    """
    now = datetime.now(timezone.utc).isoformat()
    row_id = str(uuid.uuid4())
    scrubbed = _scrub(detail)
    try:
        async with get_db() as db:
            await db.execute(
                "INSERT INTO audit_log (id, timestamp, actor, action, detail) "
                "VALUES (?,?,?,?,?)",
                (row_id, now, actor, action, json.dumps(scrubbed, cls=_AuditEncoder)),
            )
            # Trim oldest rows beyond the cap. SQLite's OFFSET N in LIMIT -1
            # means "skip the first N newest rows, return the rest" — exactly
            # the set we want to delete.
            await db.execute(
                """DELETE FROM audit_log
                    WHERE id IN (
                      SELECT id FROM audit_log
                      ORDER BY timestamp DESC
                      LIMIT -1 OFFSET ?
                    )""",
                (AUDIT_MAX_ENTRIES,),
            )
            await db.commit()
    except Exception as e:
        # Never fail the calling operation because audit writing hiccupped.
        log.warning("audit write failed (action=%s): %s", action, e)


async def list_audit(limit: int = AUDIT_MAX_ENTRIES) -> list[dict]:
    """Most recent audit rows first, with `detail` already JSON-decoded."""
    limit = max(1, min(limit, AUDIT_MAX_ENTRIES))
    async with get_db() as db:
        rows = await (
            await db.execute(
                "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            )
        ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["detail"] = json.loads(d.get("detail") or "{}")
        except json.JSONDecodeError:
            d["detail"] = {}
        out.append(d)
    return out
