"""
Centralised audit-log writer.

All UI-driven mutations (settings saves, credential changes, manual scan
triggers, analysis triggers, Claude change approvals, etc.) should flow
through `write_audit` so the Audit Log page sees them and retention stays
bounded.

Retention is **age-based** (F-024): every write also DELETEs rows older
than AUDIT_RETENTION_DAYS days, in the same transaction as the insert. The
table never briefly exceeds the window, and there is no separate sweeper
job to keep in sync with the scheduler. Switched away from a count-based
rolling cap because that let an attacker erase tracks by issuing N+1
trivial writes — the calendar now wins.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from pydantic import SecretStr

from database import get_db


# Substring tokens — any key whose lowercase contains any of these gets
# scrubbed. F-016: switched from exact-match to substring after the prior
# review found that real schema fields slip through:
#
#   api_secret      (OPNsense) → didn't match exact "secret"
#   msp_token       (Firewalla MSP) → didn't match exact "token"
#   local_token     (Firewalla local) → didn't match exact "token"
#   key_passphrase  (scan_credentials SSH key) → didn't match anything
#
# Substring catches "*_secret", "*_token", "*passphrase", etc. without
# needing the schema author to remember to extend an allowlist for every
# new field. False positives ("non-secret keys ending in 'auth'") are
# acceptable for an audit log — a missing scrub is much worse than an
# over-zealous one.
_SCRUB_SUBSTRINGS = frozenset(
    {
        "password",
        "passwd",
        "passphrase",
        "api_key",
        "apikey",
        "secret",
        "token",
        "bearer",
        "credential",
        "private_key",
        "ssh_password",
        "ssh_key",
    }
)

_SCRUBBED = "***"


def _key_is_sensitive(key: str) -> bool:
    """True iff `key`'s lowercase form contains any sensitive substring.

    Examples (all True):  password, msp_token, api_secret, key_passphrase
    Counterexamples (False): host, port, enabled, mode
    """
    k = key.lower()
    return any(sub in k for sub in _SCRUB_SUBSTRINGS)


def _scrub(value: Any) -> Any:
    """Recursively replace SecretStr → '***' and scrub known sensitive keys.

    Leaves untouched values (strings, numbers, non-sensitive dicts/lists) alone.
    """
    if isinstance(value, SecretStr):
        return _SCRUBBED
    if isinstance(value, dict):
        return {
            k: (_SCRUBBED if _key_is_sensitive(k) else _scrub(v))
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

# F-024: retention model.
#
# The previous policy was a 100-row rolling cap: every write trimmed the
# oldest rows beyond entry 100. Operationally that meant a token-stealing
# attacker could compress the audit window by issuing 100 trivial actions
# (e.g. POST /api/scheduler/trigger/<job> in a loop) and erase tracks of
# everything they did before. Forensic gap.
#
# Switched to **age-based retention**: keep AUDIT_RETENTION_DAYS days of
# rows; older rows get trimmed on each write. Now an attacker can't shrink
# the window by writing more — the calendar wins. 30 days is the default;
# the table stays small (~hundreds of rows for a typical operator) and
# tunable via env for users with stricter compliance needs.
#
# The page-level read cap (AUDIT_LIST_MAX) is separate: it bounds *how
# many rows the API returns in a single GET*, not how many we keep on
# disk. Keeps the UI snappy without amputating the underlying history.
AUDIT_RETENTION_DAYS = int(os.getenv("AUDIT_RETENTION_DAYS", "30"))
AUDIT_LIST_MAX = int(os.getenv("AUDIT_LIST_MAX", "500"))


async def write_audit(action: str, actor: str, detail: dict[str, Any]) -> None:
    """Insert an audit row, then trim rows older than AUDIT_RETENTION_DAYS.

    `actor` is a short label — "user" for UI-driven changes, "scheduler" /
    "system" for background events. `detail` is a JSON-serialisable dict;
    never include passwords or secret material.
    """
    now_dt = datetime.now(timezone.utc)
    now = now_dt.isoformat()
    row_id = str(uuid.uuid4())
    scrubbed = _scrub(detail)
    try:
        async with get_db() as db:
            await db.execute(
                "INSERT INTO audit_log (id, timestamp, actor, action, detail) "
                "VALUES (?,?,?,?,?)",
                (row_id, now, actor, action, json.dumps(scrubbed, cls=_AuditEncoder)),
            )
            # F-024: drop rows older than the retention window. The cutoff
            # is recomputed on every write so the trim follows wall-clock
            # time, not the rate of audit activity. ISO8601 string compare
            # is correct because our timestamps are zone-fixed (always UTC).
            cutoff = (now_dt - timedelta(days=AUDIT_RETENTION_DAYS)).isoformat()
            await db.execute(
                "DELETE FROM audit_log WHERE timestamp < ?",
                (cutoff,),
            )
            await db.commit()
    except Exception as e:
        # Never fail the calling operation because audit writing hiccupped.
        log.warning("audit write failed (action=%s): %s", action, e)


async def list_audit(limit: int = AUDIT_LIST_MAX) -> list[dict]:
    """Most recent audit rows first, with `detail` already JSON-decoded."""
    limit = max(1, min(limit, AUDIT_LIST_MAX))
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
