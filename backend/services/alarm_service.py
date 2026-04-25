"""Unified gateway-alarm service.

This is the single funnel through which every gateway integration
(OPNsense Suricata, Firewalla IDS, Firewalla custom rules) writes
into `gateway_alarms`. Direct integration → DB writes are
forbidden; they all go through `upsert_alarms()` so:

  1. Dedup is consistent (same fingerprint always collapses).
  2. Socket.io push happens exactly once per genuinely-new alarm.
  3. The audit log sees who introduced what event without each
     integration re-implementing it.

### Dedup model

A fingerprint is a string the integration computes — typically
`<src_ip>|<dst_ip>|<signature>|<minute_bucket>`. Two hits with the
same (source, fingerprint) are folded into one row with `count`
incremented and `last_seen_at` refreshed. This keeps alert storms
(Suricata firing once per packet) out of the UI without hiding
distinct attacks.

### Severity mapping

Each integration speaks its own severity scale (Suricata 1-4,
Firewalla numeric type codes). `AlarmInput.severity` takes the
normalised vocabulary (critical/high/medium/low/info); integrations
convert at their boundary.

### Socket push

Newly-inserted alarms (NOT dedup-merges) fire `alarm:new`. The
frontend Security page and a badge on the sidebar listen for this.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from database import get_db
from models.alarm import AlarmSeverity, AlarmSource, AlarmSummary, GatewayAlarm
from services.notification_service import get_notification_service

log = logging.getLogger(__name__)


@dataclass
class AlarmInput:
    """What an integration hands to the service. Deliberately thin —
    anything source-specific goes into `raw` which we JSON-blob for
    drill-down without committing to a schema."""

    source: AlarmSource
    fingerprint: str
    message: str
    severity: AlarmSeverity = "info"
    source_label: str = ""
    category: str = ""
    signature: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    device_id: Optional[str] = None
    device_name: str = ""
    timestamp: Optional[str] = None  # ISO; defaults to now
    raw: dict = field(default_factory=dict)


async def upsert_alarms(alarms: list[AlarmInput]) -> tuple[int, int]:
    """Dedup + persist + notify. Returns (new_count, updated_count).

    Atomicity: each alarm is upserted in its own execute + we commit
    once at the end. If the process dies mid-batch we may re-fetch the
    same alarms on next poll; dedup handles that gracefully.
    """
    if not alarms:
        return (0, 0)
    now = datetime.now(timezone.utc).isoformat()
    new_ids: list[str] = []
    new_alarms: list[GatewayAlarm] = []
    updated = 0

    async with get_db() as db:
        for a in alarms:
            ts = a.timestamp or now
            raw_json = json.dumps(a.raw, default=str) if a.raw else "{}"

            # Look up existing by (source, fingerprint) — the UNIQUE
            # index makes this cheap. We read before write because
            # SQLite's ON CONFLICT ... DO UPDATE is awkward to combine
            # with our need to know whether this was a create or merge.
            existing = await (
                await db.execute(
                    "SELECT id, count FROM gateway_alarms WHERE source = ? AND fingerprint = ?",
                    (a.source, a.fingerprint),
                )
            ).fetchone()

            if existing:
                # Merge: bump count, refresh last_seen, un-dismiss if it
                # came back (a dismissed alarm firing again deserves
                # attention — the user thought they were done with it).
                await db.execute(
                    """UPDATE gateway_alarms
                       SET count = count + 1,
                           last_seen_at = ?,
                           dismissed = 0,
                           dismissed_at = NULL,
                           raw_json = ?,
                           message = ?,
                           severity = ?
                       WHERE id = ?""",
                    (ts, raw_json, a.message, a.severity, existing["id"]),
                )
                updated += 1
            else:
                # Create: fresh row with count=1.
                alarm_id = f"alrm-{uuid.uuid4().hex[:12]}"
                await db.execute(
                    """INSERT INTO gateway_alarms
                       (id, source, source_label, severity, category, signature,
                        message, src_ip, dst_ip, device_id, device_name,
                        fingerprint, first_seen_at, last_seen_at, count,
                        acknowledged, dismissed, raw_json)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0, 0, ?)""",
                    (
                        alarm_id,
                        a.source,
                        a.source_label,
                        a.severity,
                        a.category,
                        a.signature,
                        a.message,
                        a.src_ip,
                        a.dst_ip,
                        a.device_id,
                        a.device_name,
                        a.fingerprint,
                        ts,
                        ts,
                        raw_json,
                    ),
                )
                new_ids.append(alarm_id)
                new_alarms.append(
                    GatewayAlarm(
                        id=alarm_id,
                        source=a.source,
                        source_label=a.source_label,
                        severity=a.severity,
                        category=a.category,
                        signature=a.signature,
                        message=a.message,
                        src_ip=a.src_ip,
                        dst_ip=a.dst_ip,
                        device_id=a.device_id,
                        device_name=a.device_name,
                        fingerprint=a.fingerprint,
                        first_seen_at=ts,
                        last_seen_at=ts,
                        count=1,
                        raw=a.raw,
                    )
                )
        await db.commit()

    # Emit exactly one socket event per genuinely-new alarm. We batch
    # the summary into the event payload so badges can update without
    # a follow-up HTTP call.
    if new_alarms:
        ns = get_notification_service()
        summary = await get_summary()
        for alm in new_alarms:
            await ns.emit_alarm_new(alm.model_dump(), summary.model_dump())

    log.info(
        "alarms upsert: %d new, %d merged (source=%s)",
        len(new_ids),
        updated,
        alarms[0].source if alarms else "?",
    )
    return (len(new_ids), updated)


async def list_alarms(
    limit: int = 200,
    include_dismissed: bool = False,
    source: Optional[AlarmSource] = None,
    severity: Optional[AlarmSeverity] = None,
) -> list[GatewayAlarm]:
    """Reverse-chrono list for the Security page. Cheap — the
    last_seen DESC index covers the sort and the partial WHERE."""
    where: list[str] = []
    args: list = []
    if not include_dismissed:
        where.append("dismissed = 0")
    if source:
        where.append("source = ?")
        args.append(source)
    if severity:
        where.append("severity = ?")
        args.append(severity)
    clause = ("WHERE " + " AND ".join(where)) if where else ""

    async with get_db() as db:
        rows = await (
            await db.execute(
                f"SELECT * FROM gateway_alarms {clause} ORDER BY last_seen_at DESC LIMIT ?",
                (*args, limit),
            )
        ).fetchall()
    return [_row_to_alarm(r) for r in rows]


async def get_summary() -> AlarmSummary:
    """Counts for sidebar badge + Security page header.

    Excludes dismissed alarms from every count — a dismissed alarm is
    archived, not "unacknowledged but handled".
    """
    async with get_db() as db:
        rows = await (
            await db.execute(
                """SELECT severity, COUNT(*) c,
                      SUM(CASE WHEN acknowledged = 0 THEN 1 ELSE 0 END) ack
               FROM gateway_alarms
               WHERE dismissed = 0
               GROUP BY severity"""
            )
        ).fetchall()
    out = AlarmSummary()
    for r in rows:
        sev = r["severity"] or "info"
        c = int(r["c"] or 0)
        u = int(r["ack"] or 0)
        out.total += c
        out.unacknowledged += u
        setattr(out, sev, c + getattr(out, sev, 0))
    return out


async def acknowledge(alarm_id: str) -> bool:
    now = datetime.now(timezone.utc).isoformat()
    async with get_db() as db:
        cur = await db.execute(
            "UPDATE gateway_alarms SET acknowledged = 1, acknowledged_at = ? WHERE id = ?",
            (now, alarm_id),
        )
        await db.commit()
        return cur.rowcount > 0


async def dismiss(alarm_id: str) -> bool:
    now = datetime.now(timezone.utc).isoformat()
    async with get_db() as db:
        cur = await db.execute(
            "UPDATE gateway_alarms SET dismissed = 1, dismissed_at = ? WHERE id = ?",
            (now, alarm_id),
        )
        await db.commit()
        return cur.rowcount > 0


async def clear_dismissed() -> int:
    """Hard-delete all dismissed alarms. Returns count deleted. Used
    by the "Archive" button on the Security page — a dismiss → delete
    escape hatch so the table doesn't grow forever."""
    async with get_db() as db:
        cur = await db.execute("DELETE FROM gateway_alarms WHERE dismissed = 1")
        await db.commit()
        return cur.rowcount


def _row_to_alarm(row) -> GatewayAlarm:
    try:
        raw = json.loads(row["raw_json"] or "{}")
    except Exception:
        raw = {}
    return GatewayAlarm(
        id=row["id"],
        source=row["source"],
        source_label=row["source_label"] or "",
        severity=row["severity"] or "info",
        category=row["category"] or "",
        signature=row["signature"] or "",
        message=row["message"],
        src_ip=row["src_ip"] or "",
        dst_ip=row["dst_ip"] or "",
        device_id=row["device_id"],
        device_name=row["device_name"] or "",
        fingerprint=row["fingerprint"],
        first_seen_at=row["first_seen_at"],
        last_seen_at=row["last_seen_at"],
        count=int(row["count"] or 1),
        acknowledged=bool(row["acknowledged"]),
        acknowledged_at=row["acknowledged_at"],
        dismissed=bool(row["dismissed"]),
        dismissed_at=row["dismissed_at"],
        raw=raw,
    )
