"""Unified gateway-alarm API.

All gateway integrations (OPNsense Suricata, Firewalla alarms,
future additions) feed a single feed at /api/alarms. The frontend's
Security page reads from here; sidebar badge counts come from
/api/alarms/summary.

Design notes:

  - GETs are cheap (indexed by last_seen DESC) and safe to poll from
    the UI without caching on the server side.
  - ACK and DISMISS are distinct: ACK means "I've seen it, stop
    pinging me" — the row stays in the list, just demoted from the
    unacknowledged count. DISMISS means "this is resolved or not
    interesting" — it falls out of the default feed entirely.
  - DELETE endpoint is deliberately NOT exposed. The only path to
    hard-delete is POST /clear-dismissed which acts on ALL dismissed
    rows at once. This keeps casual API use from nuking history
    and matches the "Archive" button's "clear what's been dismissed"
    semantics.
"""

from __future__ import annotations

import os
from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from models.alarm import AlarmSeverity, AlarmSource
from services.alarm_service import (
    acknowledge,
    clear_dismissed,
    dismiss,
    get_summary,
    list_alarms,
)
from services.notification_service import get_notification_service

router = APIRouter(prefix="/api/alarms", tags=["alarms"])

_MOCK = os.getenv("BACKEND_MOCK", "false").lower() == "true"


# ─── Mock fixtures ────────────────────────────────────────────────────
# A few realistic alarms so the Security page renders something when
# BACKEND_MOCK=true. Severity mix covers every palette level so the
# frontend legend can be eyeballed. Timestamps are intentionally
# recent-looking to keep the UI "alive" in demos.

_MOCK_ALARMS = [
    {
        "id": "alrm-mock-001",
        "source": "opnsense",
        "source_label": "OPNsense 24.7.4",
        "severity": "critical",
        "category": "Trojan Activity",
        "signature": "ET TROJAN Possible Emotet HTTP",
        "message": "ET TROJAN Possible Emotet HTTP",
        "src_ip": "192.168.1.87",
        "dst_ip": "203.0.113.45",
        "device_id": None,
        "device_name": "",
        "fingerprint": "192.168.1.87|203.0.113.45|emotet|2026-04-21T18:40",
        "first_seen_at": "2026-04-21T18:40:12+00:00",
        "last_seen_at": "2026-04-21T18:42:55+00:00",
        "count": 4,
        "acknowledged": False,
        "acknowledged_at": None,
        "dismissed": False,
        "dismissed_at": None,
        "raw": {"protocol": "tcp", "severity_raw": 1},
    },
    {
        "id": "alrm-mock-002",
        "source": "firewalla",
        "source_label": "HomeLab Firewalla Gold",
        "severity": "high",
        "category": "Security Activity",
        "signature": "Security Activity",
        "message": "Suspicious connection blocked: 80.82.77.139",
        "src_ip": "192.168.1.42",
        "dst_ip": "80.82.77.139",
        "device_id": "aa:bb:cc:11:22:33",
        "device_name": "Living Room TV",
        "fingerprint": "gid-123|aa:bb:cc:11:22:33|1|2026-04-21T17:55",
        "first_seen_at": "2026-04-21T17:55:10+00:00",
        "last_seen_at": "2026-04-21T17:55:10+00:00",
        "count": 1,
        "acknowledged": False,
        "acknowledged_at": None,
        "dismissed": False,
        "dismissed_at": None,
        "raw": {"type": "1", "direction": "outbound"},
    },
    {
        "id": "alrm-mock-003",
        "source": "firewalla",
        "source_label": "HomeLab Firewalla Gold",
        "severity": "medium",
        "category": "Open Port",
        "signature": "Open Port",
        "message": "Open port 8080 detected on Jellyfin Server",
        "src_ip": "192.168.1.50",
        "dst_ip": "",
        "device_id": "aa:bb:cc:44:55:66",
        "device_name": "Jellyfin Server",
        "fingerprint": "gid-123|aa:bb:cc:44:55:66|14|2026-04-21T12:00",
        "first_seen_at": "2026-04-21T12:00:00+00:00",
        "last_seen_at": "2026-04-21T12:00:00+00:00",
        "count": 1,
        "acknowledged": True,
        "acknowledged_at": "2026-04-21T12:30:00+00:00",
        "dismissed": False,
        "dismissed_at": None,
        "raw": {"type": "14"},
    },
    {
        "id": "alrm-mock-004",
        "source": "firewalla",
        "source_label": "HomeLab Firewalla Gold",
        "severity": "info",
        "category": "New Device",
        "signature": "New Device",
        "message": "Found a new device Pixel-8 connected to your network.",
        "src_ip": "192.168.1.212",
        "dst_ip": "",
        "device_id": "aa:bb:cc:77:88:99",
        "device_name": "Pixel-8",
        "fingerprint": "gid-123|aa:bb:cc:77:88:99|5|2026-04-21T09:15",
        "first_seen_at": "2026-04-21T09:15:01+00:00",
        "last_seen_at": "2026-04-21T09:15:01+00:00",
        "count": 1,
        "acknowledged": False,
        "acknowledged_at": None,
        "dismissed": False,
        "dismissed_at": None,
        "raw": {"type": "5"},
    },
]

_MOCK_SUMMARY = {
    "total": 4,
    "unacknowledged": 3,
    "critical": 1,
    "high": 1,
    "medium": 1,
    "low": 0,
    "info": 1,
}


# ─── Endpoints ────────────────────────────────────────────────────────


@router.get("")
async def list_all(
    limit: int = Query(200, ge=1, le=1000),
    include_dismissed: bool = Query(False),
    source: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
):
    """Reverse-chrono list for the Security page. Default excludes
    dismissed rows — flip `include_dismissed=true` to see the archive.
    Filters compose (source AND severity) server-side."""
    if _MOCK:
        rows = list(_MOCK_ALARMS)
        if not include_dismissed:
            rows = [r for r in rows if not r["dismissed"]]
        if source:
            rows = [r for r in rows if r["source"] == source]
        if severity:
            rows = [r for r in rows if r["severity"] == severity]
        return {"alarms": rows[:limit]}

    src: Optional[AlarmSource] = source if source in ("opnsense", "firewalla") else None  # type: ignore[assignment]
    sev: Optional[AlarmSeverity] = (
        severity if severity in ("critical", "high", "medium", "low", "info") else None
    )  # type: ignore[assignment]
    alarms = await list_alarms(
        limit=limit,
        include_dismissed=include_dismissed,
        source=src,
        severity=sev,
    )
    return {"alarms": [a.model_dump() for a in alarms]}


@router.get("/summary")
async def summary():
    """Counts-by-severity payload for the sidebar badge + page header."""
    if _MOCK:
        return _MOCK_SUMMARY
    s = await get_summary()
    return s.model_dump()


@router.post("/{alarm_id}/acknowledge")
async def ack(alarm_id: str):
    """Mark as acknowledged. Stays in the feed but drops out of the
    unacknowledged count and the sidebar badge."""
    if _MOCK:
        for r in _MOCK_ALARMS:
            if r["id"] == alarm_id:
                r["acknowledged"] = True
                r["acknowledged_at"] = "2026-04-21T19:00:00+00:00"
                return {"ok": True}
        raise HTTPException(status_code=404, detail="alarm not found")
    ok = await acknowledge(alarm_id)
    if not ok:
        raise HTTPException(status_code=404, detail="alarm not found")
    # Push a fresh summary so the sidebar badge ticks down without
    # a full page refresh.
    try:
        s = await get_summary()
        await get_notification_service().emit_alarm_summary(s.model_dump())
    except Exception:
        pass
    return {"ok": True}


@router.post("/{alarm_id}/dismiss")
async def dismiss_one(alarm_id: str):
    """Mark as dismissed. Falls out of the default feed entirely."""
    if _MOCK:
        for r in _MOCK_ALARMS:
            if r["id"] == alarm_id:
                r["dismissed"] = True
                r["dismissed_at"] = "2026-04-21T19:00:00+00:00"
                return {"ok": True}
        raise HTTPException(status_code=404, detail="alarm not found")
    ok = await dismiss(alarm_id)
    if not ok:
        raise HTTPException(status_code=404, detail="alarm not found")
    try:
        s = await get_summary()
        await get_notification_service().emit_alarm_summary(s.model_dump())
    except Exception:
        pass
    return {"ok": True}


@router.post("/clear-dismissed")
async def clear_all_dismissed():
    """Hard-delete every dismissed alarm. Paired with the Archive
    button on the Security page — a "dismiss then clear" flow that
    keeps the table from growing unbounded."""
    if _MOCK:
        before = len(_MOCK_ALARMS)
        _MOCK_ALARMS[:] = [r for r in _MOCK_ALARMS if not r["dismissed"]]
        return {"deleted": before - len(_MOCK_ALARMS)}
    n = await clear_dismissed()
    try:
        s = await get_summary()
        await get_notification_service().emit_alarm_summary(s.model_dump())
    except Exception:
        pass
    return {"deleted": n}
