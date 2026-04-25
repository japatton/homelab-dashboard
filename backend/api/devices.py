from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Body, HTTPException, Query

from database import get_db
from models.device import Device

router = APIRouter(prefix="/api/devices", tags=["devices"])

_MOCK = os.getenv("BACKEND_MOCK", "false").lower() == "true"


@router.get("", response_model=list[Device])
async def list_devices(
    search: Optional[str] = None,
    device_type: Optional[str] = None,
    status: Optional[str] = None,
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=500, ge=1, le=1000),
):
    if _MOCK:
        from mock.fixtures import MOCK_DEVICES
        devices = MOCK_DEVICES
        if search:
            s = search.lower()
            devices = [d for d in devices if s in (d.hostname or "").lower()
                       or s in (d.ip or "").lower() or s in (d.label or "").lower()]
        if device_type:
            devices = [d for d in devices if d.device_type == device_type]
        if status:
            devices = [d for d in devices if d.status == status]
        start = (page - 1) * limit
        return devices[start: start + limit]

    from services.device_service import get_all_devices
    all_devs = await get_all_devices()
    if search:
        s = search.lower()
        all_devs = [d for d in all_devs
                    if s in (d.hostname or "").lower()
                    or s in (d.ip or "").lower()
                    or s in (d.label or "").lower()]
    if device_type:
        all_devs = [d for d in all_devs if d.device_type == device_type]
    if status:
        all_devs = [d for d in all_devs if d.status == status]
    start = (page - 1) * limit
    return all_devs[start: start + limit]


@router.get("/{device_id}", response_model=Device)
async def get_device(device_id: str):
    if _MOCK:
        from mock.fixtures import MOCK_DEVICES_BY_ID
        device = MOCK_DEVICES_BY_ID.get(device_id)
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        return device

    async with get_db() as db:
        row = await (await db.execute(
            "SELECT * FROM devices WHERE id = ?",
            (device_id,),
        )).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Device not found")

        # Single aggregated query instead of four correlated sub-selects.
        # With the (device_id, severity) index this is one index seek + one
        # grouped scan; the old form re-scanned the index four times per
        # request. Noticeable on the network-map popovers where this
        # endpoint can fire for every hovered device.
        sev_rows = await (await db.execute(
            """SELECT severity, COUNT(*) AS n
                 FROM vuln_results
                WHERE device_id = ?
                GROUP BY severity""",
            (device_id,),
        )).fetchall()
    sev_counts = {r["severity"]: r["n"] for r in sev_rows}
    vcrit = sev_counts.get("critical", 0)
    vhigh = sev_counts.get("high", 0)
    vmed  = sev_counts.get("medium", 0)
    vlow  = sev_counts.get("low", 0)

    from models.device import VulnSummary
    from services.device_service import _load_services_for_device

    meta = json.loads(row["metadata"] or "{}")

    async with get_db() as db:
        services = await _load_services_for_device(db, row["id"])

    def _parse_ts(v):
        if not v:
            return None
        try:
            return datetime.fromisoformat(v)
        except (TypeError, ValueError):
            return None

    return Device(
        id=row["id"], mac=row["mac"], ip=row["ip"], hostname=row["hostname"],
        label=row["label"], device_type=row["device_type"] or "unknown",
        status="online" if row["is_online"] else "offline",
        confidence=row["confidence"] or 0.0,
        metadata=meta, services=services, is_online=bool(row["is_online"]),
        first_seen=_parse_ts(row["first_seen"]),
        last_seen=_parse_ts(row["last_seen"]),
        vuln_summary=VulnSummary(
            critical=vcrit, high=vhigh, medium=vmed, low=vlow,
        ),
    )


@router.put("/{device_id}/label")
async def update_label(device_id: str, label: str = Body(..., embed=True)):
    if _MOCK:
        return {"device_id": device_id, "label": label}

    async with get_db() as db:
        result = await db.execute(
            "UPDATE devices SET label = ? WHERE id = ?", (label, device_id)
        )
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="Device not found")
        await db.commit()
    return {"device_id": device_id, "label": label}
