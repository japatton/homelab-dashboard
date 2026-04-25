from __future__ import annotations

import json
import os
from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException

from database import get_db
from models.topology import TopologyGraph

router = APIRouter(prefix="/api/network", tags=["network"])

_MOCK = os.getenv("BACKEND_MOCK", "false").lower() == "true"


@router.get("/topology", response_model=TopologyGraph)
async def get_topology():
    if _MOCK:
        from mock.topology_fixtures import MOCK_TOPOLOGY
        return MOCK_TOPOLOGY

    async with get_db() as db:
        cursor = await db.execute(
            """SELECT id, device_type, ip, hostname, label, metadata,
                      position_x, position_y, is_online,
                      (SELECT COUNT(*) FROM vuln_results WHERE device_id = d.id AND severity = 'critical') as vuln_critical,
                      (SELECT COUNT(*) FROM vuln_results WHERE device_id = d.id AND severity = 'high') as vuln_high
               FROM devices d ORDER BY device_type"""
        )
        rows = await cursor.fetchall()

    from models.topology import NetworkNode, NetworkEdge, NodeData, NodePosition
    from datetime import datetime

    nodes = []
    for row in rows:
        meta = json.loads(row["metadata"] or "{}")
        nodes.append(NetworkNode(
            id=row["id"],
            position=NodePosition(x=row["position_x"] or 0, y=row["position_y"] or 0),
            data=NodeData(
                device_id=row["id"],
                label=row["label"] or row["hostname"] or row["ip"] or row["id"],
                device_type=row["device_type"] or "unknown",
                status="online" if row["is_online"] else "offline",
                ip=row["ip"],
                vuln_critical=row["vuln_critical"] or 0,
                vuln_high=row["vuln_high"] or 0,
                metadata=meta,
            ),
        ))

    return TopologyGraph(
        nodes=nodes,
        edges=[],
        last_updated=datetime.utcnow().isoformat(),
    )


@router.put("/topology/positions")
async def save_positions(positions: dict[str, dict] = Body(...)):
    """Persist user-dragged node positions."""
    async with get_db() as db:
        for device_id, pos in positions.items():
            await db.execute(
                "UPDATE devices SET position_x = ?, position_y = ? WHERE id = ?",
                (pos.get("x", 0), pos.get("y", 0), device_id),
            )
        await db.commit()
    return {"saved": len(positions)}


@router.get("/latency")
async def get_latency(
    device_id: Optional[str] = None,
    window_minutes: int = 60,
):
    """Return latency samples over a time window.

    If `device_id` is provided, returns samples for that single device.
    Otherwise returns samples for the primary gateway device.
    Response: {device_id, device_label, samples: [{ts, latency_ms}, ...]}.
    """
    if _MOCK:
        # Return a short synthetic series so the chart renders in mock mode
        from datetime import datetime, timedelta, timezone
        import random
        now = datetime.now(timezone.utc)
        samples = [
            {
                "ts": (now - timedelta(seconds=30 * (120 - i))).isoformat(),
                "latency_ms": round(2 + random.random() * 3, 2),
            }
            for i in range(120)
        ]
        return {"device_id": "mock-gw", "device_label": "Gateway (mock)", "samples": samples}

    from datetime import datetime, timedelta, timezone
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=window_minutes)).isoformat()

    async with get_db() as db:
        if not device_id:
            # Pick the first gateway as the default target
            gw_row = await (await db.execute(
                "SELECT id, label, hostname, ip FROM devices WHERE device_type = 'gateway' ORDER BY id LIMIT 1"
            )).fetchone()
            if not gw_row:
                return {"device_id": None, "device_label": None, "samples": []}
            device_id = gw_row["id"]
            label = gw_row["label"] or gw_row["hostname"] or gw_row["ip"] or "Gateway"
        else:
            d_row = await (await db.execute(
                "SELECT id, label, hostname, ip FROM devices WHERE id = ?", (device_id,)
            )).fetchone()
            if not d_row:
                raise HTTPException(status_code=404, detail="Device not found")
            label = d_row["label"] or d_row["hostname"] or d_row["ip"] or device_id

        rows = await (await db.execute(
            """SELECT ts, latency_ms FROM latency_samples
               WHERE device_id = ? AND ts >= ?
               ORDER BY ts ASC""",
            (device_id, cutoff),
        )).fetchall()

    samples = [
        {"ts": r["ts"], "latency_ms": r["latency_ms"]}
        for r in rows
    ]
    return {"device_id": device_id, "device_label": label, "samples": samples}


@router.get("/status")
async def get_network_status():
    if _MOCK:
        from mock.fixtures import MOCK_DEVICES
        online = sum(1 for d in MOCK_DEVICES if d.is_online)
        return {
            "total": len(MOCK_DEVICES),
            "online": online,
            "offline": len(MOCK_DEVICES) - online,
            "scanning": 0,
            "unknown_type": sum(1 for d in MOCK_DEVICES if d.device_type == "unknown"),
        }

    async with get_db() as db:
        total = (await (await db.execute("SELECT COUNT(*) FROM devices")).fetchone())[0]
        online = (await (await db.execute("SELECT COUNT(*) FROM devices WHERE is_online = 1")).fetchone())[0]
        unknown = (await (await db.execute("SELECT COUNT(*) FROM devices WHERE device_type = 'unknown'")).fetchone())[0]

    return {
        "total": total,
        "online": online,
        "offline": total - online,
        "scanning": 0,
        "unknown_type": unknown,
    }
