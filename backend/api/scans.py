from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Body, HTTPException

from models.scan import ScanJob, ScanProfile

router = APIRouter(prefix="/api/scans", tags=["scans"])

_MOCK = os.getenv("BACKEND_MOCK", "false").lower() == "true"

# In-memory job registry (augmented by DB in live mode)
_jobs: dict[str, ScanJob] = {}


async def _run_nmap(job: ScanJob, targets: list[str], profile: str) -> None:
    """Background task: run nmap, update topology, mark job done."""
    from services.notification_service import get_notification_service
    from integrations.nmap import NmapIntegration
    from services.device_service import merge_nmap_result
    from services.topology_service import build_topology_graph
    from database import get_db

    ns = get_notification_service()
    job.status = "running"

    try:
        await ns.emit_scan_progress(job.id, "nmap", 10, "Starting scan")
        nmap = NmapIntegration()
        result = await nmap.scan(targets, profile=profile)

        await ns.emit_scan_progress(
            job.id, "nmap", 65, f"Discovered {len(result.hosts)} hosts"
        )
        devices = await merge_nmap_result(result)

        await ns.emit_scan_progress(job.id, "nmap", 85, "Refreshing topology")
        topology = await build_topology_graph(devices)
        await ns.emit_topology_updated(topology)

        job.status = "completed"
        job.progress = 100
        job.completed_at = datetime.now(timezone.utc)

        await ns.emit_scan_complete(job.id, "nmap", len(devices), None)

        now = job.completed_at.isoformat()
        async with get_db() as db:
            await db.execute(
                """INSERT INTO scan_results (id, scan_type, status, target_count, result_count, started_at, completed_at)
                   VALUES (?, 'nmap', 'completed', ?, ?, ?, ?)""",
                (job.id, len(targets), len(devices), job.started_at.isoformat(), now),
            )
            await db.commit()

    except Exception as e:
        job.status = "failed"
        job.error = str(e)
        await ns.emit_scan_complete(job.id, "nmap", 0, str(e))


@router.post("/nmap", response_model=ScanJob)
async def trigger_nmap(
    targets: Optional[list[str]] = Body(None),
    profile: ScanProfile = Body("standard"),
):
    job = ScanJob(
        id=str(uuid.uuid4()),
        scan_type="nmap",
        status="pending",
        profile=profile,
        targets=targets,
        started_at=datetime.now(timezone.utc),
        progress=0,
    )
    _jobs[job.id] = job

    if _MOCK:
        job.status = "completed"
        job.progress = 100
        job.completed_at = datetime.now(timezone.utc)
        return job

    scan_targets = targets or ["192.168.0.0/24"]
    from services.background_tasks import spawn

    spawn(_run_nmap(job, scan_targets, profile), name=f"scan:nmap:{job.id}")
    return job


@router.post("/openvas", response_model=ScanJob)
async def trigger_openvas():
    job = ScanJob(
        id=str(uuid.uuid4()),
        scan_type="openvas",
        status="pending",
        started_at=datetime.now(timezone.utc),
    )
    _jobs[job.id] = job

    if _MOCK:
        job.status = "completed"
        job.progress = 100
        job.completed_at = datetime.now(timezone.utc)
        return job

    # Phase 5: OpenVAS integration
    raise HTTPException(status_code=501, detail="OpenVAS integration coming in Phase 5")


@router.get("/{scan_job_id}", response_model=ScanJob)
async def get_scan_status(scan_job_id: str):
    job = _jobs.get(scan_job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return job


@router.get("", response_model=list[ScanJob])
async def list_scans():
    return list(reversed(list(_jobs.values())))
