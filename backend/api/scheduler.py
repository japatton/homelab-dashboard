from __future__ import annotations

import os

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from scheduler.state import get_all_job_states

router = APIRouter(prefix="/api/scheduler", tags=["scheduler"])


class IntervalUpdate(BaseModel):
    nmap_minutes: int | None = None
    unifi_seconds: int | None = None
    openvas_hours: int | None = None


_MOCK = os.getenv("BACKEND_MOCK", "false").lower() == "true"


@router.get("/status")
async def scheduler_status():
    if _MOCK:
        return {
            "running": False,
            "mock": True,
            "jobs": [
                {"id": "nmap_scan", "next_run": None},
                {"id": "unifi_poll", "next_run": None},
            ],
        }
    from scheduler import get_all_jobs
    from scheduler.scheduler import get_scheduler

    sched = get_scheduler()
    return {
        "running": sched.running,
        "mock": False,
        "jobs": get_all_jobs(),
    }


@router.get("/history")
async def scheduler_history():
    return await get_all_job_states()


@router.post("/trigger/{job_id}")
async def trigger_job(job_id: str):
    if _MOCK:
        return {"triggered": job_id, "mock": True}

    from scheduler.jobs import (
        nmap_scan_job,
        unifi_poll_job,
        openvas_scan_job,
        latency_poll_job,
    )
    from services.background_tasks import spawn

    if job_id == "nmap_scan":
        spawn(nmap_scan_job(), name="job:nmap_scan")
    elif job_id == "unifi_poll":
        spawn(unifi_poll_job(), name="job:unifi_poll")
    elif job_id == "openvas_scan":
        spawn(openvas_scan_job(), name="job:openvas_scan")
    elif job_id == "latency_poll":
        spawn(latency_poll_job(), name="job:latency_poll")
    else:
        raise HTTPException(status_code=404, detail=f"Unknown job: {job_id}")

    from services.audit_service import write_audit

    await write_audit("trigger_job", "user", {"job_id": job_id})
    return {"triggered": job_id}


@router.put("/intervals")
async def update_intervals(body: IntervalUpdate):
    """Update one or more job intervals. All fields optional; only those
    provided are applied. Accepts a JSON body (not query params)."""
    if _MOCK:
        return {"updated": True, "mock": True}

    from scheduler import update_interval
    from config import get_config_manager

    mgr = get_config_manager()
    cfg = mgr.get()
    updated: dict = {}

    if body.nmap_minutes is not None:
        if update_interval("nmap_scan", minutes=body.nmap_minutes):
            cfg.scheduler.nmap_interval_minutes = body.nmap_minutes
            updated["nmap_minutes"] = body.nmap_minutes

    if body.unifi_seconds is not None:
        if update_interval("unifi_poll", seconds=body.unifi_seconds):
            cfg.scheduler.unifi_poll_interval_seconds = body.unifi_seconds
            updated["unifi_seconds"] = body.unifi_seconds

    if body.openvas_hours is not None:
        if update_interval("openvas_scan", hours=body.openvas_hours):
            cfg.scheduler.openvas_interval_hours = body.openvas_hours
            updated["openvas_hours"] = body.openvas_hours

    if updated:
        mgr.save(cfg)
        from services.audit_service import write_audit

        await write_audit("save_scan_intervals", "user", updated)

    return {"updated": updated}


@router.post("/pause/{job_id}")
async def pause_job(job_id: str):
    """Pause a scheduled job. It stops firing on its interval but can still
    be triggered manually via /trigger/{job_id}. State persists in memory
    only — a backend restart re-enables all jobs."""
    if _MOCK:
        return {"paused": job_id, "mock": True}
    from scheduler.scheduler import pause_job as _pause

    if not _pause(job_id):
        raise HTTPException(status_code=404, detail=f"Unknown job: {job_id}")
    from services.audit_service import write_audit

    await write_audit("pause_job", "user", {"job_id": job_id})
    return {"paused": job_id}


@router.post("/resume/{job_id}")
async def resume_job(job_id: str):
    if _MOCK:
        return {"resumed": job_id, "mock": True}
    from scheduler.scheduler import resume_job as _resume

    if not _resume(job_id):
        raise HTTPException(status_code=404, detail=f"Unknown job: {job_id}")
    from services.audit_service import write_audit

    await write_audit("resume_job", "user", {"job_id": job_id})
    return {"resumed": job_id}
