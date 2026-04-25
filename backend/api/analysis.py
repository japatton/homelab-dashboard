from __future__ import annotations

import os

from fastapi import APIRouter, HTTPException

from services.analysis_service import (
    delete_report,
    get_report,
    list_reports,
    run_daily_analysis,
)
from services.background_tasks import spawn

router = APIRouter(prefix="/api/analysis", tags=["analysis"])

_MOCK = os.getenv("BACKEND_MOCK", "false").lower() == "true"


@router.get("/reports")
async def reports_index(limit: int = 50):
    """Newest-first list with a short preview for each report."""
    if _MOCK:
        return []
    return await list_reports(limit=limit)


@router.get("/reports/{report_id}")
async def report_detail(report_id: str):
    r = await get_report(report_id)
    if not r:
        raise HTTPException(status_code=404, detail="Report not found")
    return r


@router.delete("/reports/{report_id}")
async def report_delete(report_id: str):
    from services.audit_service import write_audit
    ok = await delete_report(report_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Report not found")
    await write_audit("delete_analysis_report", "user", {"report_id": report_id})
    return {"deleted": report_id}


@router.post("/trigger")
async def trigger_analysis(period_hours: int = 24):
    """Fire an analysis run now. Returns immediately; the report lands in
    /reports once the model responds (Gemma 4B on a workstation GPU is
    usually 10–60 seconds, longer on CPU)."""
    if _MOCK:
        return {"triggered": True, "mock": True}

    from services.audit_service import write_audit
    # Fire-and-forget — the job persists its own result whether success or failure.
    spawn(run_daily_analysis(period_hours=period_hours), name="analysis:daily")
    await write_audit("trigger_analysis", "user", {"period_hours": period_hours})
    return {"triggered": True, "period_hours": period_hours}
