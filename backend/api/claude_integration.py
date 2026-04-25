from __future__ import annotations

from services.background_tasks import spawn
import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException

from database import get_db

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/claude", tags=["claude"])

_MOCK = os.getenv("BACKEND_MOCK", "false").lower() == "true"

# ── Mock fixture (used in MOCK mode only) ─────────────────────────────────────
_staged: dict[str, dict] = {
    "mock-change-01": {
        "id": "mock-change-01",
        "triggered_at": "2026-04-17T04:00:00Z",
        "device_id": "dev-unknown-01",
        "device_context": {
            "ip": "192.168.1.200",
            "open_ports": [8443, 9000],
            "banners": {"9000": "HTTP/1.1 200 OK\r\nServer: Portainer/2.x"},
        },
        "reason": "Unknown device at 192.168.1.200 — open ports 8443/9000 with Portainer banner detected. Generating container management integration.",
        "diff_preview": (
            "--- /dev/null\n"
            "+++ portainer_integration.py\n"
            "@@ -0,0 +1,22 @@\n"
            "+from __future__ import annotations\n"
            "+import httpx\n"
            "+\n"
            "+DEVICE_TYPE = 'server'\n"
            "+DEVICE_LABEL = 'Portainer'\n"
            "+\n"
            "+async def enrich(ip: str) -> list[dict]:\n"
            "+    try:\n"
            "+        async with httpx.AsyncClient(verify=False, timeout=5) as c:\n"
            "+            r = await c.get(f'https://{ip}:9000/api/status')\n"
            "+            if r.status_code == 200:\n"
            "+                data = r.json()\n"
            "+                return [{'port': 9000, 'protocol': 'tcp',\n"
            "+                         'name': 'portainer',\n"
            "+                         'version': data.get('Version', ''),\n"
            "+                         'launch_url': f'https://{ip}:9000'}]\n"
            "+    except Exception:\n"
            "+        pass\n"
            "+    return []\n"
        ),
        "generated_files": ["portainer_integration.py"],
        "status": "pending",
    }
}


# ── Helpers ───────────────────────────────────────────────────────────────────

# Local alias kept so the call sites below read naturally and existing callers
# don't need to change. The real implementation (with rolling 100-entry
# retention) lives in services/audit_service.py — centralising there keeps
# retention consistent across UI-driven writes from every router.
from services.audit_service import write_audit as _write_audit  # noqa: E402


async def _get_change(change_id: str) -> Optional[dict]:
    if _MOCK:
        return _staged.get(change_id)
    async with get_db() as db:
        row = await (
            await db.execute(
                "SELECT * FROM claude_staged_changes WHERE id = ?", (change_id,)
            )
        ).fetchone()
    if row is None:
        return None
    d = dict(row)
    d["device_context"] = json.loads(d.get("device_context") or "{}")
    d["generated_files"] = json.loads(d.get("generated_files") or "[]")
    return d


# ── Routes ────────────────────────────────────────────────────────────────────


@router.get("/staged")
async def get_staged():
    if _MOCK:
        return [v for v in _staged.values() if v["status"] == "pending"]

    async with get_db() as db:
        rows = await (
            await db.execute(
                "SELECT * FROM claude_staged_changes WHERE status = 'pending' ORDER BY triggered_at DESC"
            )
        ).fetchall()

    results = []
    for row in rows:
        d = dict(row)
        d["device_context"] = json.loads(d.get("device_context") or "{}")
        d["generated_files"] = json.loads(d.get("generated_files") or "[]")
        results.append(d)
    return results


@router.post("/approve/{change_id}")
async def approve_change(change_id: str):
    change = await _get_change(change_id)
    if not change:
        raise HTTPException(status_code=404, detail="Staged change not found")
    if change["status"] != "pending":
        raise HTTPException(
            status_code=400, detail=f"Change is already {change['status']}"
        )

    now = datetime.now(timezone.utc).isoformat()

    if _MOCK:
        _staged[change_id]["status"] = "approved"
        _staged[change_id]["reviewed_at"] = now
    else:
        async with get_db() as db:
            await db.execute(
                "UPDATE claude_staged_changes SET status='approved', reviewed_at=? WHERE id=?",
                (now, change_id),
            )
            await db.commit()

        # Apply the generated files in background
        ctx = change.get("device_context", {})
        sandbox_dir = ctx.get("_sandbox_dir", "")
        generated = change.get("generated_files", [])
        if sandbox_dir and generated:
            spawn(
                _do_apply(change_id, sandbox_dir, generated, change),
                name=f"claude:apply:{change_id}",
            )

    await _write_audit(
        "approve_claude_change",
        "user",
        {
            "change_id": change_id,
            "device_id": change.get("device_id"),
        },
    )
    return {"approved": change_id}


@router.post("/reject/{change_id}")
async def reject_change(change_id: str):
    change = await _get_change(change_id)
    if not change:
        raise HTTPException(status_code=404, detail="Staged change not found")

    now = datetime.now(timezone.utc).isoformat()

    if _MOCK:
        _staged[change_id]["status"] = "rejected"
        _staged[change_id]["reviewed_at"] = now
    else:
        async with get_db() as db:
            await db.execute(
                "UPDATE claude_staged_changes SET status='rejected', reviewed_at=? WHERE id=?",
                (now, change_id),
            )
            await db.commit()

    await _write_audit(
        "reject_claude_change",
        "user",
        {
            "change_id": change_id,
            "device_id": change.get("device_id"),
        },
    )
    return {"rejected": change_id}


@router.get("/audit")
async def get_audit_log(limit: int = 50):
    # Delegated to services/audit_service so retention and JSON decoding stay
    # in one place. Endpoint path kept for frontend compatibility.
    from services.audit_service import list_audit

    return await list_audit(limit=limit)


@router.get("/history")
async def get_change_history(limit: int = 50):
    """All staged changes (approved + rejected + pending), newest first."""
    if _MOCK:
        return list(_staged.values())

    async with get_db() as db:
        rows = await (
            await db.execute(
                "SELECT * FROM claude_staged_changes ORDER BY triggered_at DESC LIMIT ?",
                (limit,),
            )
        ).fetchall()

    results = []
    for row in rows:
        d = dict(row)
        d["device_context"] = json.loads(d.get("device_context") or "{}")
        d["generated_files"] = json.loads(d.get("generated_files") or "[]")
        results.append(d)
    return results


async def _do_apply(
    change_id: str, sandbox_dir: str, generated_files: list[str], change: dict
) -> None:
    try:
        from services.claude_runner import apply_change

        copied = await apply_change(change_id, sandbox_dir, generated_files)
        log.info("Applied %d file(s) for change %s: %s", len(copied), change_id, copied)

        await _write_audit(
            "apply_claude_change",
            "system",
            {
                "change_id": change_id,
                "device_id": change.get("device_id"),
                "files_applied": copied,
            },
        )

        # Notify frontend
        from services.notification_service import get_notification_service

        ns = get_notification_service()
        await ns.emit_claude_staged(
            {
                "id": change_id,
                "status": "applied",
                "files_applied": copied,
            }
        )
    except Exception as e:
        log.error("apply_change failed: %s", e)
