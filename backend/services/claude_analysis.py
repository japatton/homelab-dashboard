from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from datetime import datetime, timezone

from database import get_db
from models.device import Device

log = logging.getLogger(__name__)

_MOCK = os.getenv("BACKEND_MOCK", "false").lower() == "true"

# Cap concurrent Claude analyses. One run can burn 2-4k tokens + spawn a
# sandbox git clone — if the scheduler fires while a manual trigger is
# still in flight (or the user clicks "Analyze" several times), serialise
# them. 2 is "one running, one queued"; tune up if you have API headroom
# and good parallel sandbox isolation.
_CLAUDE_CONCURRENCY = int(os.getenv("CLAUDE_MAX_CONCURRENT", "2"))
_claude_semaphore = asyncio.Semaphore(_CLAUDE_CONCURRENCY)


async def analyze_unknown_device(device: Device) -> str | None:
    """
    Trigger a Claude analysis for a single unknown device.
    Inserts a pending staged change into the DB and emits a socket notification.
    Returns the staged change ID, or None if analysis was skipped/failed.

    Concurrency is bounded by `_claude_semaphore` — see module top for
    rationale. This is module-global rather than per-caller so the
    scheduler + a manual UI trigger can't run multiple analyses past
    the cap simultaneously.
    """
    if _MOCK:
        log.debug("Claude analysis skipped in MOCK mode")
        return None

    from config import get_config_manager
    cfg = get_config_manager().get()
    if not cfg.claude.enabled:
        log.debug("Claude integration disabled — skipping analysis for %s", device.id)
        return None

    # Acquire the semaphore *after* the fast skip paths — no point queueing
    # behind an in-flight analysis only to bail on `claude.enabled`.
    async with _claude_semaphore:
        return await _analyze_unknown_device_locked(device, cfg)


async def _analyze_unknown_device_locked(device: Device, cfg) -> str | None:
    """Inner body — runs under the concurrency semaphore."""

    # Don't re-analyse a device that already has a pending staged change
    async with get_db() as db:
        existing = await (await db.execute(
            """SELECT id FROM claude_staged_changes
               WHERE device_id = ? AND status = 'pending'""",
            (device.id,),
        )).fetchone()
    if existing:
        log.debug("Device %s already has a pending staged change — skipping", device.id)
        return None

    device_context = {
        "ip": device.ip,
        "hostname": device.hostname,
        "os_guess": device.metadata.get("os_guess"),
        "open_ports": [s.port for s in device.services],
        "services": [
            {"port": s.port, "protocol": s.protocol, "name": s.name, "version": s.version}
            for s in device.services
        ],
        "banners": device.metadata.get("banners", {}),
    }

    try:
        from services.claude_runner import run_device_analysis
        result = await run_device_analysis(device_context)
    except Exception as e:
        log.error("Claude analysis failed for device %s: %s", device.id, e)
        return None

    change_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    async with get_db() as db:
        await db.execute(
            """INSERT INTO claude_staged_changes
               (id, triggered_at, device_id, device_context, reason,
                diff_preview, generated_files, status)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')""",
            (
                change_id,
                now,
                device.id,
                json.dumps(device_context),
                result["reason"],
                result["diff_preview"],
                json.dumps(result["generated_files"]),
            ),
        )
        # Store sandbox_dir for later apply step
        await db.execute(
            """UPDATE claude_staged_changes SET device_context = ?
               WHERE id = ?""",
            (
                json.dumps({**device_context, "_sandbox_dir": result["sandbox_dir"]}),
                change_id,
            ),
        )
        await db.commit()

    # Emit real-time notification
    try:
        from services.notification_service import get_notification_service
        ns = get_notification_service()
        await ns.emit_claude_staged({
            "id": change_id,
            "triggered_at": now,
            "device_id": device.id,
            "reason": result["reason"],
            "diff_preview": result["diff_preview"],
            "generated_files": result["generated_files"],
            "status": "pending",
        })
    except Exception as e:
        log.warning("Failed to emit claude:staged event: %s", e)

    log.info("Claude staged change %s created for device %s", change_id, device.id)
    return change_id


async def run_analysis_for_unknown_devices(devices: list[Device]) -> int:
    """Analyse all unknown devices that qualify. Returns count of new staged changes."""
    from services.device_service import detect_unknown_devices
    unknown = detect_unknown_devices(devices)
    count = 0
    for device in unknown:
        result = await analyze_unknown_device(device)
        if result:
            count += 1
    return count
