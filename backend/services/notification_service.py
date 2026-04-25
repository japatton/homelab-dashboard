from __future__ import annotations

import functools
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    import socketio as _sio_type


class NotificationService:
    def __init__(self) -> None:
        self._sio: "_sio_type.AsyncServer | None" = None

    def init(self, sio: "_sio_type.AsyncServer") -> None:
        self._sio = sio

    async def emit_topology_updated(self, graph, room: Optional[str] = None) -> None:
        if self._sio is None:
            return
        data = graph.model_dump() if hasattr(graph, "model_dump") else graph
        kwargs = {"to": room} if room else {}
        await self._sio.emit("topology:updated", data, **kwargs)

    async def emit_device_updated(self, device: dict) -> None:
        if self._sio:
            await self._sio.emit("device:updated", device)

    async def emit_scan_progress(
        self, job_id: str, scan_type: str, percent: int, message: str = ""
    ) -> None:
        if self._sio:
            await self._sio.emit("scan:progress", {
                "job_id": job_id,
                "scan_type": scan_type,
                "percent": percent,
                "message": message,
            })

    async def emit_scan_complete(
        self,
        job_id: str,
        scan_type: str,
        device_count: int,
        error: Optional[str] = None,
        device_id: Optional[str] = None,
    ) -> None:
        """Broadcast scan completion. `device_id` is set when the run
        targeted a single device (used by the Devices page to clear its
        per-row "scanning" spinner); omit it for network-wide scans."""
        if self._sio:
            payload: dict = {
                "job_id": job_id,
                "scan_type": scan_type,
                "device_count": device_count,
                "error": error,
            }
            if device_id is not None:
                payload["device_id"] = device_id
            await self._sio.emit("scan:complete", payload)

    async def emit_claude_staged(self, change: dict) -> None:
        if self._sio:
            await self._sio.emit("claude:staged", change)

    async def emit_vuln_updated(self, device_id: str, summary: dict) -> None:
        if self._sio:
            await self._sio.emit("vuln:updated", {"device_id": device_id, "summary": summary})

    async def emit_scheduler_tick(self, job_id: str, next_run: str) -> None:
        if self._sio:
            await self._sio.emit("scheduler:tick", {"job_id": job_id, "next_run": next_run})

    async def emit_alarm_new(self, alarm: dict, summary: dict) -> None:
        """Push a newly-created gateway alarm to all connected sockets.

        Payload carries both the full alarm row and the updated total-
        counts summary, so the sidebar badge can tick in lockstep with
        the Security page feed without a follow-up HTTP round-trip.
        `summary` is the AlarmSummary.model_dump() — keys
        {total, unacknowledged, critical, high, medium, low, info}.
        """
        if self._sio:
            await self._sio.emit("alarm:new", {"alarm": alarm, "summary": summary})

    async def emit_alarm_summary(self, summary: dict) -> None:
        """Push ONLY an updated counts summary (after ack / dismiss /
        archive). Frontend applies this to the sidebar badge without
        touching the feed list."""
        if self._sio:
            await self._sio.emit("alarm:summary", {"summary": summary})

    async def emit_openvas_reset(self, stage: str, percent: int, message: str = "", error: Optional[str] = None) -> None:
        """Progress for the "Reset OpenVAS Admin Password" flow.

        `stage` is a short machine-friendly slug ("stopping" / "wiping" /
        "starting" / "warmup" / "ready" / "error"). `percent` drives the
        progress bar in the modal; `message` is the human-readable line.
        """
        if self._sio:
            await self._sio.emit("openvas:reset", {
                "stage": stage,
                "percent": percent,
                "message": message,
                "error": error,
            })


@functools.lru_cache(maxsize=1)
def get_notification_service() -> NotificationService:
    return NotificationService()
