from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from database import get_db

log = logging.getLogger(__name__)


async def record_job_run(job_id: str, status: str, detail: str = "") -> None:
    now = datetime.now(timezone.utc).isoformat()
    async with get_db() as db:
        await db.execute(
            """INSERT INTO scheduler_state (job_id, last_run, status, detail)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(job_id) DO UPDATE SET last_run=excluded.last_run,
               status=excluded.status, detail=excluded.detail""",
            (job_id, now, status, detail),
        )
        await db.commit()


async def get_job_state(job_id: str) -> Optional[dict]:
    async with get_db() as db:
        row = await (
            await db.execute(
                "SELECT * FROM scheduler_state WHERE job_id = ?", (job_id,)
            )
        ).fetchone()
    if row is None:
        return None
    return dict(row)


async def get_all_job_states() -> list[dict]:
    async with get_db() as db:
        rows = await (
            await db.execute("SELECT * FROM scheduler_state ORDER BY last_run DESC")
        ).fetchall()
    return [dict(r) for r in rows]
