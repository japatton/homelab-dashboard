from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from apscheduler.executors.asyncio import AsyncIOExecutor
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

log = logging.getLogger(__name__)

_scheduler: Optional[AsyncIOScheduler] = None


def get_scheduler() -> AsyncIOScheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = AsyncIOScheduler(
            timezone="UTC",
            executors={"default": AsyncIOExecutor()},
        )
    return _scheduler


async def start_scheduler(
    nmap_interval_minutes: int = 15,
    unifi_interval_seconds: int = 30,
    openvas_interval_hours: int = 24,
    latency_interval_seconds: int = 30,
    analysis_hour_utc: int = 6,
    analysis_enabled: bool = False,
    opnsense_interval_seconds: int = 60,
    firewalla_interval_seconds: int = 120,
) -> None:
    from scheduler.jobs import (
        nmap_scan_job,
        unifi_poll_job,
        openvas_scan_job,
        latency_poll_job,
        daily_analysis_job,
        opnsense_poll_job,
        firewalla_poll_job,
    )

    sched = get_scheduler()

    # Kick the first run shortly after startup so the dashboard populates
    # without waiting a full interval. UniFi poll fires almost immediately
    # (5s — lets lifespan finish), nmap after 15s (CPU-heavier), OpenVAS
    # after 60s (rarely needed on first boot, but still earlier than 24h).
    now = datetime.now(timezone.utc)

    sched.add_job(
        nmap_scan_job,
        trigger=IntervalTrigger(minutes=nmap_interval_minutes),
        id="nmap_scan",
        replace_existing=True,
        misfire_grace_time=60,
        next_run_time=now + timedelta(seconds=15),
    )

    sched.add_job(
        unifi_poll_job,
        trigger=IntervalTrigger(seconds=unifi_interval_seconds),
        id="unifi_poll",
        replace_existing=True,
        misfire_grace_time=10,
        next_run_time=now + timedelta(seconds=5),
    )

    sched.add_job(
        openvas_scan_job,
        trigger=IntervalTrigger(hours=openvas_interval_hours),
        id="openvas_scan",
        replace_existing=True,
        misfire_grace_time=300,
        next_run_time=now + timedelta(seconds=60),
    )

    sched.add_job(
        latency_poll_job,
        trigger=IntervalTrigger(seconds=latency_interval_seconds),
        id="latency_poll",
        replace_existing=True,
        misfire_grace_time=15,
        next_run_time=now + timedelta(seconds=20),
    )

    # Gateway integrations (OPNsense, Firewalla) are always registered —
    # the job bodies silent-skip when their integration isn't enabled or
    # is missing credentials. This keeps the scheduler roster stable
    # regardless of which gateways the user has wired up, and lets the
    # Settings UI flip things on without a backend restart.
    sched.add_job(
        opnsense_poll_job,
        trigger=IntervalTrigger(seconds=opnsense_interval_seconds),
        id="opnsense_poll",
        replace_existing=True,
        misfire_grace_time=20,
        next_run_time=now + timedelta(seconds=10),
    )

    sched.add_job(
        firewalla_poll_job,
        trigger=IntervalTrigger(seconds=firewalla_interval_seconds),
        id="firewalla_poll",
        replace_existing=True,
        misfire_grace_time=30,
        next_run_time=now + timedelta(seconds=12),
    )

    # Daily AI analysis — CronTrigger at a fixed UTC hour so operators know
    # when to look for the report. Registered unconditionally so the user can
    # pause/resume and reschedule via the existing UI; if Ollama is disabled
    # at config level the job body short-circuits and logs a skip.
    sched.add_job(
        daily_analysis_job,
        trigger=CronTrigger(hour=analysis_hour_utc, minute=0, timezone="UTC"),
        id="daily_analysis",
        replace_existing=True,
        misfire_grace_time=1800,  # 30m — the analysis is not time-sensitive
    )

    sched.start()

    if not analysis_enabled:
        # Start paused so it doesn't fire when Ollama isn't configured yet.
        # User flips enabled=true in Settings → backend restart → job resumes.
        try:
            sched.get_job("daily_analysis").pause()
        except Exception:
            pass

    log.info(
        "Scheduler started — nmap every %dm, unifi every %ds, openvas every %dh, "
        "latency every %ds, opnsense every %ds, firewalla every %ds, "
        "daily_analysis at %02d:00 UTC (%s)",
        nmap_interval_minutes,
        unifi_interval_seconds,
        openvas_interval_hours,
        latency_interval_seconds,
        opnsense_interval_seconds,
        firewalla_interval_seconds,
        analysis_hour_utc,
        "enabled" if analysis_enabled else "paused",
    )


async def stop_scheduler() -> None:
    sched = get_scheduler()
    if sched.running:
        sched.shutdown(wait=False)
        log.info("Scheduler stopped")


def update_interval(job_id: str, **trigger_kwargs) -> bool:
    sched = get_scheduler()
    job = sched.get_job(job_id)
    if job is None:
        return False
    job.reschedule(trigger=IntervalTrigger(**trigger_kwargs))
    log.info("Job %s rescheduled: %s", job_id, trigger_kwargs)
    return True


def pause_job(job_id: str) -> bool:
    sched = get_scheduler()
    job = sched.get_job(job_id)
    if job is None:
        return False
    job.pause()
    log.info("Job %s paused", job_id)
    return True


def resume_job(job_id: str) -> bool:
    sched = get_scheduler()
    job = sched.get_job(job_id)
    if job is None:
        return False
    job.resume()
    log.info("Job %s resumed", job_id)
    return True


def _job_dict(job) -> dict:
    """APScheduler sets next_run_time=None when a job is paused."""
    return {
        "id": job.id,
        "next_run": job.next_run_time.isoformat() if job.next_run_time else None,
        "paused": job.next_run_time is None,
    }


def get_job_info(job_id: str) -> Optional[dict]:
    sched = get_scheduler()
    job = sched.get_job(job_id)
    if job is None:
        return None
    d = _job_dict(job)
    d["running"] = sched.running
    return d


def get_all_jobs() -> list[dict]:
    sched = get_scheduler()
    return [_job_dict(job) for job in sched.get_jobs()]
