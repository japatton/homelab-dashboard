from __future__ import annotations

from fastapi import APIRouter, Body

from config import get_config_manager

router = APIRouter(prefix="/api/settings", tags=["settings"])


@router.get("")
async def get_settings():
    cfg = get_config_manager().get()
    return cfg.masked()


@router.put("/scan-intervals")
async def update_scan_intervals(
    nmap_interval_minutes: int = Body(None),
    unifi_poll_interval_seconds: int = Body(None),
    openvas_interval_hours: int = Body(None),
):
    mgr = get_config_manager()
    cfg = mgr.get()

    if nmap_interval_minutes is not None:
        cfg.scheduler.nmap_interval_minutes = nmap_interval_minutes
    if unifi_poll_interval_seconds is not None:
        cfg.scheduler.unifi_poll_interval_seconds = unifi_poll_interval_seconds
    if openvas_interval_hours is not None:
        cfg.scheduler.openvas_interval_hours = openvas_interval_hours

    mgr.save(cfg)
    return cfg.scheduler.model_dump()


@router.put("/proxy")
async def update_proxy_config(
    mode: str = Body(None),
    external_host: str = Body(None),
    cert_type: str = Body(None),
    letsencrypt_email: str = Body(None),
):
    mgr = get_config_manager()
    cfg = mgr.get()

    if mode is not None:
        cfg.proxy.mode = mode  # type: ignore[assignment]
    if external_host is not None:
        cfg.proxy.external_host = external_host
    if cert_type is not None:
        cfg.proxy.cert_type = cert_type  # type: ignore[assignment]
    if letsencrypt_email is not None:
        cfg.proxy.letsencrypt_email = letsencrypt_email

    mgr.save(cfg)
    return cfg.proxy.model_dump()
