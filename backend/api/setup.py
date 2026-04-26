from __future__ import annotations

import logging
import os as _os

from fastapi import APIRouter, Body, HTTPException
from pydantic import SecretStr

from config import get_config_manager
from services.url_validation import (
    TargetValidationError,
    parse_host,
    validate_outbound_target,
)

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/setup", tags=["setup"])

_MOCK = _os.getenv("BACKEND_MOCK", "false").lower() == "true"


def _gate(host_or_url: str) -> str:
    """F-002: Apply outbound-target SSRF validation; on failure raise
    the FastAPI HTTPException directly so each endpoint can use a
    one-liner. Returns the parsed hostname for callers that want it.
    """
    try:
        return validate_outbound_target(host_or_url)
    except TargetValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))


def _safe_400(action: str, e: Exception) -> HTTPException:
    """F-027: Don't echo raw exception text back to the API caller —
    response bodies and banner fragments can leak through stringified
    httpx errors. Log the detail server-side and return a generic 400.
    """
    log.warning("%s failed: %s", action, e)
    return HTTPException(
        status_code=400,
        detail=f"{action} failed — see server logs for detail",
    )


@router.get("/status")
async def get_setup_status():
    if _MOCK:
        return {"setup_complete": True}
    mgr = get_config_manager()
    return {"setup_complete": mgr.is_setup_complete()}


@router.post("/test-elasticsearch")
async def test_elasticsearch(
    host: str = Body(...),
    port: int = Body(9200),
    user: str = Body(""),
    password: str = Body(""),
):
    if not host:
        raise HTTPException(status_code=400, detail="Host is required")
    parsed = _gate(host)  # F-002: SSRF allowlist
    try:
        import httpx

        auth = (user, password) if user else None
        async with httpx.AsyncClient(timeout=5.0) as c:
            r = await c.get(f"http://{parsed}:{port}", auth=auth)  # type: ignore[arg-type]
            if r.status_code < 500:
                info = r.json()
                # Extract specific known fields rather than echoing the
                # full body — defence-in-depth even if the validator
                # somehow let through a sensitive target (it shouldn't).
                return {
                    "ok": True,
                    "version": info.get("version", {}).get("number", "unknown"),
                }
        raise HTTPException(
            status_code=400, detail=f"Unexpected status {r.status_code}"
        )
    except HTTPException:
        raise
    except Exception as e:
        raise _safe_400("test-elasticsearch", e)


@router.post("/test-unifi")
async def test_unifi(
    url: str = Body(...),
    user: str = Body(...),
    password: str = Body(...),
):
    """Auth against the UniFi controller and return the list of sites the
    user can see, so the wizard can show a dropdown instead of free-text.
    """
    _gate(url)  # F-002: SSRF allowlist
    try:
        import httpx

        async with httpx.AsyncClient(
            verify=False, follow_redirects=True, timeout=8.0
        ) as c:
            controller_type: str | None = None
            # Try UDM / UDM Pro first
            r = await c.post(
                f"{url.rstrip('/')}/api/auth/login",
                json={"username": user, "password": password},
            )
            if r.status_code in (200, 201):
                controller_type = "udm"
                site_url = f"{url.rstrip('/')}/proxy/network/api/self/sites"
            else:
                # Fall back to classic controller
                r2 = await c.post(
                    f"{url.rstrip('/')}/api/login",
                    json={"username": user, "password": password},
                )
                if r2.status_code in (200, 201):
                    controller_type = "classic"
                    site_url = f"{url.rstrip('/')}/api/self/sites"
                else:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Authentication failed ({r.status_code})",
                    )

            # Fetch site list — non-fatal if it fails (we still return ok)
            sites: list[dict] = []
            try:
                sr = await c.get(site_url)
                if sr.status_code == 200:
                    sites = [
                        {
                            "id": s.get("name"),
                            "display_name": s.get("desc") or s.get("name"),
                            "role": s.get("role"),
                        }
                        for s in sr.json().get("data", [])
                        if s.get("name")
                    ]
            except Exception as e:
                log.info("UniFi /self/sites fetch failed: %s", e)

            return {"ok": True, "type": controller_type, "sites": sites}
    except HTTPException:
        raise
    except Exception as e:
        raise _safe_400("test-unifi", e)


@router.post("/test-opnsense")
async def test_opnsense(
    url: str = Body(...),
    api_key: str = Body(...),
    api_secret: str = Body(""),
    verify_ssl: bool = Body(False),
    ids_enabled: bool = Body(False),
):
    """Probe OPNsense: HTTP Basic auth + firmware/status + system_info.

    `api_secret` defaults to "" so the UI can re-test saved creds by
    leaving the field blank (placeholder "(unchanged)"). When blank we
    pull the stored secret out of config, mirroring test-openvas.
    """
    from integrations.opnsense import OPNsenseIntegration

    secret = api_secret
    if not secret:
        cfg = get_config_manager().get()
        secret = cfg.opnsense.api_secret.get_secret_value()
        if not secret:
            raise HTTPException(
                status_code=400,
                detail="no API secret supplied and none stored — enter a secret first",
            )

    _gate(url)  # F-002: SSRF allowlist

    integ = OPNsenseIntegration(
        url=url,
        api_key=api_key,
        api_secret=secret,
        verify_ssl=verify_ssl,
        ids_enabled=ids_enabled,
    )
    res = await integ.test_connection()
    if not res.ok:
        # res.message is integration-source-faithful (parsed by the
        # integration's own _safe_error sanitiser), so it's safe to
        # bubble — the integration class is the one who knows whether
        # gvmd / OPNsense / etc. error text contains banner fragments.
        raise HTTPException(status_code=400, detail=res.message)
    return {
        "ok": True,
        "message": res.message,
        "hostname": res.detail.get("hostname", ""),
        "version": res.detail.get("version", ""),
        "product": res.detail.get("product", "OPNsense"),
    }


@router.post("/test-firewalla")
async def test_firewalla(
    mode: str = Body("msp"),
    msp_domain: str = Body(""),
    msp_token: str = Body(""),
    local_url: str = Body(""),
    local_token: str = Body(""),
    verify_ssl: bool = Body(False),
):
    """Probe Firewalla in either MSP or local mode.

    Blank tokens fall back to stored values so the UI can re-verify
    saved creds without forcing the user to retype.
    """
    from integrations.firewalla import FirewallaIntegration

    cfg = get_config_manager().get()
    m = (mode or "msp").lower()
    if m not in ("msp", "local"):
        raise HTTPException(status_code=400, detail=f"unknown mode {mode!r}")

    if m == "msp":
        if not msp_domain:
            raise HTTPException(status_code=400, detail="MSP domain required")
        token = msp_token or cfg.firewalla.msp_token.get_secret_value()
        if not token:
            raise HTTPException(
                status_code=400,
                detail="no MSP token supplied and none stored — enter a token first",
            )
        _gate(msp_domain)  # F-002: SSRF allowlist
        integ = FirewallaIntegration(
            mode="msp",
            msp_domain=msp_domain,
            msp_token=token,
            verify_ssl=verify_ssl,
        )
    else:
        if not local_url:
            raise HTTPException(status_code=400, detail="Local box URL required")
        _gate(local_url)  # F-002: SSRF allowlist
        token = local_token or cfg.firewalla.local_token.get_secret_value()
        integ = FirewallaIntegration(
            mode="local",
            local_url=local_url,
            local_token=token,
            verify_ssl=verify_ssl,
        )

    res = await integ.test_connection()
    if not res.ok:
        raise HTTPException(status_code=400, detail=res.message)
    return {
        "ok": True,
        "message": res.message,
        "mode": m,
        "box_count": res.detail.get("box_count", 0),
        "boxes": res.detail.get("boxes", []),
    }


@router.post("/test-openvas")
async def test_openvas(
    host: str = Body(...),
    port: int = Body(9390),
    user: str = Body("admin"),
    password: str = Body(""),
):
    """Full gvmd auth check: TCP reach + GMP authenticate + version read.

    `password` defaults to "" so the UI can re-test existing creds by leaving
    the field blank (placeholder is "(unchanged)"). When blank, we pull the
    stored password out of config so the test uses the same creds the
    scheduled scan will use.
    """
    from integrations.openvas import OpenVASIntegration

    pw = password
    if not pw:
        # Fall back to the saved password so "Test" after a no-op save
        # actually validates what's persisted, not an empty string.
        cfg = get_config_manager().get()
        pw = cfg.openvas.password.get_secret_value()
        if not pw:
            raise HTTPException(
                status_code=400,
                detail="no password supplied and none stored — enter a password first",
            )

    _gate(host)  # F-002: SSRF allowlist

    integ = OpenVASIntegration(host=host, port=port, username=user, password=pw)
    res = await integ.test_connection()
    if not res.ok:
        # ConnectionResult.offline surfaces gvmd's own error text — bubble that
        # verbatim so the user sees "Authentication failed" vs "scanner
        # unreachable" vs whatever gvmd is actually saying.
        raise HTTPException(status_code=400, detail=res.message)
    return {"ok": True, "message": res.message, "user": user}


@router.post("/reset-openvas")
async def reset_openvas(
    new_password: str = Body(..., embed=True),
    username: str = Body("admin", embed=True),
):
    """Destructive: recreate the openvas container with a new admin password.

    Returns immediately and streams progress via the `openvas:reset`
    socket.io channel. The actual stop/wipe/recreate/warmup flow runs as a
    background task in `services.openvas_reset.reset_openvas_password`.

    Why background: the warmup alone can take 10+ minutes, which would
    definitely blow HTTP's idle timeout on any reverse proxy we might sit
    behind. The Settings modal already has a socket listener for progress.
    """
    from services.openvas_reset import reset_openvas_password
    from services.background_tasks import spawn

    pw = (new_password or "").strip()
    if len(pw) < 8:
        raise HTTPException(
            status_code=400,
            detail="new password must be at least 8 characters",
        )
    user = (username or "admin").strip() or "admin"

    # Fire-and-forget. Any failure is surfaced over socket.io + audit log.
    spawn(reset_openvas_password(pw, user), name="openvas:reset")
    return {"ok": True, "message": "reset started — watch the modal for progress"}


@router.post("/rotate-openvas")
async def rotate_openvas(username: str = Body("admin", embed=True)):
    """User-facing "Rotate password" button.

    Generates a fresh random password server-side (the user never sees
    or types it — the platform is the only thing that talks to OpenVAS),
    runs the same reset flow as /reset-openvas, and emits progress over
    the `openvas:reset` socket.io channel.

    This is the escape hatch paired with the auto-generate-on-first-boot
    path: if the stored password ever drifts out of sync with what
    gvmd knows (e.g. manual volume surgery), clicking Rotate brings
    everything back into lockstep in ~10 minutes.
    """
    from services.background_tasks import spawn
    from services.openvas_autopassword import rotate_openvas_password

    user = (username or "admin").strip() or "admin"
    spawn(rotate_openvas_password(), name="openvas:rotate")
    return {
        "ok": True,
        "username": user,
        "message": "rotation started — watch the modal for progress",
    }


@router.post("/test-ollama")
async def test_ollama(
    host: str = Body(...),
    port: int = Body(11434),
    model: str = Body("gemma3:4b"),
    api_key: str = Body(""),
):
    """Probe Ollama's OpenAI-compatible /v1/models endpoint and return
    available model IDs. The frontend uses `model_present` to show whether
    the configured model name actually exists on the server."""
    from integrations.ollama import OllamaIntegration

    _gate(host)  # F-002: SSRF allowlist (host may be a bare hostname or full URL)

    integ = OllamaIntegration(host=host, port=port, model=model, api_key=api_key)
    res = await integ.test_connection()
    if not res.ok:
        raise HTTPException(status_code=400, detail=res.message)
    return {
        "ok": True,
        "message": res.message,
        "models": res.detail.get("models", []),
        "model_present": res.detail.get("model_present", False),
    }


@router.post("/complete")
async def complete_setup(payload: dict = Body(...)):
    from services.audit_service import write_audit

    try:
        mgr = get_config_manager()
        cfg = mgr.get()

        if "proxy" in payload:
            p = payload["proxy"]
            cfg.proxy.mode = p.get("mode", cfg.proxy.mode)  # type: ignore[assignment]
            cfg.proxy.external_host = p.get("external_host", cfg.proxy.external_host)
            cfg.proxy.cert_type = p.get("cert_type", cfg.proxy.cert_type)  # type: ignore[assignment]
            cfg.proxy.letsencrypt_email = p.get(
                "letsencrypt_email", cfg.proxy.letsencrypt_email
            )

        if "elasticsearch" in payload:
            e = payload["elasticsearch"]
            cfg.elasticsearch.host = e.get("host", cfg.elasticsearch.host)
            cfg.elasticsearch.port = e.get("port", cfg.elasticsearch.port)
            cfg.elasticsearch.user = e.get("user", cfg.elasticsearch.user)
            if "password" in e and e["password"]:
                cfg.elasticsearch.password = SecretStr(e["password"])

        if "unifi" in payload:
            u = payload["unifi"]
            cfg.unifi.url = u.get("url", cfg.unifi.url)
            cfg.unifi.user = u.get("user", cfg.unifi.user)
            cfg.unifi.site = u.get("site", cfg.unifi.site)
            if "password" in u and u["password"]:
                cfg.unifi.password = SecretStr(u["password"])

        if "opnsense" in payload:
            o = payload["opnsense"]
            if "enabled" in o:
                cfg.opnsense.enabled = bool(o["enabled"])
            if "url" in o:
                cfg.opnsense.url = o["url"]
            if "api_key" in o:
                cfg.opnsense.api_key = o["api_key"]
            if "api_secret" in o and o["api_secret"]:
                cfg.opnsense.api_secret = SecretStr(o["api_secret"])
            if "verify_ssl" in o:
                cfg.opnsense.verify_ssl = bool(o["verify_ssl"])
            if "ids_enabled" in o:
                cfg.opnsense.ids_enabled = bool(o["ids_enabled"])
            if "poll_interval_seconds" in o:
                try:
                    cfg.opnsense.poll_interval_seconds = int(o["poll_interval_seconds"])
                except (TypeError, ValueError):
                    pass

        if "firewalla" in payload:
            f = payload["firewalla"]
            if "enabled" in f:
                cfg.firewalla.enabled = bool(f["enabled"])
            if "mode" in f and f["mode"] in ("msp", "local"):
                cfg.firewalla.mode = f["mode"]  # type: ignore[assignment]
            if "msp_domain" in f:
                cfg.firewalla.msp_domain = f["msp_domain"]
            if "msp_token" in f and f["msp_token"]:
                cfg.firewalla.msp_token = SecretStr(f["msp_token"])
            if "local_url" in f:
                cfg.firewalla.local_url = f["local_url"]
            if "local_token" in f and f["local_token"]:
                cfg.firewalla.local_token = SecretStr(f["local_token"])
            if "verify_ssl" in f:
                cfg.firewalla.verify_ssl = bool(f["verify_ssl"])
            if "alarms_enabled" in f:
                cfg.firewalla.alarms_enabled = bool(f["alarms_enabled"])
            if "poll_interval_seconds" in f:
                try:
                    cfg.firewalla.poll_interval_seconds = int(
                        f["poll_interval_seconds"]
                    )
                except (TypeError, ValueError):
                    pass

        if "openvas" in payload:
            o = payload["openvas"]
            # Host + port + user persist; password is NOT accepted from
            # the wizard any more — the platform auto-manages it. See
            # services/openvas_autopassword.py and the post-save hook
            # below that seeds one on first setup.
            cfg.openvas.host = o.get("host", cfg.openvas.host)
            cfg.openvas.port = int(o.get("port", cfg.openvas.port))
            cfg.openvas.user = o.get("user", cfg.openvas.user)
            # Accept password ONLY if explicitly provided (legacy clients
            # or someone rolling back the frontend). Normal flow skips it.
            if "password" in o and o["password"]:
                cfg.openvas.password = SecretStr(o["password"])

        if "claude" in payload:
            cfg.claude.enabled = payload["claude"].get("enabled", cfg.claude.enabled)

        if "ollama" in payload:
            o = payload["ollama"]
            if "enabled" in o:
                cfg.ollama.enabled = bool(o["enabled"])
            if "host" in o:
                cfg.ollama.host = o["host"]
            if "port" in o:
                cfg.ollama.port = int(o["port"])
            if "model" in o:
                cfg.ollama.model = o["model"]
            if "daily_schedule_hour_utc" in o:
                cfg.ollama.daily_schedule_hour_utc = int(o["daily_schedule_hour_utc"])
            if "api_key" in o and o["api_key"]:
                cfg.ollama.api_key = SecretStr(o["api_key"])

        cfg.setup_complete = True
        mgr.save(cfg)

        # Audit summary: record which sections were touched + their
        # non-secret values. Secrets (passwords / api_key) never hit the log.
        sections: dict = {}
        for key in (
            "proxy",
            "elasticsearch",
            "unifi",
            "opnsense",
            "firewalla",
            "openvas",
            "claude",
            "ollama",
        ):
            if key in payload:
                sections[key] = {
                    k: v
                    for k, v in payload[key].items()
                    # Strip every secret-ish key across all section types.
                    if k
                    not in (
                        "password",
                        "api_key",
                        "api_secret",
                        "msp_token",
                        "local_token",
                    )
                }
        if sections:
            await write_audit(
                "save_settings",
                "user",
                {"sections": list(sections.keys()), "values": sections},
            )

        # If the user touched the OpenVAS section and no password is
        # stored, auto-generate + run the container reset in the
        # background. The Settings modal listens on `openvas:reset` for
        # progress, same channel as the manual rotate flow. We spawn
        # rather than await: NVT warmup is 5-10 min and would blow any
        # reverse-proxy timeout. Safe to no-op if a password is already
        # present.
        if "openvas" in payload and not cfg.openvas.password.get_secret_value():
            from services.background_tasks import spawn
            from services.openvas_autopassword import ensure_openvas_password

            spawn(ensure_openvas_password(), name="openvas:auto-init")

        return {"setup_complete": True}
    except Exception as e:
        log.exception("Setup completion failed")
        raise HTTPException(status_code=500, detail=f"Setup save failed: {e}")
