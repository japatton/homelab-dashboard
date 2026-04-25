from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

import socketio
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config import get_config_manager
from database import init_db
from middleware.auth import DashboardTokenMiddleware, get_dashboard_token
from services.notification_service import get_notification_service

# Configure root logger so module-level log.info() calls (scheduler.jobs,
# integrations.openvas, services.vuln_service, etc.) reach Docker logs.
# Without this, only uvicorn's own logger is wired up and every other
# log.info is silently dropped.
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

# Socket.io server — shared via notification_service
sio = socketio.AsyncServer(
    async_mode="asgi",
    cors_allowed_origins="*",
    logger=False,
    engineio_logger=False,
)
get_notification_service().init(sio)

_MOCK = os.getenv("BACKEND_MOCK", "false").lower() == "true"


async def _check_docker_socket() -> None:
    """Preflight for the OpenVAS rotate path.

    The reset/rotate flow in services.openvas_reset talks to the host's
    dockerd through /var/run/docker.sock to wipe the openvas volume and
    recreate the container. That requires both that the socket is mounted
    AND that our non-root user has a supplementary group matching the
    socket's GID (see DOCKER_GID in .env).

    When this is misconfigured the user only discovers it by clicking
    Rotate and getting an opaque traceback. Do it at startup instead:
    log a loud, actionable warning if the mount is present but dockerd
    is unreachable. Silent when the socket isn't mounted at all — that's
    the "openvas profile not enabled" case and we shouldn't nag.
    """
    import logging
    import os
    import asyncio

    log = logging.getLogger("docker_preflight")

    sock_path = "/var/run/docker.sock"
    if not os.path.exists(sock_path):
        # Mount not present → openvas profile likely not enabled. Stay silent.
        return

    try:
        import docker  # lazy; same pattern as openvas_reset

        def _ping():
            client = docker.from_env()
            try:
                client.ping()
            finally:
                # Release the connection pool; we only wanted a health check.
                # Close failures aren't actionable (the probe already finished)
                # but they shouldn't disappear — debug-log so they're traceable.
                try:
                    client.close()
                except Exception as close_err:
                    log.debug("docker client close ignored: %s", close_err)

        await asyncio.to_thread(_ping)
        log.info("docker.sock preflight: OK (OpenVAS rotate path available)")
    except Exception as e:
        # The docker SDK wraps low-level errors in DockerException. We
        # discriminate on the stringified message rather than the type
        # so that "Permission denied" (our most common failure mode) can
        # be called out with the specific fix, while other dockerd
        # failures (daemon down, API mismatch) fall through to a generic
        # warning.
        msg = str(e).lower()
        if "permission denied" in msg:
            try:
                st = os.stat(sock_path)
                sock_gid = st.st_gid
            except Exception:
                sock_gid = "unknown"
            log.warning(
                "docker.sock preflight FAILED: permission denied. "
                "The socket is mounted but our user cannot access it. "
                "Fix: set DOCKER_GID=%s in .env and run "
                "`docker compose up -d --force-recreate backend`. "
                "Until then the OpenVAS Rotate button will error with the "
                "same message. Full error: %s",
                sock_gid,
                e,
            )
        else:
            # Catch-all: dockerd down, API version mismatch, etc. Warn
            # but don't block startup — the rest of the app is fine.
            log.warning(
                "docker.sock preflight FAILED: %s. OpenVAS Rotate will not "
                "work until resolved. Non-fatal — continuing startup.",
                e,
            )


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── Startup ────────────────────────────────────────────────────────────
    await init_db()
    mgr = get_config_manager()
    mgr.load()
    cfg = mgr.get()

    if _MOCK:
        logging.getLogger(__name__).info(
            "Running in MOCK mode — no real integrations active"
        )
    else:
        # Surface docker.sock misconfiguration in the startup logs rather
        # than making the user discover it via a cryptic Rotate failure.
        await _check_docker_socket()

        # Start periodic scan scheduler
        from scheduler import start_scheduler

        await start_scheduler(
            nmap_interval_minutes=cfg.scheduler.nmap_interval_minutes,
            unifi_interval_seconds=cfg.scheduler.unifi_poll_interval_seconds,
            openvas_interval_hours=cfg.scheduler.openvas_interval_hours,
            analysis_hour_utc=cfg.ollama.daily_schedule_hour_utc,
            analysis_enabled=cfg.ollama.enabled and bool(cfg.ollama.host),
            opnsense_interval_seconds=cfg.opnsense.poll_interval_seconds,
            firewalla_interval_seconds=cfg.firewalla.poll_interval_seconds,
        )

        # Ensure Elasticsearch indices exist (best-effort, non-fatal).
        # Uses the module-level singleton so scan jobs share the same
        # client for the life of the process.
        if cfg.elasticsearch.host:
            try:
                from integrations.elasticsearch_client import get_es_client

                es = get_es_client()
                if es is not None:
                    await es.ensure_indices()
            except Exception as _e:
                import logging as _log

                _log.getLogger(__name__).warning("Elasticsearch init skipped: %s", _e)

    yield

    # ── Shutdown ───────────────────────────────────────────────────────────
    if not _MOCK:
        from scheduler import stop_scheduler
        from integrations.elasticsearch_client import close_es_client

        await stop_scheduler()
        await close_es_client()


app = FastAPI(
    title="Homelab Dashboard API",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS: when DASHBOARD_TOKEN is set, clamp allow_origins to the configured
# frontend host(s) and disable credential sharing — otherwise any page on
# the internet can read the token-authenticated API (Authorization header
# is not gated by CORS but localStorage scraping is). When unset, stay
# permissive so dev workflows (curl, different ports) keep working.
_allowed_origins_env = os.getenv("DASHBOARD_ALLOWED_ORIGINS", "").strip()
if _allowed_origins_env:
    _origins = [o.strip() for o in _allowed_origins_env.split(",") if o.strip()]
else:
    _origins = ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_credentials=_origins != ["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Opt-in bearer-token gate over /api/*. Unset → no-op.
app.add_middleware(DashboardTokenMiddleware, token=get_dashboard_token())

# Routers — imported here (not at top) so the middleware stack above is fully
# wired before any route module side-effects run. The E402 noqa is deliberate.
from api.network import router as network_router  # noqa: E402
from api.devices import router as devices_router  # noqa: E402
from api.settings import router as settings_router  # noqa: E402
from api.setup import router as setup_router  # noqa: E402
from api.scans import router as scans_router  # noqa: E402
from api.claude_integration import router as claude_router  # noqa: E402
from api.scheduler import router as scheduler_router  # noqa: E402
from api.vulns import router as vulns_router  # noqa: E402
from api.analysis import router as analysis_router  # noqa: E402
from api.alarms import router as alarms_router  # noqa: E402

app.include_router(network_router)
app.include_router(devices_router)
app.include_router(settings_router)
app.include_router(setup_router)
app.include_router(scans_router)
app.include_router(claude_router)
app.include_router(scheduler_router)
app.include_router(vulns_router)
app.include_router(analysis_router)
app.include_router(alarms_router)


@app.get("/health")
async def health():
    return {"status": "ok", "mock": _MOCK}


# Track which sids have already received the initial staged-change notification
_notified_sids: set[str] = set()


@sio.event
async def connect(sid, environ):
    if _MOCK:
        from mock.topology_fixtures import MOCK_TOPOLOGY

        await sio.emit("topology:updated", MOCK_TOPOLOGY.model_dump(), to=sid)
        if sid not in _notified_sids:
            from api.claude_integration import _staged

            pending = [v for v in _staged.values() if v["status"] == "pending"]
            if pending:
                await sio.emit("claude:staged", pending[0], to=sid)
                _notified_sids.add(sid)
    else:
        # Send current real topology on connect
        try:
            from services.device_service import get_all_devices
            from services.topology_service import build_topology_graph

            devices = await get_all_devices()
            if devices:
                topology = await build_topology_graph(devices)
                ns = get_notification_service()
                await ns.emit_topology_updated(topology, room=sid)
        except Exception:
            pass


@sio.event
async def disconnect(sid):
    _notified_sids.discard(sid)


# Mount Socket.io alongside FastAPI
socket_app = socketio.ASGIApp(sio, other_asgi_app=app, socketio_path="/socket.io")
