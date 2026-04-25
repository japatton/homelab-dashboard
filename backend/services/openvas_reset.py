from __future__ import annotations

"""
Recreate the `homelab-openvas` container with a new admin password.

Why this lives in the backend instead of being a user-run shell script:

    The `immauss/openvas` image only reads the `PASSWORD` env var on the
    very first container start, when the named volume is empty. Once the
    volume is populated, the env var is ignored forever. Changing the
    password therefore means: stop + remove the container, wipe its volume,
    and recreate with the new env. That's awkward to do by hand — the user
    has to track the project's volume name, know which compose service it
    belongs to, and remember the 5–10 min NVT warmup — so we lift it into
    a single Settings button.

The flow emits socket.io progress events (`openvas:reset`) at each step
so the modal can render a stage-labelled progress bar instead of hanging
for ten minutes:

    stopping   →  5%
    wiping     → 25%
    starting   → 45%
    warmup     → 50–95%   (pulled forward during authenticate-polling)
    ready      → 100%
    error      → terminal

Every call writes one audit row at the top and one at the bottom. We
also save the new password into our own config ONLY after gvmd has
authenticated with it — failure leaves the stored password untouched so
the rest of the app keeps using whatever was working before.

Security note: this module talks to dockerd via the host's docker socket.
It must never accept a container name from user input — we always operate
on a fixed name (`OPENVAS_CONTAINER_NAME`) so a compromised Settings form
can't redirect the wipe at an unrelated container.
"""

import asyncio
import logging
from typing import Optional

from services.audit_service import write_audit
from services.notification_service import get_notification_service

log = logging.getLogger(__name__)

# Pinned container and volume names. These match docker-compose.yml's
# `container_name: homelab-openvas` and `volumes: openvas-data` under the
# compose project name `homelab-dashboard` — hence the actual volume name
# on dockerd is `homelab-dashboard_openvas-data`. If you rename the
# service or the project, update these constants.
OPENVAS_CONTAINER_NAME = "homelab-openvas"
OPENVAS_VOLUME_NAMES = (
    "homelab-dashboard_openvas-data",   # new pinned project name
    "passwordmanager_openvas-data",     # fallback for pre-pin deployments
)

# How long to wait for gvmd to come up and accept the new password.
# The `immauss/openvas` first-boot sequence is NVT sync + SCAP CVE ingest
# + VT rebuild; on an SSD-backed homelab box the happy path is ~10 min,
# but on a slow disk or when the upstream feed has a large delta it can
# run 35–45 min. 15 min is too tight and leaves the operator stranded
# with a gvmd that knows the new password but a config.yml that doesn't
# (we only persist after auth succeeds — see step 6 of reset flow).
# 60 min covers the worst case we've observed; if gvmd still isn't up
# by then something else is genuinely wrong.
WARMUP_TIMEOUT_SECONDS = 60 * 60
WARMUP_POLL_SECONDS = 15


class ResetError(RuntimeError):
    """Raised when the reset flow cannot continue. Message is user-visible."""


async def reset_openvas_password(new_password: str, username: str = "admin") -> None:
    """Full reset flow. Runs in a background task; use the socket.io
    `openvas:reset` channel for progress and the audit log for history.
    """
    ns = get_notification_service()

    async def emit(stage: str, percent: int, message: str, error: Optional[str] = None) -> None:
        log.info("openvas_reset: %s (%d%%) %s", stage, percent, message)
        await ns.emit_openvas_reset(stage, percent, message, error)

    await write_audit(
        "reset_openvas_start", "user",
        {"container": OPENVAS_CONTAINER_NAME, "username": username},
    )

    try:
        # Run the blocking docker SDK calls in a thread — the `docker`
        # library is synchronous. Keeping them off the event loop means
        # socket.io can still flush progress events in parallel.
        import docker  # lazy — only imported when the user actually resets
        try:
            client = docker.from_env()
            client.ping()
        except Exception as e:
            raise ResetError(
                f"cannot reach dockerd at /var/run/docker.sock: {e}. "
                f"Confirm the backend container has the socket mounted and "
                f"is a member of the docker group (DOCKER_GID in .env)."
            ) from e

        # ── 1. Capture current container config so we can recreate it ──
        await emit("stopping", 5, f"locating {OPENVAS_CONTAINER_NAME}")
        container = await asyncio.to_thread(_get_container, client, OPENVAS_CONTAINER_NAME)
        if container is None:
            raise ResetError(
                f"container {OPENVAS_CONTAINER_NAME!r} not found. "
                f"Make sure the openvas profile is up: "
                f"`docker compose --profile openvas up -d openvas`."
            )
        config = _snapshot_config(container)

        # ── 2. Stop + remove it ──
        await emit("stopping", 15, "stopping container (up to 30s)")
        await asyncio.to_thread(_stop_and_remove, container)

        # ── 3. Wipe the named volume ──
        await emit("wiping", 30, "removing openvas-data volume")
        removed = await asyncio.to_thread(_remove_first_matching_volume, client, OPENVAS_VOLUME_NAMES)
        if removed:
            await emit("wiping", 35, f"removed volume {removed}")
        else:
            # Not fatal — if compose created the volume differently we
            # can still recreate. We just won't guarantee first-boot state.
            await emit("wiping", 35, "no named volume found; continuing")

        # ── 4. Recreate with updated PASSWORD env ──
        await emit("starting", 45, "recreating container with new password")
        new_container = await asyncio.to_thread(
            _recreate_with_password, client, config, username, new_password
        )
        await emit("starting", 50,
                   f"container {new_container.name} started — waiting for gvmd")

        # ── 5. Poll authenticate() until gvmd accepts the new password ──
        host = _infer_openvas_host(config)
        port = _infer_openvas_port(config)
        await _wait_for_gvmd_auth(host, port, username, new_password, emit)

        # ── 6. Persist the new creds now that we know they work ──
        from config import get_config_manager
        from pydantic import SecretStr
        mgr = get_config_manager()
        cfg = mgr.get()
        cfg.openvas.user = username
        cfg.openvas.password = SecretStr(new_password)
        mgr.save(cfg)

        await emit("ready", 100, f"authenticated as {username}")
        await write_audit(
            "reset_openvas_success", "user",
            {"container": OPENVAS_CONTAINER_NAME, "username": username},
        )

    except ResetError as e:
        await emit("error", 0, str(e), error=str(e))
        await write_audit(
            "reset_openvas_failed", "user",
            {"container": OPENVAS_CONTAINER_NAME, "reason": str(e)},
        )
    except Exception as e:
        # Never leak a stack trace to the UI — but log it here so we can debug.
        log.exception("reset_openvas_password crashed")
        msg = f"{type(e).__name__}: {e}"
        await emit("error", 0, msg, error=msg)
        await write_audit(
            "reset_openvas_failed", "user",
            {"container": OPENVAS_CONTAINER_NAME, "reason": msg},
        )


# ── docker SDK helpers (all sync — called via asyncio.to_thread) ──────────────


def _get_container(client, name: str):
    import docker.errors
    try:
        return client.containers.get(name)
    except docker.errors.NotFound:
        return None


def _snapshot_config(container) -> dict:
    """Pull out everything we need to recreate the container.

    We lean on the existing inspect output rather than trying to round-trip
    through compose: this makes the flow work even when compose state has
    drifted from the on-disk file, and it doesn't require the compose file
    to be reachable from inside the backend container.
    """
    attrs = container.attrs
    c = attrs.get("Config", {})
    hc = attrs.get("HostConfig", {})
    ns_settings = attrs.get("NetworkSettings", {}).get("Networks", {}) or {}
    # Capture per-network DNS aliases so we can re-apply them after
    # recreation. Compose assigns service-name aliases (e.g. `openvas`) at
    # startup; without re-applying them the service-name stops resolving
    # after our reset, and anything hardcoded to `openvas` breaks until
    # compose recreates the container itself.
    network_aliases: dict[str, list[str]] = {}
    for net_name, cfg in ns_settings.items():
        aliases = list(cfg.get("Aliases") or [])
        # Docker auto-adds the short container id as an alias — keeping it
        # is harmless but noisy; drop it so the re-attach only adds the
        # meaningful aliases (service name + container_name).
        aliases = [a for a in aliases if a and not _looks_like_short_id(a, container.id)]
        if aliases:
            network_aliases[net_name] = aliases
    return {
        # Fallback must match docker-compose.yml's openvas.image pin so the
        # recreated container uses the same version we're testing against.
        "image": c.get("Image") or "immauss/openvas:26.02.28.01",
        "name": container.name,
        "env": list(c.get("Env") or []),
        "labels": dict(c.get("Labels") or {}),
        "restart_policy": hc.get("RestartPolicy") or {"Name": "unless-stopped"},
        "port_bindings": hc.get("PortBindings") or {},
        "binds": list(hc.get("Binds") or []),
        "mounts": list(hc.get("Mounts") or []),
        "networks": list(ns_settings.keys()),
        "network_aliases": network_aliases,
        "exposed_ports": dict(c.get("ExposedPorts") or {}),
        "healthcheck": c.get("Healthcheck"),
    }


def _looks_like_short_id(alias: str, container_id: str) -> bool:
    """Docker auto-registers the 12-char short id as a network alias.
    We drop it to avoid cluttering the re-attach call. Match by prefix
    since the alias IS the short id and `container.id` is the full 64-char."""
    return len(alias) == 12 and container_id.startswith(alias)


def _stop_and_remove(container) -> None:
    try:
        container.stop(timeout=30)
    except Exception as e:
        log.warning("stop failed (continuing to remove): %s", e)
    try:
        container.remove(force=True)
    except Exception as e:
        raise ResetError(f"could not remove container: {e}") from e


def _remove_first_matching_volume(client, candidate_names: tuple[str, ...]) -> Optional[str]:
    import docker.errors
    for name in candidate_names:
        try:
            vol = client.volumes.get(name)
        except docker.errors.NotFound:
            continue
        try:
            vol.remove(force=True)
            return name
        except Exception as e:
            raise ResetError(f"could not remove volume {name}: {e}") from e
    return None


def _recreate_with_password(client, config: dict, username: str, password: str):
    """Recreate the openvas container from the captured snapshot, replacing
    the USERNAME / PASSWORD env vars (and injecting them if they were
    missing). Everything else — ports, bindings, labels, network, restart
    policy — is preserved bit-for-bit."""
    env_no_creds = [
        e for e in config["env"]
        if not (e.startswith("USERNAME=") or e.startswith("PASSWORD="))
    ]
    env_no_creds.append(f"USERNAME={username}")
    env_no_creds.append(f"PASSWORD={password}")

    # Translate the inspect-style port bindings back into docker SDK form.
    # PortBindings format: {"9392/tcp": [{"HostIp": "", "HostPort": "9392"}]}
    # docker SDK expects:   ports={"9392/tcp": 9392} or list of tuples.
    ports = {}
    for key, bindings in (config.get("port_bindings") or {}).items():
        if not bindings:
            continue
        b = bindings[0]
        ports[key] = b.get("HostPort") or None

    # We defer network attachment so we can specify aliases. `containers.run`
    # only accepts a single network as a string with no alias control, which
    # would drop the service-name alias (e.g. `openvas`) that compose set up.
    # Instead: create the container with bridge, disconnect it immediately,
    # then connect each captured network with its saved aliases.
    networks = config.get("networks") or []
    network_aliases = config.get("network_aliases") or {}

    run_kwargs = dict(
        image=config["image"],
        name=config["name"],
        detach=True,
        environment=env_no_creds,
        labels=config.get("labels") or {},
        restart_policy=config.get("restart_policy") or {"Name": "unless-stopped"},
        ports=ports,
        volumes=config.get("binds") or None,
    )
    # Preserve healthcheck if present; SDK accepts the inspect-style dict.
    if config.get("healthcheck"):
        run_kwargs["healthcheck"] = config["healthcheck"]

    if networks:
        # Create in stopped state so we can rewire networking before start.
        container = client.containers.create(**run_kwargs)
        # Docker always attaches new containers to `bridge` by default — we
        # need to drop that so we don't end up dual-homed with a rogue IP.
        try:
            client.networks.get("bridge").disconnect(container, force=True)
        except Exception:
            # Not fatal — bridge might have been skipped if network_mode was set.
            pass
        for net in networks:
            aliases = network_aliases.get(net) or []
            try:
                client.networks.get(net).connect(container, aliases=aliases or None)
            except Exception as e:
                log.warning("could not attach network %s (aliases=%s): %s", net, aliases, e)
        container.start()
    else:
        # No captured networks — fall back to the simple run path. Shouldn't
        # happen in practice (compose always puts the container on homelab-net)
        # but we don't want to fail the reset if inspect returned weird data.
        container = client.containers.run(**run_kwargs)
    return container


def _infer_openvas_host(config: dict) -> str:
    """Return a hostname the backend can use to reach gvmd.

    Inside the compose network the service is addressable as `openvas`
    (that's the service name from docker-compose.yml). If the container
    isn't on a shared network we fall back to the container name, which
    dockerd resolves over the bridge.
    """
    if "homelab-net" in (config.get("networks") or []):
        return "openvas"
    return OPENVAS_CONTAINER_NAME


def _infer_openvas_port(config: dict) -> int:
    """Pick gvmd's GMP port from the container config. Defaults to 9390 —
    the value we pass into `OpenVASIntegration` everywhere else."""
    # Exposed ports look like {"9390/tcp": {}} or {"9392/tcp": {}}.
    exposed = config.get("exposed_ports") or {}
    if "9390/tcp" in exposed:
        return 9390
    return 9390


async def _wait_for_gvmd_auth(host: str, port: int, username: str, password: str, emit) -> None:
    """Poll GMP authenticate() until it succeeds or we time out.

    The timeout is intentionally long (15 min): on a fresh NVT sync the
    scanner is not reachable at all for the first few minutes, then it
    starts accepting TCP but rejects GMP commands with "Only command
    GET_VERSION is allowed before AUTHENTICATE" for another minute or two.
    We translate each of those into the same "warmup" stage so the user
    sees continuous motion.
    """
    from integrations.openvas import OpenVASIntegration

    deadline = asyncio.get_event_loop().time() + WARMUP_TIMEOUT_SECONDS
    last_reason = ""
    # Progress between 50 and 95 while we wait — don't let the bar sit still.
    start_pct = 50
    end_pct = 95
    tick = 0

    while True:
        tick += 1
        remaining = deadline - asyncio.get_event_loop().time()
        if remaining <= 0:
            raise ResetError(
                f"gvmd did not authenticate within {WARMUP_TIMEOUT_SECONDS // 60} "
                f"minutes — last response: {last_reason or 'unknown'}"
            )

        integ = OpenVASIntegration(host=host, port=port, username=username, password=password)
        res = await integ.test_connection()
        if res.ok:
            return
        last_reason = res.message

        # Glide the percent forward toward end_pct using a fraction of the
        # total wait. Never goes backwards.
        fraction = 1 - (remaining / WARMUP_TIMEOUT_SECONDS)
        pct = min(end_pct, int(start_pct + (end_pct - start_pct) * fraction))
        mins = int(remaining // 60)
        secs = int(remaining % 60)
        await emit(
            "warmup", pct,
            f"gvmd warming up ({last_reason}) — up to {mins:d}:{secs:02d} remaining",
        )
        await asyncio.sleep(WARMUP_POLL_SECONDS)
