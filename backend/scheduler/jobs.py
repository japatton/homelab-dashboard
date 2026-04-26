from __future__ import annotations

import asyncio
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone

from database import get_db
from scheduler.state import record_job_run
from services.notification_service import get_notification_service

log = logging.getLogger(__name__)

_MOCK = os.getenv("BACKEND_MOCK", "false").lower() == "true"


def _default_scan_targets() -> list[str]:
    """Derive scan targets from env. Prefer NMAP_TARGETS, then EXTERNAL_HOST /24.

    F-003: NMAP_TARGETS is operator-supplied and reaches Nmap's argv;
    validate it the same way the API path does so a typo or a malicious
    CI env var can't slip a `-iL /etc/...` into the scheduled scan.
    Falls back to the hardcoded RFC1918 default on validation failure
    (loud log line so the operator sees the rejection).
    """
    from integrations.nmap import validate_targets, TargetValidationError

    env_targets = os.getenv("NMAP_TARGETS", "").strip()
    if env_targets:
        candidates = [t.strip() for t in env_targets.split(",") if t.strip()]
        try:
            validate_targets(candidates)
            return candidates
        except TargetValidationError as e:
            log.warning(
                "NMAP_TARGETS env value rejected (%s) — falling back to "
                "EXTERNAL_HOST-derived default. Fix .env if this was intentional.",
                e,
            )

    host = os.getenv("EXTERNAL_HOST", "").strip()
    # If EXTERNAL_HOST is an IPv4 address, derive its /24
    try:
        parts = host.split(".")
        if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            return [f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"]
    except Exception:
        pass

    # Last-resort fallback (RFC1918 common default)
    log.warning(
        "No NMAP_TARGETS or resolvable EXTERNAL_HOST — defaulting to 192.168.1.0/24"
    )
    return ["192.168.1.0/24"]


async def nmap_scan_job(
    targets: list[str] | None = None, profile: str = "standard"
) -> None:
    """Scheduled Nmap scan — discovers/updates all devices and emits topology update."""
    if _MOCK:
        log.debug("nmap_scan_job skipped in MOCK mode")
        return

    from integrations.nmap import NmapIntegration
    from services.device_service import merge_nmap_result, detect_unknown_devices
    from services.topology_service import build_topology_graph

    job_id = str(uuid.uuid4())
    ns = get_notification_service()
    scan_targets = targets or _default_scan_targets()
    log.info("nmap_scan_job: scanning %s", scan_targets)

    try:
        await ns.emit_scan_progress(job_id, "nmap", 10, "Starting Nmap scan")
        nmap = NmapIntegration()
        result = await nmap.scan(scan_targets, profile=profile)

        await ns.emit_scan_progress(
            job_id, "nmap", 60, f"Found {len(result.hosts)} hosts"
        )
        devices = await merge_nmap_result(result)

        await ns.emit_scan_progress(job_id, "nmap", 80, "Building topology")
        topology = await build_topology_graph(devices)

        await ns.emit_topology_updated(topology)
        await ns.emit_scan_complete(job_id, "nmap", len(devices), None)
        await record_job_run("nmap_scan", "success", f"{len(devices)} devices found")

        # Trigger Claude analysis for unknown devices (non-blocking)
        unknown = detect_unknown_devices(devices)
        if unknown:
            from services.claude_analysis import run_analysis_for_unknown_devices
            from services.background_tasks import spawn

            spawn(
                run_analysis_for_unknown_devices(devices),
                name="claude_analysis",
            )

        # Persist scan summary to DB
        now = datetime.now(timezone.utc).isoformat()
        async with get_db() as db:
            await db.execute(
                """INSERT INTO scan_results (id, scan_type, status, target_count, result_count, started_at, completed_at)
                   VALUES (?, 'nmap', 'completed', ?, ?, ?, ?)""",
                (job_id, len(scan_targets), len(devices), now, now),
            )
            await db.commit()

        # Ship to Elasticsearch: one doc per device (snapshot) + a scan summary.
        # All ES calls are best-effort — never fail the scan job on ES errors.
        try:
            from integrations.elasticsearch_client import get_es_client

            es = get_es_client()
            if es is not None:
                for d in devices:
                    snap = {
                        "id": d.id,
                        "mac": d.mac,
                        "ip": d.ip,
                        "hostname": d.hostname,
                        "device_type": d.device_type,
                        "is_online": d.is_online,
                        "vendor": getattr(d, "vendor", None),
                        "os": getattr(d, "os", None),
                        "label": getattr(d, "label", None),
                    }
                    await es.store_device_snapshot(snap)
                await es.store_scan_result(
                    scan_id=job_id,
                    scan_type="nmap",
                    device_id="",
                    summary={
                        "targets": scan_targets,
                        "device_count": len(devices),
                        "unknown_count": len(unknown),
                    },
                )
        except Exception as _es_e:
            log.debug("ES ship from nmap_scan_job failed (non-fatal): %s", _es_e)

    except Exception as e:
        log.error("nmap_scan_job failed: %s", e)
        await ns.emit_scan_complete(job_id, "nmap", 0, str(e))
        await record_job_run("nmap_scan", "error", str(e))


async def unifi_poll_job() -> None:
    """Scheduled UniFi topology poll — updates managed devices and refreshes graph."""
    if _MOCK:
        log.debug("unifi_poll_job skipped in MOCK mode")
        return

    from config import get_config_manager
    from integrations.unifi import UniFiIntegration
    from services.device_service import merge_unifi_topology
    from services.topology_service import build_topology_graph

    cfg = get_config_manager().get()
    if not cfg.unifi.url or not cfg.unifi.user:
        return

    try:
        unifi = UniFiIntegration(
            url=cfg.unifi.url,
            username=cfg.unifi.user,
            password=cfg.unifi.password.get_secret_value(),
            site=cfg.unifi.site,
        )
        # Hard cap the poll at 20s. Default interval is 30s, so without a
        # timeout a hung controller (cert expired, network partition,
        # UDM rebooting) would stack poll tasks forever — each holding an
        # httpx connection and a copy of the config creds in memory.
        # 20s leaves 10s slack for DB writes + notification emit.
        topology_data = await asyncio.wait_for(unifi.fetch_topology(), timeout=20.0)
        devices = await merge_unifi_topology(topology_data)

        graph = await build_topology_graph(devices, topology_data)
        ns = get_notification_service()
        await ns.emit_topology_updated(graph)
        await record_job_run("unifi_poll", "success", f"{len(devices)} devices")

    except asyncio.TimeoutError:
        log.warning(
            "unifi_poll_job: fetch_topology timed out after 20s — skipping this run"
        )
        await record_job_run("unifi_poll", "error", "timeout (20s)")
    except Exception as e:
        log.error("unifi_poll_job failed: %s", e)
        await record_job_run("unifi_poll", "error", str(e))


async def opnsense_poll_job() -> None:
    """Scheduled OPNsense poll — refreshes DHCP leases, ARP, and
    (optionally) Suricata alerts.

    Runs only when `opnsense.enabled=True` AND `opnsense.url` and
    credentials are configured. Failures are logged as warnings but
    never raised — a flaky firewall shouldn't brick the scheduler.

    Unlike UniFi, OPNsense's value-add is device-identity data
    (hostnames from DHCP, L2 presence from ARP), not topology edges.
    So after the merge we emit `topology:updated` to refresh client
    hostnames/IPs, but we don't try to synthesise edges from lease
    data — the topology-service heuristic fallback still does that.
    """
    if _MOCK:
        log.debug("opnsense_poll_job skipped in MOCK mode")
        return

    from config import get_config_manager
    from integrations.opnsense import OPNsenseIntegration
    from services.device_service import merge_gateway_leases
    from services.topology_service import build_topology_graph
    from services.alarm_service import AlarmInput, upsert_alarms

    cfg = get_config_manager().get()
    oc = cfg.opnsense
    if (
        not oc.enabled
        or not oc.url
        or not oc.api_key
        or not oc.api_secret.get_secret_value()
    ):
        # Silent skip: the user hasn't finished wiring this up yet.
        return

    try:
        integ = OPNsenseIntegration(
            url=oc.url,
            api_key=oc.api_key,
            api_secret=oc.api_secret.get_secret_value(),
            verify_ssl=oc.verify_ssl,
            ids_enabled=oc.ids_enabled,
        )
        # 15s hard cap — same rationale as unifi_poll_job. The
        # Suricata alert query is the tail risk here; everything else
        # returns in milliseconds.
        snap = await asyncio.wait_for(integ.fetch_snapshot(), timeout=15.0)

        source_label = (
            f"{snap.system.product} {snap.system.version}".strip()
            if snap.system
            else "OPNsense"
        )
        devices = await merge_gateway_leases(
            source="opnsense",
            source_label=source_label,
            leases=snap.leases,
            arp=snap.arp,
        )

        # Push fresh topology so new hostnames land in the map + sidebar.
        graph = await build_topology_graph(devices)
        ns = get_notification_service()
        await ns.emit_topology_updated(graph)

        # Convert Suricata alerts into the unified alarm feed.
        if snap.alerts:
            alarm_inputs = []
            for a in snap.alerts:
                # Suricata severity 1..4: 1=emergency, 2=critical,
                # 3=warning, 4=notice. Map into our 5-level vocab.
                sev_map = {1: "critical", 2: "high", 3: "medium", 4: "low"}
                sev = sev_map.get(a.severity, "info")
                alarm_inputs.append(
                    AlarmInput(
                        source="opnsense",
                        source_label=source_label,
                        fingerprint=a.fingerprint,
                        message=a.signature,
                        severity=sev,  # type: ignore[arg-type]
                        category=a.category or "ids",
                        signature=a.signature,
                        src_ip=a.src_ip,
                        dst_ip=a.dst_ip,
                        timestamp=a.timestamp or None,
                        raw={
                            "protocol": a.protocol,
                            "severity_raw": a.severity,
                        },
                    )
                )
            await upsert_alarms(alarm_inputs)

        await record_job_run(
            "opnsense_poll",
            "success",
            f"{len(snap.leases)} leases, {len(snap.arp)} arp, {len(snap.alerts)} alerts",
        )

    except asyncio.TimeoutError:
        log.warning("opnsense_poll_job: snapshot timed out after 15s")
        await record_job_run("opnsense_poll", "error", "timeout (15s)")
    except Exception as e:
        log.error("opnsense_poll_job failed: %s", e)
        await record_job_run("opnsense_poll", "error", str(e))


async def firewalla_poll_job() -> None:
    """Scheduled Firewalla poll — refreshes device inventory + alarms.

    Two modes (set by `firewalla.mode`):
      - "msp": cloud API at https://<msp_domain>/v2/, PAT auth.
      - "local": direct box API on port 8833, fireguard token.

    MSP is the primary path. Local is best-effort because the endpoint
    shape isn't officially documented; if MSP isn't configured we try
    local, and if neither is there we silent-skip.

    Unlike OPNsense, Firewalla HAS authoritative online/offline — the
    agent on the box has a continuous view. We still don't flip
    devices offline here (to avoid conflict with Nmap+UniFi), but
    `online=True` is trusted.
    """
    if _MOCK:
        log.debug("firewalla_poll_job skipped in MOCK mode")
        return

    from config import get_config_manager
    from integrations.firewalla import FirewallaIntegration
    from services.device_service import merge_firewalla_devices
    from services.topology_service import build_topology_graph
    from services.alarm_service import AlarmInput, upsert_alarms

    cfg = get_config_manager().get()
    fc = cfg.firewalla
    if not fc.enabled:
        return

    try:
        integ = FirewallaIntegration(
            mode=fc.mode,
            msp_domain=fc.msp_domain,
            msp_token=fc.msp_token.get_secret_value(),
            local_url=fc.local_url,
            local_token=fc.local_token.get_secret_value(),
            verify_ssl=fc.verify_ssl,
        )
        if not integ.is_configured():
            # Enabled but credentials missing — tell the user via job
            # state so the Settings UI can surface a "needs config" pill.
            await record_job_run(
                "firewalla_poll",
                "error",
                "integration enabled but no credentials configured",
            )
            return

        snap = await asyncio.wait_for(
            integ.fetch_snapshot(with_alarms=fc.alarms_enabled),
            timeout=20.0,
        )

        source_label = snap.box_label or "Firewalla"
        devices = await merge_firewalla_devices(
            source_label=source_label,
            devices=snap.devices,
        )

        graph = await build_topology_graph(devices)
        ns = get_notification_service()
        await ns.emit_topology_updated(graph)

        if snap.alarms:
            alarm_inputs = []
            for a in snap.alarms:
                alarm_inputs.append(
                    AlarmInput(
                        source="firewalla",
                        source_label=source_label,
                        fingerprint=a.fingerprint,
                        message=a.message,
                        severity=a.severity,
                        category=a.category or "firewalla",
                        signature=a.signature,
                        src_ip=a.src_ip,
                        dst_ip=a.dst_ip,
                        device_id=a.device_id,
                        device_name=a.device_name,
                        timestamp=a.timestamp,
                        raw=a.raw,
                    )
                )
            await upsert_alarms(alarm_inputs)

        await record_job_run(
            "firewalla_poll",
            "success",
            f"{len(snap.devices)} devices, {len(snap.alarms)} alarms",
        )

    except asyncio.TimeoutError:
        log.warning("firewalla_poll_job: snapshot timed out after 20s")
        await record_job_run("firewalla_poll", "error", "timeout (20s)")
    except Exception as e:
        log.error("firewalla_poll_job failed: %s", e)
        await record_job_run("firewalla_poll", "error", str(e))


async def latency_poll_job() -> None:
    """Measure latency to gateway(s) + infra devices via TCP-connect timing.

    Cheap — runs frequently (every 30s) to build a time series for the
    network-map latency graph. We target gateway and infra (switches/APs)
    only: those are the devices whose latency matters for homelab health.
    """
    if _MOCK:
        return

    from services.device_service import get_all_devices

    # Common homelab ports, in order of likelihood to respond quickly
    _PROBE_PORTS = (443, 80, 22, 53)
    _PROBE_TIMEOUT = 2.0

    try:
        devices = await get_all_devices()
    except Exception as e:
        log.debug("latency_poll_job: get_all_devices failed: %s", e)
        return

    targets = [
        d
        for d in devices
        if d.is_online and d.ip and d.device_type in ("gateway", "switch", "ap")
    ]
    if not targets:
        return

    now_iso = datetime.now(timezone.utc).isoformat()
    loop = asyncio.get_event_loop()

    async def _probe(ip: str) -> float | None:
        for port in _PROBE_PORTS:
            start = loop.time()
            try:
                fut = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(fut, timeout=_PROBE_TIMEOUT)
                elapsed_ms = (loop.time() - start) * 1000.0
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return elapsed_ms
            except (asyncio.TimeoutError, OSError):
                continue
        return None

    # Probe all targets concurrently
    results = await asyncio.gather(
        *(_probe(d.ip) for d in targets),  # type: ignore[arg-type]
        return_exceptions=True,
    )

    async with get_db() as db:
        for device, result in zip(targets, results):
            latency = result if isinstance(result, (int, float)) else None
            await db.execute(
                "INSERT INTO latency_samples (device_id, ts, latency_ms, success) VALUES (?, ?, ?, ?)",
                (device.id, now_iso, latency, 1 if latency is not None else 0),
            )
        # Keep only last 24h of samples to cap table growth
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        await db.execute("DELETE FROM latency_samples WHERE ts < ?", (cutoff,))
        await db.commit()


async def openvas_scan_job() -> None:
    """Scheduled OpenVAS scan — scans all online devices, emits vuln updates."""
    if _MOCK:
        log.debug("openvas_scan_job skipped in MOCK mode")
        return

    from config import get_config_manager
    from services.device_service import get_all_devices
    from services.vuln_service import run_openvas_scan
    from services.notification_service import get_notification_service

    cfg = get_config_manager().get()
    if not cfg.openvas.host:
        log.info("OpenVAS not configured — skipping scheduled scan")
        return

    # Reachability probe: the OpenVAS container takes 5–10 min on first boot to
    # sync NVT feeds. Skip silently if it isn't listening yet instead of
    # spamming 'Connection refused' for every discovered device.
    import asyncio as _asyncio

    try:
        _reader, _writer = await _asyncio.wait_for(
            _asyncio.open_connection(cfg.openvas.host, cfg.openvas.port),
            timeout=3.0,
        )
        _writer.close()
        try:
            await _writer.wait_closed()
        except Exception:
            pass
    except (OSError, _asyncio.TimeoutError) as e:
        log.info("OpenVAS not reachable (%s) — skipping this run; retrying in 5m", e)
        await record_job_run(
            "openvas_scan",
            "skipped",
            f"scanner unreachable: {e} (retry in 5m)",
        )
        # Register a one-off retry so first-boot scanner-warmup (5–10 min
        # for NVT feed sync) or transient downtime doesn't force us to wait
        # a full 24h for another attempt. The retry calls this same
        # function — if gvmd is still down, we'll re-enter this branch and
        # reschedule another 5-min retry. Once a run gets past the probe,
        # no retry is scheduled, so it naturally stops. Using a distinct
        # job id + replace_existing keeps at most one retry queued.
        try:
            from apscheduler.triggers.date import DateTrigger
            from scheduler.scheduler import get_scheduler

            get_scheduler().add_job(
                openvas_scan_job,
                trigger=DateTrigger(
                    run_date=datetime.now(timezone.utc) + timedelta(minutes=5),
                ),
                id="openvas_scan_retry",
                replace_existing=True,
                misfire_grace_time=60,
            )
        except Exception as rexc:
            log.debug("could not schedule OpenVAS retry: %s", rexc)
        return

    # Pre-flight gvmd auth: if the stored admin creds are wrong, every
    # per-device scan below will fail with the same "Authentication failed"
    # error. Catch it once here, write a prominent audit row, and skip the
    # fanout so logs + audit surface "fix OpenVAS creds in Settings", not
    # "100 hosts failed, check logs".
    from integrations.openvas import OpenVASIntegration
    from services.audit_service import write_audit

    probe = OpenVASIntegration(
        host=cfg.openvas.host,
        port=cfg.openvas.port,
        username=cfg.openvas.user,
        password=cfg.openvas.password.get_secret_value(),
    )
    auth = await probe.test_connection()
    if not auth.ok:
        msg = f"{auth.message} (user={cfg.openvas.user!r})"
        log.error("openvas_scan_job aborted: %s", msg)
        await write_audit(
            "openvas_auth_failed",
            "scheduler",
            {
                "host": cfg.openvas.host,
                "user": cfg.openvas.user,
                "reason": auth.message,
            },
        )
        await record_job_run(
            "openvas_scan",
            "error",
            f"scanner auth failed — fix in Settings: {auth.message}",
        )
        return

    devices = await get_all_devices()
    online = [d for d in devices if d.is_online and d.ip]
    log.info("openvas_scan_job: scanning %d online devices", len(online))

    ns = get_notification_service()
    total_findings = 0

    for device in online:
        try:
            count = await run_openvas_scan(device.id, device.ip)  # type: ignore[arg-type]
            if count > 0:
                total_findings += count
                await ns.emit_vuln_updated(device.id, {"count": count})
        except Exception as e:
            log.error("openvas_scan_job device %s failed: %s", device.id, e)

    await record_job_run(
        "openvas_scan",
        "success",
        f"{total_findings} findings across {len(online)} devices",
    )


async def daily_analysis_job() -> None:
    """Once-a-day AI analysis. Pulls 24h of ES data, sends it to the
    configured Ollama model, stores the markdown report to SQLite for the
    Analysis page to render."""
    if _MOCK:
        log.debug("daily_analysis_job skipped in MOCK mode")
        return

    from config import get_config_manager
    from services.analysis_service import run_daily_analysis

    cfg = get_config_manager().get()
    if not (cfg.ollama.enabled and cfg.ollama.host):
        log.debug("daily_analysis_job: Ollama not configured/enabled — skipping")
        return

    try:
        report_id = await run_daily_analysis(period_hours=24)
        if report_id:
            await record_job_run("daily_analysis", "success", f"report {report_id}")
        else:
            await record_job_run("daily_analysis", "skipped", "ollama disabled")
    except Exception as e:
        log.error("daily_analysis_job failed: %s", e)
        await record_job_run("daily_analysis", "error", str(e))
