from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from database import get_db

log = logging.getLogger(__name__)


async def run_openvas_scan(device_id: str, ip: str) -> int:
    """
    Run an OpenVAS scan for one device IP.
    Fetches stored credentials (if any), runs the scan, persists results,
    and returns the number of findings stored.

    Emits `scan:complete` with `device_id` on both success and failure so
    the Devices page can clear its per-row "scanning…" spinner. Without
    this emit, the button relies on a 90s TTL and the user sees a stuck
    spinner even when the scan actually completed seconds earlier.
    """
    from config import get_config_manager
    from integrations.openvas import OpenVASIntegration
    from integrations.credentials import get_scan_credential
    from services.notification_service import get_notification_service

    ns = get_notification_service()
    cfg = get_config_manager().get()
    if not cfg.openvas.host:
        log.warning("OpenVAS host not configured — skipping scan for %s", ip)
        await ns.emit_scan_complete(
            job_id=f"device:{device_id}",
            scan_type="openvas",
            device_count=0,
            error="OpenVAS host not configured",
            device_id=device_id,
        )
        return 0

    try:
        creds = await get_scan_credential(ip)

        scanner = OpenVASIntegration(
            host=cfg.openvas.host,
            port=cfg.openvas.port,
            username=cfg.openvas.user,
            password=cfg.openvas.password.get_secret_value(),
        )

        raw_findings = await scanner.scan_target(ip, credentials=creds)

        # Ship a scan-run summary to Elasticsearch whether or not we found
        # anything — a clean scan is still useful telemetry (proves the
        # scanner ran and covered this host).
        await _ship_scan_summary_to_es(device_id, ip, len(raw_findings))

        count = (
            await _store_findings(device_id, ip, raw_findings) if raw_findings else 0
        )
        if count:
            log.info("Stored %d vulns for %s (%s)", count, ip, device_id)

        await ns.emit_scan_complete(
            job_id=f"device:{device_id}",
            scan_type="openvas",
            device_count=1,
            error=None,
            device_id=device_id,
        )
        return count

    except Exception as e:
        # Let the caller see the exception (fire-and-forget spawn() will
        # log it), but surface to the UI as well so the button clears.
        log.exception("OpenVAS scan failed for %s (%s)", ip, device_id)
        await ns.emit_scan_complete(
            job_id=f"device:{device_id}",
            scan_type="openvas",
            device_count=0,
            error=str(e),
            device_id=device_id,
        )
        raise


async def _ship_scan_summary_to_es(device_id: str, ip: str, finding_count: int) -> None:
    """Post a single 'homelab-scans' doc summarising this OpenVAS run."""
    try:
        from integrations.elasticsearch_client import get_es_client

        es = get_es_client()
        if es is None:
            return
        await es.store_scan_result(
            scan_id=str(uuid.uuid4()),
            scan_type="openvas",
            device_id=device_id,
            summary={"ip": ip, "finding_count": finding_count},
        )
    except Exception as e:
        log.debug("ES scan summary ship failed (non-fatal): %s", e)


async def _store_findings(device_id: str, ip: str, findings: list[dict]) -> int:
    """Persist findings with content-based deduplication.

    Identity for a finding is (device_id, cve_id, name, port, protocol) —
    enforced by a UNIQUE index on vuln_results. A repeat scan of an
    unresolved issue collides with the existing row and updates the
    mutable fields (detected_at = last-seen, scan_job_id, severity/score,
    description/solution, cve_ids). first_seen is preserved by COALESCE
    with the existing row's value.

    Returns the total number of rows touched (inserts + updates), which is
    effectively "findings seen this scan" — the same semantic the UI has
    always used for the per-scan count.
    """
    now = datetime.now(timezone.utc).isoformat()
    scan_job_id = str(uuid.uuid4())
    stored = 0

    # Elasticsearch shipping (best-effort; never blocks SQLite writes)
    from integrations.elasticsearch_client import get_es_client

    es = get_es_client()

    # Build parameter rows + ES docs up front, then issue ONE executemany
    # per scan instead of N round-trips through aiosqlite. A /24 scan can
    # produce hundreds of findings and the old loop was the single biggest
    # chunk of wall-clock time in the scan's DB phase.
    rows: list[tuple] = []
    es_docs: list[dict] = []
    for f in findings:
        vid = str(uuid.uuid4())
        cve_list = f.get("cve_ids") or []
        cve_ids = json.dumps(cve_list)
        primary_cve = cve_list[0] if cve_list else ""
        # Coerce identity-column values to non-null defaults so the
        # UNIQUE index actually dedupes (SQLite treats NULLs as distinct).
        name = f.get("name") or ""
        port = f.get("port") if f.get("port") is not None else 0
        protocol = f.get("protocol") or "tcp"

        rows.append(
            (
                vid,
                device_id,
                primary_cve,
                f["severity"],
                f["score"],
                f.get("description", ""),
                f.get("solution", ""),
                scan_job_id,
                now,  # first_seen (kept only if this is a new row)
                now,  # detected_at
                name,
                port,
                protocol,
                cve_ids,
            )
        )
        es_docs.append(
            {
                "id": vid,
                "device_id": device_id,
                "device_ip": ip,
                "scan_job_id": scan_job_id,
                "cve_id": primary_cve,
                "cve_ids": cve_list,
                "name": name,
                "severity": f["severity"],
                "score": f["score"],
                "port": port,
                "protocol": protocol,
                "description": (f.get("description") or "")[:2000],
                "solution": (f.get("solution") or "")[:1000],
            }
        )

    async with get_db() as db:
        if rows:
            await db.executemany(
                """INSERT INTO vuln_results
                   (id, device_id, cve_id, severity, score, description,
                    solution, scan_job_id, first_seen, detected_at,
                    name, port, protocol, cve_ids)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(device_id, cve_id, name, port, protocol) DO UPDATE SET
                        severity    = excluded.severity,
                        score       = excluded.score,
                        description = excluded.description,
                        solution    = excluded.solution,
                        scan_job_id = excluded.scan_job_id,
                        detected_at = excluded.detected_at,
                        cve_ids     = excluded.cve_ids,
                        -- Preserve the earliest sighting. COALESCE handles
                        -- the pre-migration case where first_seen was NULL.
                        first_seen  = COALESCE(vuln_results.first_seen, excluded.first_seen)
                """,
                rows,
            )
            stored = len(rows)
        await db.commit()

    # ES ship happens outside the DB transaction so an ES outage never
    # rolls back a successful SQLite write. Still non-fatal per-doc.
    if es is not None:
        for doc in es_docs:
            try:
                await es.store_vuln_result(doc)
            except Exception as e:
                log.debug(
                    "ES vuln ship failed for %s (non-fatal): %s",
                    doc.get("cve_id") or doc.get("name"),
                    e,
                )

    return stored


async def get_device_vulns(device_id: str) -> list[dict]:
    async with get_db() as db:
        rows = await (
            await db.execute(
                """SELECT * FROM vuln_results WHERE device_id = ?
               ORDER BY score DESC, detected_at DESC""",
                (device_id,),
            )
        ).fetchall()
    return [dict(r) for r in rows]


async def get_all_vulns(
    severity: Optional[str] = None,
    device_id: Optional[str] = None,
    limit: int = 200,
    offset: int = 0,
) -> list[dict]:
    clauses: list[str] = []
    params: list = []

    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    if device_id:
        clauses.append("device_id = ?")
        params.append(device_id)

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params += [limit, offset]

    async with get_db() as db:
        rows = await (
            await db.execute(
                f"""SELECT v.*, d.ip as device_ip, d.hostname as device_hostname, d.label as device_label
                FROM vuln_results v
                LEFT JOIN devices d ON d.id = v.device_id
                {where}
                ORDER BY v.score DESC, v.detected_at DESC
                LIMIT ? OFFSET ?""",
                params,
            )
        ).fetchall()

    return [dict(r) for r in rows]


async def get_vuln_stats() -> dict:
    async with get_db() as db:
        rows = await (
            await db.execute(
                "SELECT severity, COUNT(*) as count FROM vuln_results GROUP BY severity"
            )
        ).fetchall()
        total = await (await db.execute("SELECT COUNT(*) FROM vuln_results")).fetchone()
        devices_affected = await (
            await db.execute("SELECT COUNT(DISTINCT device_id) FROM vuln_results")
        ).fetchone()

    by_sev = {r["severity"]: r["count"] for r in rows}
    return {
        "total": total[0] if total else 0,
        "devices_affected": devices_affected[0] if devices_affected else 0,
        "critical": by_sev.get("critical", 0),
        "high": by_sev.get("high", 0),
        "medium": by_sev.get("medium", 0),
        "low": by_sev.get("low", 0),
    }
