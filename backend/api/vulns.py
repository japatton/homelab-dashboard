from __future__ import annotations

import os
from typing import Optional

from fastapi import APIRouter, Body, HTTPException, Query

router = APIRouter(prefix="/api/vulns", tags=["vulns"])

_MOCK = os.getenv("BACKEND_MOCK", "false").lower() == "true"


# ── Mock fixture data ─────────────────────────────────────────────────────────

_MOCK_VULNS = [
    {
        "id": "vuln-001",
        "device_id": "dev-server-01",
        "device_ip": "192.168.1.50",
        "device_hostname": "homelab-server",
        "device_label": "Homelab Server",
        "cve_id": "CVE-2023-44487",
        "severity": "high",
        "score": 7.5,
        "name": "HTTP/2 Rapid Reset Attack",
        "description": "The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly.",
        "solution": "Update to a patched version of your HTTP server software.",
        "port": 443,
        "protocol": "tcp",
        "cve_ids": '["CVE-2023-44487"]',
        "scan_job_id": "mock-job-01",
        "detected_at": "2026-04-17T04:00:00Z",
    },
    {
        "id": "vuln-002",
        "device_id": "dev-server-01",
        "device_ip": "192.168.1.50",
        "device_hostname": "homelab-server",
        "device_label": "Homelab Server",
        "cve_id": "CVE-2023-2650",
        "severity": "high",
        "score": 7.5,
        "name": "OpenSSL Excessive Resource Usage in X.509 Policy Constraints",
        "description": "Processing some specially crafted ASN.1 object identifiers or data containing them may be very slow.",
        "solution": "Update OpenSSL to version 3.0.9, 1.1.1u or later.",
        "port": 443,
        "protocol": "tcp",
        "cve_ids": '["CVE-2023-2650"]',
        "scan_job_id": "mock-job-01",
        "detected_at": "2026-04-17T04:00:00Z",
    },
    {
        "id": "vuln-003",
        "device_id": "dev-truenas-01",
        "device_ip": "192.168.1.60",
        "device_hostname": "truenas",
        "device_label": "TrueNAS",
        "cve_id": "CVE-2022-45143",
        "severity": "critical",
        "score": 9.1,
        "name": "Apache Tomcat HTTP Request Smuggling",
        "description": "Apache Tomcat ignored the HTTP method when determining whether to send a 204 response, potentially allowing request smuggling attacks.",
        "solution": "Upgrade Apache Tomcat to 10.1.2, 9.0.69 or 8.5.83.",
        "port": 80,
        "protocol": "tcp",
        "cve_ids": '["CVE-2022-45143"]',
        "scan_job_id": "mock-job-01",
        "detected_at": "2026-04-17T04:00:00Z",
    },
    {
        "id": "vuln-004",
        "device_id": "dev-truenas-01",
        "device_ip": "192.168.1.60",
        "device_hostname": "truenas",
        "device_label": "TrueNAS",
        "cve_id": "CVE-2023-0215",
        "severity": "medium",
        "score": 5.9,
        "name": "OpenSSL USE-after-free following BIO_new_NDEF",
        "description": "The public API function BIO_new_NDEF is a helper function used for streaming ASN.1 data via a BIO.",
        "solution": "Update OpenSSL to version 3.0.8, 1.1.1t or later.",
        "port": 443,
        "protocol": "tcp",
        "cve_ids": '["CVE-2023-0215"]',
        "scan_job_id": "mock-job-01",
        "detected_at": "2026-04-17T04:00:00Z",
    },
    {
        "id": "vuln-005",
        "device_id": "dev-unknown-01",
        "device_ip": "192.168.1.200",
        "device_hostname": None,
        "device_label": None,
        "cve_id": "CVE-2021-44228",
        "severity": "critical",
        "score": 10.0,
        "name": "Apache Log4j2 Remote Code Execution (Log4Shell)",
        "description": "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases) JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints.",
        "solution": "Update Log4j2 to version 2.17.1 (Java 8), 2.12.4 (Java 7) or 2.3.2 (Java 6).",
        "port": 8443,
        "protocol": "tcp",
        "cve_ids": '["CVE-2021-44228"]',
        "scan_job_id": "mock-job-01",
        "detected_at": "2026-04-17T04:01:00Z",
    },
    {
        "id": "vuln-006",
        "device_id": "dev-unknown-01",
        "device_ip": "192.168.1.200",
        "device_hostname": None,
        "device_label": None,
        "cve_id": "CVE-2021-45046",
        "severity": "critical",
        "score": 9.0,
        "name": "Apache Log4j2 Context Lookup JNDI Injection",
        "description": "Thread Context Message Pattern and Context Lookup Pattern vulnerable to partial execution of arbitrary code.",
        "solution": "Update Log4j2 to version 2.16.0 or later.",
        "port": 9000,
        "protocol": "tcp",
        "cve_ids": '["CVE-2021-45046"]',
        "scan_job_id": "mock-job-01",
        "detected_at": "2026-04-17T04:01:00Z",
    },
    {
        "id": "vuln-007",
        "device_id": "dev-server-01",
        "device_ip": "192.168.1.50",
        "device_hostname": "homelab-server",
        "device_label": "Homelab Server",
        "cve_id": None,
        "severity": "low",
        "score": 2.0,
        "name": "SSL/TLS Certificate Signed Using Weak Hash Algorithm",
        "description": "The SSL/TLS certificate is signed using a deprecated weak hashing algorithm.",
        "solution": "Reissue the certificate using a strong algorithm such as SHA-256.",
        "port": 443,
        "protocol": "tcp",
        "cve_ids": "[]",
        "scan_job_id": "mock-job-01",
        "detected_at": "2026-04-17T04:00:00Z",
    },
]


def _filter_mock(severity: Optional[str], device_id: Optional[str]) -> list[dict]:
    results = _MOCK_VULNS
    if severity:
        results = [v for v in results if v["severity"] == severity]
    if device_id:
        results = [v for v in results if v["device_id"] == device_id]
    return results


# ── Routes ────────────────────────────────────────────────────────────────────


@router.get("")
async def list_vulns(
    severity: Optional[str] = None,
    device_id: Optional[str] = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    if _MOCK:
        data = _filter_mock(severity, device_id)
        return data[offset : offset + limit]

    from services.vuln_service import get_all_vulns

    return await get_all_vulns(
        severity=severity, device_id=device_id, limit=limit, offset=offset
    )


@router.get("/stats")
async def vuln_stats():
    if _MOCK:
        return {
            "total": len(_MOCK_VULNS),
            "devices_affected": 3,
            "critical": sum(1 for v in _MOCK_VULNS if v["severity"] == "critical"),
            "high": sum(1 for v in _MOCK_VULNS if v["severity"] == "high"),
            "medium": sum(1 for v in _MOCK_VULNS if v["severity"] == "medium"),
            "low": sum(1 for v in _MOCK_VULNS if v["severity"] == "low"),
        }
    from services.vuln_service import get_vuln_stats

    return await get_vuln_stats()


@router.get("/device/{device_id}")
async def device_vulns(device_id: str):
    if _MOCK:
        return _filter_mock(None, device_id)
    from services.vuln_service import get_device_vulns

    return await get_device_vulns(device_id)


@router.post("/scan/{device_id}")
async def trigger_device_scan(device_id: str):
    if _MOCK:
        return {"triggered": device_id, "mock": True}

    from database import get_db

    async with get_db() as db:
        row = await (
            await db.execute("SELECT ip FROM devices WHERE id = ?", (device_id,))
        ).fetchone()
    if not row or not row["ip"]:
        raise HTTPException(status_code=404, detail="Device not found or has no IP")

    from services.audit_service import write_audit
    from services.vuln_service import run_openvas_scan
    from services.background_tasks import spawn

    spawn(run_openvas_scan(device_id, row["ip"]), name=f"scan:openvas:{device_id}")
    await write_audit(
        "trigger_openvas_scan",
        "user",
        {"device_id": device_id, "ip": row["ip"]},
    )
    return {"triggered": device_id, "ip": row["ip"]}


# ── Scan credentials ──────────────────────────────────────────────────────────


@router.get("/credentials")
async def list_credentials():
    if _MOCK:
        return []
    from integrations.credentials import list_scan_credentials

    return await list_scan_credentials()


@router.post("/credentials")
async def add_credential(
    target_ip: str = Body(...),
    username: str = Body(...),
    # Auth type chosen in the UI. Only one of (password) / (private_key[,
    # key_passphrase]) is meaningful; the other is ignored.
    auth_type: str = Body("password"),
    password: str = Body(""),
    private_key: str = Body(""),
    key_passphrase: str = Body(""),
    note: str = Body(""),
):
    from integrations.credentials import upsert_scan_credential
    from services.audit_service import write_audit

    if auth_type not in ("password", "key"):
        raise HTTPException(status_code=400, detail=f"invalid auth_type {auth_type!r}")
    if auth_type == "password" and not password:
        raise HTTPException(
            status_code=400, detail="password required for password auth"
        )
    if auth_type == "key" and not private_key:
        raise HTTPException(status_code=400, detail="private_key required for key auth")

    cred_id = await upsert_scan_credential(
        target_ip,
        username,
        auth_type=auth_type,
        password=password,
        private_key=private_key,
        key_passphrase=key_passphrase,
        note=note,
    )
    await write_audit(
        "save_scan_credential",
        "user",
        {
            "id": cred_id,
            "target_ip": target_ip,
            "username": username,
            "auth_type": auth_type,
        },
    )
    return {"id": cred_id, "target_ip": target_ip}


@router.delete("/credentials/{cred_id}")
async def delete_credential(cred_id: str):
    from integrations.credentials import delete_scan_credential
    from services.audit_service import write_audit

    if not await delete_scan_credential(cred_id):
        raise HTTPException(status_code=404, detail="Credential not found")
    await write_audit("delete_scan_credential", "user", {"id": cred_id})
    return {"deleted": cred_id}


@router.post("/credentials/test")
async def test_credential(
    target_ip: str = Body(...),
    username: str = Body(...),
    auth_type: str = Body("password"),
    password: str = Body(""),
    private_key: str = Body(""),
    key_passphrase: str = Body(""),
):
    """Expand `target_ip` (single / comma list / a.b.c.x-y / CIDR) and try an
    SSH auth against every resulting host. Returns overall ok/fail + per-host
    detail. Each run writes a summary audit entry so Settings mistakes are
    reviewable.

    F-009: probe only IPs that already exist in the devices table. Without
    this gate the endpoint is a token-gated SSH-spray + lateral-movement
    primitive — the operator can probe arbitrary LAN IPs by submitting a
    range pattern. Allowing only discovered devices bounds the surface to
    targets the dashboard has actually seen (via Nmap / UniFi / OPNsense /
    Firewalla). IPs not in the table are returned in `unknown_targets` so
    the operator sees what was filtered.
    """
    from services.audit_service import write_audit
    from services.device_service import known_device_ips
    from services.ip_expand import expand_targets, ExpandError
    from services.ssh_probe import probe_many

    if auth_type not in ("password", "key"):
        raise HTTPException(status_code=400, detail=f"invalid auth_type {auth_type!r}")
    if auth_type == "password" and not password:
        raise HTTPException(
            status_code=400, detail="password required for password auth"
        )
    if auth_type == "key" and not private_key:
        raise HTTPException(status_code=400, detail="private_key required for key auth")

    try:
        ips = expand_targets(target_ip)
    except ExpandError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # F-009: filter to IPs already in the devices table.
    known = await known_device_ips(ips)
    probe_ips = [ip for ip in ips if ip in known]
    unknown_targets = [ip for ip in ips if ip not in known]

    if not probe_ips:
        # Nothing to probe — surface the gate as a 400 so the operator
        # sees the rejection reason (vs a misleading "0 hosts tested").
        raise HTTPException(
            status_code=400,
            detail=(
                "no targets in the devices table — run a discovery scan "
                "first or pick IPs the dashboard has already seen. "
                f"Filtered out: {unknown_targets[:10]}"
            ),
        )

    results = await probe_many(
        probe_ips,
        username,
        password=password or None,
        private_key=private_key or None,
        key_passphrase=key_passphrase or None,
    )
    per_host = [r.to_dict() for r in results]
    ok_count = sum(1 for r in results if r.ok)
    all_ok = ok_count == len(results)
    summary = {
        "target_ip": target_ip,
        "username": username,
        "auth_type": auth_type,
        "host_count": len(results),
        "ok_count": ok_count,
        "fail_count": len(results) - ok_count,
        "all_ok": all_ok,
        "unknown_targets": unknown_targets,
        "results": per_host,
    }
    # One audit row per test — individual host lines are in `results` for
    # when "check logs" is the user-facing error. 100-entry retention would
    # otherwise chew through the cap on a single /24 test.
    await write_audit(
        "test_scan_credential",
        "user",
        {k: v for k, v in summary.items() if k != "results"}
        | {
            # Keep the per-host list, but cap what we store so a /29 doesn't
            # hide every other audit row off-screen.
            "results": per_host[:32],
        },
    )
    return summary
