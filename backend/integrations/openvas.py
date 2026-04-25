from __future__ import annotations

import asyncio
import logging
import os
import uuid
from typing import Optional
from xml.etree import ElementTree as ET

from .base import BaseIntegration, ConnectionResult

log = logging.getLogger(__name__)

# GMP severity band → our severity labels
_SEVERITY_MAP = [
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
    (0.0, "log"),
]


def _band(score: float) -> str:
    for threshold, label in _SEVERITY_MAP:
        if score >= threshold:
            return label
    return "log"


class OpenVASIntegration(BaseIntegration):
    name = "openvas"

    def __init__(
        self, host: str, port: int = 9390, username: str = "admin", password: str = ""
    ):
        self._host = host
        self._port = port
        self._username = username
        self._password = password

    def _get_gmp(self):
        from gvm.connections import TLSConnection
        from gvm.protocols.gmp import GMPv224

        # Use the version-specific wrapper, not the auto-selecting `Gmp`. On
        # python-gvm 26.2 the outer `Gmp` does not expose `authenticate` until
        # protocol negotiation inside `__enter__`, and even then some methods
        # differ from GMPv224. We pin GMPv224 because that is what the scan
        # path (_run_scan_sync) uses successfully against gvmd 22.7.
        # timeout=120: gvmd can be slow to serialize large responses
        # (get_scanners/get_report). Without this, the default ~60s timeout
        # manifests as "Remote closed the connection" mid-stream.
        conn = TLSConnection(hostname=self._host, port=self._port, timeout=120)
        return GMPv224(conn)

    async def test_connection(self) -> ConnectionResult:
        """Full gvmd auth check — reachability + credential validation.

        python-gvm's `Gmp.authenticate()` does NOT raise on 400; it silently
        leaves `_authenticated = False` when gvmd rejects the creds. Until this
        fix, that meant the Settings "Test" badge went green on TCP reachability
        even when the password was wrong, and the scheduled scan was the first
        thing to actually surface the auth failure.

        We now:
          1. TCP-connect with a short timeout (fast-fail on unreachable /
             first-boot warmup)
          2. Run authenticate() and parse the response status — 2xx means we
             really got in, anything else becomes a user-visible error.
          3. Read the version, mostly for the label.
        """
        try:
            # Fast TCP reachability probe up front so 'scanner not running' and
            # 'auth failed' produce distinct messages.
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self._host, self._port),
                    timeout=4.0,
                )
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
            except (OSError, asyncio.TimeoutError) as e:
                return ConnectionResult.offline(f"scanner unreachable: {e}")

            def _check():
                gmp = self._get_gmp()
                with gmp:
                    auth_resp = gmp.authenticate(self._username, self._password)
                    auth_root = ET.fromstring(auth_resp)
                    auth_status = auth_root.get("status", "")
                    auth_stext = auth_root.get("status_text", "")
                    if not auth_status.startswith("2"):
                        # Bubble up gvmd's own status text — "Authentication
                        # failed", "Only command GET_VERSION is allowed before
                        # AUTHENTICATE" (scanner still warming up), etc.
                        raise RuntimeError(
                            f"authentication rejected (status={auth_status}): "
                            f"{auth_stext} [user={self._username!r}]"
                        )
                    version = gmp.get_version()
                    root = ET.fromstring(version)
                    return root.findtext("version") or "unknown"

            version = await asyncio.to_thread(_check)
            return ConnectionResult.success(
                f"OpenVAS GMP {version} — authenticated as {self._username}"
            )
        except ImportError:
            return ConnectionResult.offline("python-gvm not installed")
        except Exception as e:
            return ConnectionResult.offline(self._safe_error(e))

    async def scan_target(
        self,
        ip: str,
        scan_config: str = "daba56c8-73ec-11df-a475-002264764cea",  # Full and fast
        credentials: Optional[dict] = None,
    ) -> list[dict]:
        """
        Run an OpenVAS scan against a single IP.
        Returns list of vuln dicts with keys: name, severity, score, description, solution, port, cve_ids.
        credentials: optional dict with keys ssh_username, ssh_password, smb_username, smb_password.
        """
        try:
            results = await asyncio.to_thread(
                self._run_scan_sync, ip, scan_config, credentials or {}
            )
            return results
        except Exception as e:
            log.error("OpenVAS scan failed for %s: %s", ip, self._safe_error(e))
            return []

    # Well-known GMP UUIDs. The scan_config UUID for "Full and fast" has been
    # stable for over a decade; the scanner UUID for the default "OpenVAS
    # Default" scanner varies between GVM releases, so we resolve it at runtime.
    _DEFAULT_SCAN_CONFIG = "daba56c8-73ec-11df-a475-002264764cea"  # Full and fast

    def _resolve_default_scanner(self, gmp) -> str:
        """Look up the default OpenVAS scanner's UUID on this server. We pick
        the first scanner whose type indicates it's the local OpenVAS scanner
        (type=2 in GMP), falling back to the first non-CVE scanner if that
        fails.

        Important: on some gvmd builds (immauss/openvas 22.7 being one),
        `get_scanners` severs the TLS session mid-response. python-gvm's
        TLSConnection then transparently reopens the socket — but the new
        socket is unauthenticated, so subsequent commands fail with
        "Only command GET_VERSION is allowed before AUTHENTICATE".
        We catch that case and re-authenticate before returning."""
        try:
            # filter_string keeps the payload small — full get_scanners on
            # some gvmd builds closes the socket mid-response.
            r = gmp.get_scanners(filter_string="first=1 rows=20")
            root = ET.fromstring(r)
            # Prefer type=2 (OpenVAS scanner)
            for s in root.findall("scanner"):
                stype = s.findtext("type") or ""
                name = s.findtext("name") or ""
                if stype == "2" or "OpenVAS" in name:
                    sid = s.get("id")
                    if sid:
                        return sid
            # Fallback: first scanner that isn't the CVE scanner (type=3)
            for s in root.findall("scanner"):
                if (s.findtext("type") or "") != "3":
                    sid = s.get("id")
                    if sid:
                        return sid
        except Exception as e:
            log.warning(
                "get_scanners failed (%s) — reauthenticating on new socket "
                "and using the OpenVAS Default UUID",
                e,
            )
            # The broken socket has been replaced by python-gvm; the new one
            # is unauthenticated. Re-authenticate so the rest of the scan
            # (create_target, create_task, start_task, ...) can proceed.
            try:
                gmp.authenticate(self._username, self._password)
            except Exception as auth_err:
                log.error(
                    "re-authenticate after get_scanners failure also failed: %s",
                    auth_err,
                )
        # Final fallback: the historical "OpenVAS Default" UUID. Verified
        # present on immauss/openvas builds via `gvmd --verify-scanner`.
        return "08b69003-5fc2-4037-a479-93b440211c73"

    def _run_scan_sync(
        self, ip: str, scan_config: str, credentials: dict
    ) -> list[dict]:
        """High-level python-gvm scan implementation.

        Previous iterations tried raw-XML-over-same-socket and
        gmp.send_command bypass paths — both hit auth persistence issues
        we couldn't explain with python-gvm 26.2.0. We now use ONLY the
        library's high-level methods, which empirically keep the session
        alive (authenticate + get_version works in test_connection). We
        also force GMPv224 directly to avoid the auto-negotiation path
        picking GMPv226 (whose create_target XML gvmd 22.7 rejects with
        'Remote closed the connection').
        """
        from gvm.connections import TLSConnection
        from gvm.protocols.gmp import GMPv224
        from gvm.protocols.gmp.requests.v224 import AliveTest, CredentialType

        scanner_id = os.getenv(
            "OPENVAS_SCANNER_ID",
            "08b69003-5fc2-4037-a479-93b440211c73",
        )
        port_list_id = os.getenv(
            "OPENVAS_PORT_LIST_ID",
            # "All TCP and Nmap top 100 UDP" — full 65,535 TCP + the 100
            # most-common UDP ports. The best default for a homelab: catches
            # non-standard TCP services (Plex, Docker-published ports, game
            # servers) without paying the hour-long UDP-everywhere tax.
            "730ef368-57e2-11e1-a90f-406186ea4fc5",
        )

        def _check(cmd_name: str, resp: str) -> ET.Element:
            """Parse a GMP response and raise if status is not 2xx."""
            root = ET.fromstring(resp)
            status = root.get("status", "")
            stext = root.get("status_text", "")
            if not status.startswith("2"):
                raise RuntimeError(
                    f"{cmd_name} failed: status={status}, status_text={stext!r}, "
                    f"body={resp[:500]}"
                )
            return root

        step = "connect"
        try:
            conn = TLSConnection(hostname=self._host, port=self._port, timeout=120)
            with GMPv224(conn) as gmp:
                step = "authenticate"
                # python-gvm's gmp.authenticate() silently swallows a failed
                # auth — it just doesn't set `self._authenticated = True` and
                # returns the response string. Every subsequent command then
                # fails with gvmd's "Only command GET_VERSION is allowed
                # before AUTHENTICATE". Catch and surface the real failure
                # right here so the error names the actual cause instead of
                # cascading through create_target / create_task / etc.
                auth_resp = gmp.authenticate(self._username, self._password)
                auth_root = ET.fromstring(auth_resp)
                auth_status = auth_root.get("status", "")
                auth_stext = auth_root.get("status_text", "")
                if not auth_status.startswith("2"):
                    raise RuntimeError(
                        f"authenticate rejected: status={auth_status} "
                        f"status_text={auth_stext!r} "
                        f"user={self._username!r} body={auth_resp[:300]}"
                    )

                # Create SSH credential if provided. Picks USERNAME_PASSWORD
                # or USERNAME_SSH_KEY based on auth_type — the store may hold
                # either, and gvmd needs the right credential_type per flavour.
                cred_id = None
                auth_type = credentials.get("auth_type") or "password"
                have_user = bool(credentials.get("ssh_username"))
                have_pw = bool(credentials.get("ssh_password"))
                have_key = bool(credentials.get("ssh_private_key"))

                if have_user and (
                    (auth_type == "password" and have_pw)
                    or (auth_type == "key" and have_key)
                ):
                    step = "create_credential"
                    try:
                        kwargs = dict(
                            name=f"homelab-ssh-{ip}-{uuid.uuid4().hex[:6]}",
                            login=credentials["ssh_username"],
                        )
                        if auth_type == "key":
                            kwargs["credential_type"] = CredentialType.USERNAME_SSH_KEY
                            kwargs["private_key"] = credentials["ssh_private_key"]
                            kp = credentials.get("ssh_key_passphrase") or ""
                            if kp:
                                # python-gvm names this parameter "key_phrase"
                                kwargs["key_phrase"] = kp
                        else:
                            kwargs["credential_type"] = CredentialType.USERNAME_PASSWORD
                            kwargs["password"] = credentials["ssh_password"]
                        r = gmp.create_credential(**kwargs)
                        cred_id = ET.fromstring(r).get("id")
                    except Exception as e:
                        log.warning("Credential creation failed for %s: %s", ip, e)

                log.info(
                    "OpenVAS scan %s: scanner=%s config=%s port_list=%s cred=%s",
                    ip,
                    scanner_id,
                    scan_config,
                    port_list_id,
                    cred_id,
                )

                # Create target
                step = "create_target"
                target_name = f"homelab-{ip}-{uuid.uuid4().hex[:8]}"
                target_kwargs: dict = {
                    "name": target_name,
                    "hosts": [ip],
                    "alive_test": AliveTest.CONSIDER_ALIVE,
                    "port_list_id": port_list_id,
                }
                if cred_id:
                    target_kwargs["ssh_credential_id"] = cred_id
                    target_kwargs["ssh_credential_port"] = 22

                r = gmp.create_target(**target_kwargs)
                target_root = ET.fromstring(r)
                target_id = target_root.get("id")
                if not target_id:
                    status = target_root.get("status", "?")
                    stext = target_root.get("status_text", "?")
                    raise RuntimeError(
                        f"create_target returned no id (status={status}, status_text={stext!r})"
                    )

                # Create task
                step = "create_task"
                task_name = f"homelab-task-{ip}-{uuid.uuid4().hex[:8]}"
                r = gmp.create_task(
                    name=task_name,
                    config_id=scan_config,
                    target_id=target_id,
                    scanner_id=scanner_id,
                )
                task_root = ET.fromstring(r)
                task_id = task_root.get("id")
                if not task_id:
                    status = task_root.get("status", "?")
                    stext = task_root.get("status_text", "?")
                    raise RuntimeError(
                        f"create_task returned no id (status={status}, status_text={stext!r})"
                    )

                # Start task
                step = "start_task"
                r = gmp.start_task(task_id)
                report_id = ET.fromstring(r).findtext("report_id")

                # Poll until scan finishes (max 60 min — "Full and fast" with
                # full 65535-TCP port list can run 20-40 min by itself, and
                # OpenVAS queues scans when >1 runs at once).
                step = "poll"
                import time

                last_logged_progress = -2
                final_status = ""
                # NOTE: `time.sleep` is intentional here — this whole
                # function runs inside `asyncio.to_thread` so a sync sleep
                # is correct and does not block the event loop. Do NOT
                # "fix" this to asyncio.sleep — the python-gvm client is
                # sync-only and can't be awaited.
                for i in range(720):  # 720 * 5s = 60 min
                    time.sleep(5)
                    r = gmp.get_task(task_id)
                    task_root = ET.fromstring(r)
                    status = task_root.findtext("task/status") or ""
                    progress = task_root.findtext("task/progress") or "?"
                    final_status = status
                    # Log on status change or every ~60s of Running
                    if (progress != last_logged_progress and i % 12 == 0) or status in (
                        "Done",
                        "Stopped",
                    ):
                        log.info(
                            "OpenVAS scan %s: status=%s progress=%s (poll %d/720)",
                            ip,
                            status,
                            progress,
                            i,
                        )
                        last_logged_progress = progress
                    if status in ("Done", "Stopped"):
                        break
                    if status == "":
                        break
                else:
                    log.warning(
                        "OpenVAS scan %s: poll timed out after 60 min "
                        "(last status=%s)",
                        ip,
                        final_status,
                    )

                # Fetch results
                if not report_id:
                    log.warning("OpenVAS scan %s: no report_id, returning empty", ip)
                    return []
                if final_status != "Done":
                    log.warning(
                        "OpenVAS scan %s: poll exited with status=%s "
                        "(not Done) — fetching report anyway",
                        ip,
                        final_status,
                    )
                step = "get_report"
                # rows=-1 returns all results (default page size is 10, which
                # silently truncates any real scan). first=1 sorts from the
                # top of the list. min_qod=30 keeps medium-confidence NVTs
                # instead of gvmd's default 70 cutoff.
                r = gmp.get_report(
                    report_id,
                    filter_string="rows=-1 first=1 min_qod=30 apply_overrides=1",
                )
                report_root = ET.fromstring(r)
                # Dump counts from the report envelope so we can see if gvmd
                # is giving us zero results, or if _parse_results is dropping
                # them during the severity="log" filter step.
                rc = report_root.find(".//result_count")
                full = rc.findtext("full") if rc is not None else "?"
                filtered = rc.findtext("filtered") if rc is not None else "?"
                raw_result_count = len(report_root.findall(".//result"))
                log.info(
                    "OpenVAS scan %s: report %s result_count full=%s filtered=%s "
                    "raw_elements=%d",
                    ip,
                    report_id,
                    full,
                    filtered,
                    raw_result_count,
                )
                parsed = _parse_results(report_root)
                log.info(
                    "OpenVAS scan %s: parsed %d findings after severity filter "
                    "(dropped %d 'log' severity)",
                    ip,
                    len(parsed),
                    raw_result_count - len(parsed),
                )
                return parsed
        except Exception as e:
            # Re-raise with the step annotated so the caller logs which
            # GMP operation actually broke (rather than just "Remote closed").
            raise RuntimeError(f"{step} failed: {self._safe_error(e)}") from e

    async def get_scan_configs(self) -> list[dict]:
        try:

            def _fetch():
                from gvm.connections import TLSConnection
                from gvm.protocols.gmp import Gmp

                with Gmp(TLSConnection(hostname=self._host, port=self._port)) as gmp:
                    gmp.authenticate(self._username, self._password)
                    r = gmp.get_scan_configs()
                    root = ET.fromstring(r)
                    return [
                        {"id": c.get("id"), "name": c.findtext("name", "")}
                        for c in root.findall("config")
                    ]

            return await asyncio.to_thread(_fetch)
        except Exception as e:
            log.warning("get_scan_configs failed: %s", e)
            return []


def _parse_results(root: ET.Element) -> list[dict]:
    vulns = []
    # Count severity bands before filtering so debug logs show the shape of
    # what gvmd returned (e.g. "5 high, 12 medium, 40 low, 80 log").
    band_counts: dict[str, int] = {}
    for result in root.findall(".//result"):
        nvt = result.find("nvt")
        if nvt is None:
            continue

        name = result.findtext("name") or nvt.findtext("name") or "Unknown"
        description = result.findtext("description") or ""
        solution_el = nvt.find("solution")
        solution = solution_el.text if solution_el is not None else ""

        try:
            score = float(
                result.findtext("severity") or nvt.findtext("cvss_base") or "0"
            )
        except ValueError:
            score = 0.0

        severity = _band(score)
        band_counts[severity] = band_counts.get(severity, 0) + 1
        if severity == "log":
            continue  # Skip informational

        port_str = result.findtext("port") or ""
        port: Optional[int] = None
        protocol = "tcp"
        if "/" in port_str:
            p, proto = port_str.split("/", 1)
            try:
                port = int(p)
                protocol = proto.strip()
            except ValueError:
                pass

        cve_ids = [ref.get("id", "") for ref in nvt.findall("refs/ref[@type='cve']")]

        vulns.append(
            {
                "name": name,
                "description": description[:2000],
                "solution": (solution or "")[:1000],
                "score": score,
                "severity": severity,
                "port": port,
                "protocol": protocol,
                "cve_ids": cve_ids,
            }
        )

    if band_counts:
        log.info("OpenVAS severity breakdown: %s", band_counts)
    return vulns
