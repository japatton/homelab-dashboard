from __future__ import annotations

import asyncio
import logging
import xml.etree.ElementTree as ET
from typing import Optional

from .base import BaseIntegration, ConnectionResult
from models.scan import NmapHost, NmapPort, NmapResult

log = logging.getLogger(__name__)

SCAN_PROFILES = {
    "quick": ["-T4", "-F", "--open"],
    "standard": ["-T4", "-sV", "--open", "--version-intensity", "3"],
    "full": ["-T4", "-sV", "-sC", "--open", "--version-intensity", "5"],
}


class NmapIntegration(BaseIntegration):
    name = "nmap"

    async def test_connection(self) -> ConnectionResult:
        try:
            proc = await asyncio.create_subprocess_exec(
                "nmap",
                "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
            version_line = stdout.decode().split("\n")[0]
            return ConnectionResult.success(version_line.strip())
        except FileNotFoundError:
            return ConnectionResult.offline("nmap binary not found in PATH")
        except Exception as e:
            return ConnectionResult.offline(str(e))

    async def scan(
        self,
        targets: list[str],
        profile: str = "standard",
        extra_args: Optional[list[str]] = None,
        timeout: int = 300,
    ) -> NmapResult:
        args = ["nmap", "-oX", "-"] + SCAN_PROFILES.get(
            profile, SCAN_PROFILES["standard"]
        )
        if extra_args:
            args.extend(extra_args)
        args.extend(targets)

        log.info("Nmap starting: %s", " ".join(args))
        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            log.warning("Nmap scan timed out after %ds", timeout)
            return NmapResult(command=" ".join(args))
        except Exception as e:
            log.error("Nmap subprocess error: %s", e)
            return NmapResult(command=" ".join(args))

        if proc.returncode not in (0, 1):
            log.warning("Nmap exited %d: %s", proc.returncode, stderr.decode()[:200])

        return _parse_xml(stdout.decode(errors="replace"), " ".join(args))


def _parse_xml(xml_text: str, command: str) -> NmapResult:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        log.error("Nmap XML parse error: %s", e)
        return NmapResult(command=command)

    hosts: list[NmapHost] = []
    run_stats = root.find("runstats/finished")
    elapsed = float(run_stats.get("elapsed", "0")) if run_stats is not None else 0.0

    for host_el in root.findall("host"):
        status = host_el.find("status")
        if status is None or status.get("state") != "up":
            continue

        ip = None
        mac = None
        for addr in host_el.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
            elif addr.get("addrtype") == "mac":
                mac = addr.get("addr")

        if not ip:
            continue

        hostnames_el = host_el.find("hostnames")
        hostname = None
        if hostnames_el is not None:
            # `ET.Element.__bool__` on a childless element is deprecated
            # (3.12+), so use explicit `is not None` to pick the first
            # non-null match. PTR hostname is preferred over the bare
            # <hostname> when both are present.
            hn = hostnames_el.find("hostname[@type='PTR']")
            if hn is None:
                hn = hostnames_el.find("hostname")
            if hn is not None:
                hostname = hn.get("name")

        ports: list[NmapPort] = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") not in (
                    "open",
                    "open|filtered",
                ):
                    continue
                service_el = port_el.find("service")
                ports.append(
                    NmapPort(
                        port=int(port_el.get("portid", "0")),
                        protocol=port_el.get("protocol", "tcp"),
                        state=state_el.get("state", "open"),
                        service=service_el.get("name", "")
                        if service_el is not None
                        else "",
                        version=_version_string(service_el)
                        if service_el is not None
                        else "",
                        product=service_el.get("product", "")
                        if service_el is not None
                        else "",
                    )
                )

        os_guess = None
        os_el = host_el.find("os/osmatch")
        if os_el is not None:
            os_guess = os_el.get("name")

        hosts.append(
            NmapHost(
                ip=ip,
                mac=mac,
                hostname=hostname,
                status="up",
                ports=ports,
                os_guess=os_guess,
            )
        )

    return NmapResult(hosts=hosts, scan_duration_seconds=elapsed, command=command)


def _version_string(service_el: ET.Element) -> str:
    parts = [
        service_el.get("product", ""),
        service_el.get("version", ""),
        service_el.get("extrainfo", ""),
    ]
    return " ".join(p for p in parts if p).strip()
