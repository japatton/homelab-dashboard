from __future__ import annotations

import asyncio
import logging
import re
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

# F-003: targets are appended to argv positionally, so any element
# beginning with `-` is interpreted as a flag — `-iL <file>` reads
# arbitrary files as target lists, `--script <name>` enables NSE
# scripts, `-oN <file>` writes Nmap output anywhere the process can
# write. This regex describes the legitimate shapes (single IPv4,
# IPv4/CIDR, last-octet range a.b.c.x-y, DNS hostname). Anything
# else gets rejected at the API boundary.
#
# Defense-in-depth: scan() also prefixes the target list with `--` in
# argv so a future regex relaxation can't accidentally re-enable flag
# injection. Both layers must fail for an attacker-controlled element
# to land as a flag.
_TARGET_RE = re.compile(
    r"^(?:"
    # IPv4 dotted quad, with optional /CIDR (0-32) or last-octet range
    r"(?:[0-9]{1,3}(?:\.[0-9]{1,3}){3})"
    r"(?:/(?:[0-9]|[1-2][0-9]|3[0-2])|-[0-9]{1,3})?"
    r"|"
    # DNS hostname — RFC 1035 conservative (letters, digits, hyphens,
    # dots; not starting/ending with hyphen; up to 253 chars total)
    r"(?=.{1,253}$)"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)"
    r"(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*"
    r")$"
)

_TARGETS_MAX = 64


class TargetValidationError(ValueError):
    """Raised when a target list contains shapes that could be flag-
    injected into Nmap. Callers should turn this into an HTTP 400.
    """


def validate_targets(targets: list[str]) -> None:
    """Reject target lists that could become Nmap flags or that exceed
    a sanity cap. Mutates nothing; raises TargetValidationError on the
    first bad entry. Called from every public path that builds a
    target list — both the API (api/scans.py) and the scheduler's
    default-derivation path (scheduler/jobs.py).
    """
    if not isinstance(targets, list) or not targets:
        raise TargetValidationError("targets must be a non-empty list")
    if len(targets) > _TARGETS_MAX:
        raise TargetValidationError(
            f"too many targets ({len(targets)}); cap is {_TARGETS_MAX}"
        )
    for t in targets:
        if not isinstance(t, str):
            raise TargetValidationError(f"target must be a string, got {type(t)}")
        s = t.strip()
        if not s:
            raise TargetValidationError("target may not be empty")
        if s.startswith("-"):
            # Catches any future regex relaxation that allows a leading
            # dash; --script, -iL, -oN, -A all start with dashes.
            raise TargetValidationError(f"target may not start with '-': {t!r}")
        if not _TARGET_RE.match(s):
            raise TargetValidationError(f"invalid target shape: {t!r}")


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
        # F-003 defence-in-depth: `--` tells Nmap "everything after this
        # is a positional target, even if it looks like a flag." With
        # validate_targets() at the API boundary AND `--` here, both
        # layers have to fail before an attacker-controlled string can
        # land as a flag. validate_targets is the primary gate; this is
        # the backstop.
        args = ["nmap", "-oX", "-"] + SCAN_PROFILES.get(
            profile, SCAN_PROFILES["standard"]
        )
        if extra_args:
            args.extend(extra_args)
        args.append("--")
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
