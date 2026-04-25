from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Optional

import httpx

from .base import BaseIntegration, ConnectionResult

log = logging.getLogger(__name__)


@dataclass
class UniFiClient:
    """Represents a connected client device."""
    mac: str
    ip: Optional[str] = None
    hostname: Optional[str] = None
    ap_mac: Optional[str] = None
    sw_mac: Optional[str] = None
    sw_port: Optional[int] = None
    is_wired: bool = True
    signal: Optional[int] = None
    tx_bytes: int = 0
    rx_bytes: int = 0
    uptime: int = 0
    oui: Optional[str] = None
    name: Optional[str] = None


@dataclass
class UniFiDevice:
    """Represents a UniFi-managed network device (AP, switch, gateway)."""
    mac: str
    ip: Optional[str] = None
    name: Optional[str] = None
    model: str = ""
    device_type: str = "unknown"
    firmware: str = ""
    uptime: int = 0
    port_count: int = 0
    uplink_mac: Optional[str] = None
    clients: list[str] = field(default_factory=list)


@dataclass
class UniFiTopology:
    devices: list[UniFiDevice] = field(default_factory=list)
    clients: list[UniFiClient] = field(default_factory=list)


class UniFiIntegration(BaseIntegration):
    name = "unifi"

    def __init__(self, url: str, username: str, password: str, site: str = "default"):
        self._url = url.rstrip("/")
        self._username = username
        self._password = password
        # The value the user configured — may be a site ID ("default") OR a
        # human-readable display name ("Dream Machine Pro"). We resolve the
        # actual ID on first use via `_resolve_site()`.
        self._site_configured = site
        self._site = site
        self._site_resolved = False
        self._cookies: dict[str, str] = {}
        self._headers: dict[str, str] = {}
        self._is_udm = True  # Assume UDM Pro; auto-detected on first auth

    def _api(self, path: str) -> str:
        if self._is_udm:
            return f"{self._url}/proxy/network/api/s/{self._site}/{path}"
        return f"{self._url}/api/s/{self._site}/{path}"

    def _root_api(self, path: str) -> str:
        """URL for controller-level endpoints (not scoped to a site)."""
        if self._is_udm:
            return f"{self._url}/proxy/network/api/{path}"
        return f"{self._url}/api/{path}"

    async def _authenticate(self, client: httpx.AsyncClient) -> bool:
        # Try UDM Pro endpoint first
        for udm in (True, False):
            login_url = f"{self._url}/api/auth/login" if udm else f"{self._url}/api/login"
            try:
                r = await client.post(
                    login_url,
                    json={"username": self._username, "password": self._password},
                    timeout=10,
                )
                if r.status_code in (200, 201):
                    self._is_udm = udm
                    self._cookies = dict(r.cookies)
                    csrf = r.headers.get("X-CSRF-Token") or r.headers.get("x-csrf-token")
                    if csrf:
                        self._headers["X-CSRF-Token"] = csrf
                    return True
            except httpx.RequestError:
                continue
        return False

    async def _get(self, path: str, client: httpx.AsyncClient) -> dict:
        r = await client.get(
            self._api(path),
            cookies=self._cookies,
            headers=self._headers,
            timeout=15,
        )
        r.raise_for_status()
        return r.json()

    async def list_sites(self, client: httpx.AsyncClient) -> list[dict]:
        """Return all sites visible to this user: [{name, desc, role, ...}].

        `name` is the internal site ID (what must go in the URL); `desc` is the
        human-readable display name shown in the UniFi UI.
        """
        r = await client.get(
            self._root_api("self/sites"),
            cookies=self._cookies,
            headers=self._headers,
            timeout=10,
        )
        r.raise_for_status()
        return r.json().get("data", [])

    async def _resolve_site(self, client: httpx.AsyncClient) -> None:
        """If the configured site value isn't a valid ID, try to match by
        display name (case-insensitive). Falls back to 'default'.

        Idempotent — only does work once per client lifetime.
        """
        if self._site_resolved:
            return
        try:
            sites = await self.list_sites(client)
        except Exception as e:
            log.debug("UniFi site list failed, using '%s' as-is: %s", self._site, self._safe_error(e))
            self._site_resolved = True
            return

        if not sites:
            self._site_resolved = True
            return

        ids = {s.get("name") for s in sites if s.get("name")}
        if self._site_configured in ids:
            self._site = self._site_configured
            self._site_resolved = True
            return

        # Try to match the configured value against display names
        want = (self._site_configured or "").strip().lower()
        for s in sites:
            if (s.get("desc") or "").strip().lower() == want:
                resolved = s.get("name")
                if resolved:
                    log.info(
                        "UniFi: resolved site display-name '%s' → id '%s'",
                        self._site_configured, resolved,
                    )
                    self._site = resolved
                    self._site_resolved = True
                    return

        # Nothing matched — fall back to the first site, or 'default'
        fallback = sites[0].get("name") or "default"
        log.warning(
            "UniFi: configured site '%s' not found (available: %s) — using '%s'",
            self._site_configured,
            [s.get("name") for s in sites],
            fallback,
        )
        self._site = fallback
        self._site_resolved = True

    async def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(verify=False, follow_redirects=True)

    async def test_connection(self) -> ConnectionResult:
        try:
            async with await self._client() as c:
                ok = await self._authenticate(c)
                if not ok:
                    return ConnectionResult.offline("Authentication failed")
                await self._resolve_site(c)
                data = await self._get("stat/health", c)
                return ConnectionResult.success(
                    f"UniFi {'UDM Pro' if self._is_udm else 'Classic'}",
                    site=self._site,
                )
        except Exception as e:
            return ConnectionResult.offline(self._safe_error(e))

    async def fetch_topology(self) -> UniFiTopology:
        try:
            async with await self._client() as c:
                if not await self._authenticate(c):
                    return UniFiTopology()
                await self._resolve_site(c)

                devices_data, clients_data = await asyncio.gather(
                    self._get("stat/device", c),
                    self._get("stat/sta", c),
                )

            devices = [_parse_device(d) for d in devices_data.get("data", [])]
            clients = [_parse_client(c) for c in clients_data.get("data", [])]
            return UniFiTopology(devices=devices, clients=clients)
        except Exception as e:
            log.warning("UniFi topology fetch failed: %s", self._safe_error(e))
            return UniFiTopology()

    async def fetch_device(self, mac: str) -> Optional[UniFiDevice]:
        try:
            async with await self._client() as c:
                if not await self._authenticate(c):
                    return None
                await self._resolve_site(c)
                data = await self._get(f"stat/device/{mac}", c)
                devices = data.get("data", [])
                if devices:
                    return _parse_device(devices[0])
        except Exception as e:
            log.warning("UniFi device fetch failed: %s", self._safe_error(e))
        return None


def _parse_device(d: dict) -> UniFiDevice:
    model = d.get("model", "")
    return UniFiDevice(
        mac=d.get("mac", ""),
        ip=d.get("ip"),
        name=d.get("name") or d.get("hostname"),
        model=model,
        device_type=_model_to_type(model),
        firmware=d.get("version", ""),
        uptime=d.get("uptime", 0),
        port_count=d.get("config_network", {}).get("type") and len(d.get("port_table", [])) or 0,
        uplink_mac=d.get("uplink", {}).get("uplink_mac"),
        clients=[c.get("mac", "") for c in d.get("sta_table", [])],
    )


def _parse_client(c: dict) -> UniFiClient:
    return UniFiClient(
        mac=c.get("mac", ""),
        ip=c.get("ip"),
        hostname=c.get("hostname"),
        ap_mac=c.get("ap_mac"),
        sw_mac=c.get("sw_mac"),
        sw_port=c.get("sw_port"),
        is_wired=c.get("is_wired", False),
        signal=c.get("signal"),
        tx_bytes=c.get("tx_bytes", 0),
        rx_bytes=c.get("rx_bytes", 0),
        uptime=c.get("uptime", 0),
        oui=c.get("oui"),
        name=c.get("name"),
    )


def _model_to_type(model: str) -> str:
    m = model.upper()
    if m.startswith("UDM") or m.startswith("USG") or m.startswith("UGW"):
        return "gateway"
    if m.startswith("USW") or m.startswith("US-"):
        return "switch"
    if m.startswith("UAP") or m.startswith("U6") or m.startswith("UAL"):
        return "ap"
    if m.startswith("UVC") or "CAM" in m or "G3" in m or "G4" in m or "G5" in m:
        if "DOORBELL" in m:
            return "doorbell"
        return "camera"
    return "unknown"
