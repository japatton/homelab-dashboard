"""OPNsense edge-gateway integration.

OPNsense is a pure firewall/gateway — not a full-stack controller like
UniFi. What we get from it is:

  - DHCP v4 leases  → authoritative host→MAC bindings, real hostnames
                      (the DHCP server issued them, so they're the truth
                      over whatever Nmap could reverse-DNS)
  - ARP table       → live L2 neighbor list; a cross-check for which
                      hosts are actually on-link right now
  - System info     → firmware version + hostname for the gateway card
  - Suricata alerts → optional, only if the IDS service is running
                      (guarded by OPNsenseConfig.ids_enabled)

All calls are HTTP Basic auth with an API key+secret pair the user
generates in OPNsense's UI (System → Access → Users → [user] → API
keys). The pair is a single credential — the key is the username slot
and the secret goes in the password slot.

### API quirks we handle

1. **ARP endpoint renamed in 25.7**: the legacy `getArp` alias was
   renamed to `get_arp`. Both work on >=25.7 when privileges are open,
   but if the user restricts the API key to "Diagnostics: ARP Table"
   only the snake_case form works. We call `get_arp` first and fall
   back to `getArp` on 404 so both old and new instances are covered.

2. **Response envelopes vary**: OPNsense's search endpoints return
   `{rows: [...], total, rowCount}` but the non-search endpoints return
   a plain list or a dict. We normalise at parse time — callers just
   get lists of dataclasses.

3. **Self-signed cert default**: most homelabs never replace
   OPNsense's self-signed cert, so `verify_ssl` defaults to False.
   We always set a hostname-indication-safe httpx client; when
   `verify_ssl=True` the user is expected to have a real cert.

4. **Hostnames from DHCP**: the DHCP lease `hostname` field is richer
   than Nmap's reverse DNS (which usually fails on IoT). We surface
   both `hostname` (DHCP-provided) and `descr` (user-set description
   in the static mappings table) so the merger can prefer the
   descr-over-hostname-over-nothing precedence.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Optional

import httpx

from .base import BaseIntegration, ConnectionResult

log = logging.getLogger(__name__)


# ─── Dataclasses ──────────────────────────────────────────────────────


@dataclass
class OPNsenseLease:
    """A single DHCPv4 lease, normalised from the search_lease response.

    Fields map 1:1 to the OPNsense response except that we coerce
    everything to str/None up front so the downstream merger never has
    to handle the "address" field being an int or the "state" field
    being a bool. DHCP responses are surprisingly inconsistent across
    OPNsense versions on that front.
    """

    address: str
    mac: str
    hostname: Optional[str] = None
    # `state` is OPNsense's lease-table status: "active" / "backup" /
    # "expired". Only "active" is interesting for live-device merging.
    state: str = ""
    # `status` duplicates state on older versions. Kept for parity
    # with the raw API response; never used for decisions.
    status: str = ""
    # `descr` is the user-entered description on static mappings —
    # often the nicest display name available (beats DHCP hostname
    # which tends to be "iPhone-von-Alex" garbage).
    description: str = ""
    # `if_descr` is the human-readable interface name ("LAN",
    # "IOT_VLAN"); `if` is the raw device ("em1", "vtnet0.20"). We
    # keep both for the UI.
    interface: str = ""
    interface_description: str = ""
    # Manufacturer lookup the firewall does against the OUI database.
    # Sometimes blank, sometimes wrong — don't trust it as primary
    # identity, but it's better than nothing when all we have is a MAC.
    manufacturer: str = ""


@dataclass
class OPNsenseArpEntry:
    """A single ARP table row.

    The raw response keys are not fully stable across OPNsense
    versions (some return `mac` / `ip`, others `mac_address` /
    `ip_address`), so we normalise at parse time.
    """

    mac: str
    ip: str
    hostname: Optional[str] = None
    interface: str = ""
    # `permanent` / `expired` flags — useful for sanity-checking when
    # a device is bouncing between online/offline.
    permanent: bool = False
    expired: bool = False


@dataclass
class OPNsenseAlert:
    """A single Suricata IDS alert — shaped to match the generic
    GatewayAlarm that the alarm service upserts. We do the mapping to
    the generic shape in the poller rather than here so the integration
    layer stays source-faithful.
    """

    timestamp: str  # ISO8601; best-effort parsed from raw
    src_ip: str
    dst_ip: str
    signature: str
    severity: int  # 1 (critical) … 3 (informational) per Suricata
    category: str = ""
    protocol: str = ""
    # Opaque fingerprint for dedup — we build it from src+dst+sig+minute
    # to collapse alert storms without hiding distinct events. The alarm
    # service uses this as the dedup key.
    fingerprint: str = ""


@dataclass
class OPNsenseSystemInfo:
    """High-level box info shown on the gateway card."""

    hostname: str = ""
    version: str = ""
    # `name` is what OPNsense calls the pretty product string
    # ("OPNsense 24.7.4-amd64"). We keep both so the UI can show
    # "OPNsense 24.7.4" even when `version` alone is "24.7.4".
    product: str = ""


@dataclass
class OPNsenseSnapshot:
    """One poll cycle's worth of data. Passed whole into the merger so
    we get atomic updates — a half-updated state (leases refreshed but
    ARP not) is worse than a slightly stale consistent view."""

    leases: list[OPNsenseLease] = field(default_factory=list)
    arp: list[OPNsenseArpEntry] = field(default_factory=list)
    alerts: list[OPNsenseAlert] = field(default_factory=list)
    system: Optional[OPNsenseSystemInfo] = None


# ─── Integration class ────────────────────────────────────────────────


class OPNsenseIntegration(BaseIntegration):
    """Thin async client over OPNsense's REST API.

    One instance = one OPNsense firewall. Scope is intentionally
    narrow: we don't expose rule-editing, reboot-the-box, or anything
    that could be misused via prompt injection upstream. All methods
    are read-only.
    """

    name = "opnsense"

    def __init__(
        self,
        url: str,
        api_key: str,
        api_secret: str,
        verify_ssl: bool = False,
        ids_enabled: bool = False,
    ):
        self._url = url.rstrip("/") if url else ""
        self._api_key = api_key or ""
        self._api_secret = api_secret or ""
        self._verify_ssl = verify_ssl
        self._ids_enabled = ids_enabled

    # ── low-level helpers ────────────────────────────────────────────

    def _client(self) -> httpx.AsyncClient:
        """Fresh client per call to avoid cross-request cookie/state
        leakage. OPNsense is stateless under Basic auth so there's no
        benefit to keeping one around.
        """
        return httpx.AsyncClient(
            verify=self._verify_ssl,
            auth=(self._api_key, self._api_secret),
            timeout=httpx.Timeout(10.0, connect=5.0),
            follow_redirects=True,
        )

    async def _get(self, client: httpx.AsyncClient, path: str) -> dict:
        r = await client.get(f"{self._url}/api/{path.lstrip('/')}")
        r.raise_for_status()
        # Defensive: OPNsense occasionally returns text/html on 500-class
        # proxy errors. Force-JSON only when the content-type matches.
        ct = r.headers.get("content-type", "")
        if "json" not in ct.lower():
            raise RuntimeError(f"non-JSON response from {path} ({ct})")
        return r.json()

    async def _post(self, client: httpx.AsyncClient, path: str, body: dict) -> dict:
        r = await client.post(
            f"{self._url}/api/{path.lstrip('/')}",
            json=body,
        )
        r.raise_for_status()
        return r.json()

    # ── public operations ────────────────────────────────────────────

    async def test_connection(self) -> ConnectionResult:
        """Hit a cheap, always-available endpoint (firmware/status) and
        return both ok/notok AND a detail payload the UI can render
        for a friendly confirmation ("OPNsense 24.7.4 · hostname=fw01")."""
        if not self._url or not self._api_key or not self._api_secret:
            return ConnectionResult.offline(
                "URL, API key, and API secret are all required"
            )
        try:
            async with self._client() as c:
                data = await self._get(c, "core/firmware/status")
                # Secondary call for hostname + version — nice-to-have but
                # not strictly required; if it fails we still consider
                # the connection OK.
                try:
                    sysinfo = await self._get(
                        c, "diagnostics/system/system_information"
                    )
                    hostname = sysinfo.get("name") or sysinfo.get("hostname") or ""
                    version = (
                        sysinfo.get("versions", {}).get("product_version")
                        or sysinfo.get("version")
                        or ""
                    )
                except Exception as sysinfo_err:
                    # Optional endpoint — older firmware (pre-21.x) returns
                    # 404 here. The primary probe already succeeded, so we
                    # downgrade to a debug log rather than fail the test.
                    log.debug(
                        "opnsense sysinfo lookup failed (non-fatal): %s", sysinfo_err
                    )
                    hostname = ""
                    version = ""
                product_name = data.get("product_name") or "OPNsense"
                product_version = (
                    data.get("product_version")
                    or version
                    or data.get("product", {}).get("product_version", "")
                )
                return ConnectionResult.success(
                    f"{product_name} {product_version}".strip(),
                    hostname=hostname,
                    version=product_version,
                    product=product_name,
                )
        except httpx.HTTPStatusError as e:
            if e.response.status_code in (401, 403):
                return ConnectionResult.offline(
                    "Authentication failed — check the API key and secret "
                    "(System → Access → Users → [user] → API keys)."
                )
            return ConnectionResult.offline(
                f"HTTP {e.response.status_code} from firewall"
            )
        except httpx.ConnectError as e:
            return ConnectionResult.offline(
                f"Cannot reach firewall: {self._safe_error(e)}"
            )
        except Exception as e:
            return ConnectionResult.offline(self._safe_error(e))

    async def fetch_leases(self, client: httpx.AsyncClient) -> list[OPNsenseLease]:
        """GET /api/dhcpv4/leases/search_lease

        Response envelope is `{total, rowCount, current, rows: [...]}`.
        Each row has (at minimum): address, mac, hostname, starts,
        ends, state, status, if, if_descr, descr, man. Fields may be
        null/missing on older versions — we coerce everything via .get().
        """
        try:
            data = await self._get(client, "dhcpv4/leases/search_lease")
        except httpx.HTTPStatusError as e:
            # On some OPNsense versions the ISC DHCP service is disabled
            # in favor of KEA. The KEA leases endpoint lives at a
            # different path; we fall back here. 404 is the normal
            # "endpoint doesn't exist" signal on older versions.
            if e.response.status_code == 404:
                try:
                    data = await self._get(client, "kea/leases4/search")
                except Exception:
                    log.info(
                        "opnsense: neither dhcpv4 nor kea lease endpoints "
                        "responded — is the DHCP service configured?"
                    )
                    return []
            else:
                raise

        rows = data.get("rows") if isinstance(data, dict) else data
        if not isinstance(rows, list):
            return []

        out: list[OPNsenseLease] = []
        for r in rows:
            if not isinstance(r, dict):
                continue
            mac = (r.get("mac") or r.get("hwaddr") or "").strip().lower()
            address = (
                r.get("address") or r.get("ip_address") or r.get("ip") or ""
            ).strip()
            if not mac or not address:
                # Without both we can't key a device; skip rather than
                # creating half-useful rows that'd confuse the merger.
                continue
            out.append(
                OPNsenseLease(
                    address=address,
                    mac=mac,
                    hostname=(r.get("hostname") or "").strip() or None,
                    state=(r.get("state") or "").strip(),
                    status=(r.get("status") or "").strip(),
                    description=(r.get("descr") or r.get("description") or "").strip(),
                    interface=(r.get("if") or r.get("interface") or "").strip(),
                    interface_description=(
                        r.get("if_descr") or r.get("interface_description") or ""
                    ).strip(),
                    manufacturer=(r.get("man") or r.get("manufacturer") or "").strip(),
                )
            )
        return out

    async def fetch_arp(self, client: httpx.AsyncClient) -> list[OPNsenseArpEntry]:
        """GET /api/diagnostics/interface/get_arp (25.7+) with a
        getArp fallback for pre-25.7 boxes. Output is normalised to a
        list of dataclasses so callers don't have to care which shape
        OPNsense returned.
        """
        raw: object = None
        for path in ("diagnostics/interface/get_arp", "diagnostics/interface/getArp"):
            try:
                raw = await self._get(client, path)
                break
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 404:
                    continue
                raise
        if raw is None:
            log.warning("opnsense: no ARP endpoint responded (tried get_arp + getArp)")
            return []

        # Either endpoint historically returns a bare list; recent
        # versions may wrap in {rows: [...]}. Handle both.
        rows = raw.get("rows") if isinstance(raw, dict) else raw
        if not isinstance(rows, list):
            return []

        out: list[OPNsenseArpEntry] = []
        for r in rows:
            if not isinstance(r, dict):
                continue
            mac = (r.get("mac") or r.get("mac_address") or "").strip().lower()
            ip = (r.get("ip") or r.get("ip_address") or "").strip()
            if not mac or not ip:
                continue
            # OPNsense returns these as strings "yes"/"no" on some
            # versions and booleans on others. Defensive coercion.
            perm = r.get("permanent") or r.get("is_permanent")
            exp = r.get("expired") or r.get("is_expired")
            out.append(
                OPNsenseArpEntry(
                    mac=mac,
                    ip=ip,
                    hostname=(r.get("hostname") or "").strip() or None,
                    interface=(
                        r.get("intf") or r.get("interface") or r.get("if_descr") or ""
                    ).strip(),
                    permanent=(str(perm).lower() in ("yes", "true", "1")),
                    expired=(str(exp).lower() in ("yes", "true", "1")),
                )
            )
        return out

    async def fetch_system_info(
        self, client: httpx.AsyncClient
    ) -> Optional[OPNsenseSystemInfo]:
        """GET /api/diagnostics/system/system_information

        Best-effort — this endpoint changed shape between 22.x and
        24.x. We extract what we can and leave the rest blank; the
        poller doesn't fail if this returns nothing.
        """
        try:
            data = await self._get(client, "diagnostics/system/system_information")
        except Exception as e:
            log.debug(
                "opnsense: system_information fetch failed: %s", self._safe_error(e)
            )
            return None

        hostname = (data.get("name") or data.get("hostname") or "").strip()
        versions = (
            data.get("versions") if isinstance(data.get("versions"), dict) else {}
        )
        version = (
            (versions.get("product_version") if versions else None)
            or data.get("version")
            or ""
        )
        product = (
            (versions.get("product") if versions else None)
            or data.get("product_name")
            or "OPNsense"
        )
        return OPNsenseSystemInfo(
            hostname=hostname,
            version=str(version).strip(),
            product=str(product).strip(),
        )

    async def fetch_alerts(
        self, client: httpx.AsyncClient, limit: int = 100
    ) -> list[OPNsenseAlert]:
        """POST /api/ids/service/query_alerts — Suricata alert log.

        Only called when `ids_enabled=True` in config because the
        query is expensive (reads from the disk-backed alert log) and
        returns empty on boxes where Suricata isn't installed.

        The alert log schema ALSO varies between OPNsense versions;
        the shape here is based on 24.7 which wraps alerts in a
        `{rows: [...]}` envelope with each row having a raw
        `eve`-style JSON string under `_source` or similar. We defend
        against missing fields at every level.
        """
        if not self._ids_enabled:
            return []

        try:
            data = await self._post(
                client,
                "ids/service/query_alerts",
                {
                    "current": 1,
                    "rowCount": limit,
                    # Descending so newest come first; the alarm service
                    # handles dedup independently of arrival order.
                    "sort": {"timestamp": "desc"},
                },
            )
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                # IDS plugin not installed; not an error from our
                # perspective — just nothing to fetch.
                return []
            log.debug(
                "opnsense: IDS alert fetch failed: HTTP %d", e.response.status_code
            )
            return []
        except Exception as e:
            log.debug("opnsense: IDS alert fetch failed: %s", self._safe_error(e))
            return []

        rows = data.get("rows") if isinstance(data, dict) else data
        if not isinstance(rows, list):
            return []

        out: list[OPNsenseAlert] = []
        for r in rows:
            if not isinstance(r, dict):
                continue
            # `r` is either an already-flattened dict or a wrapper with
            # the actual eve.json payload nested under `_source`.
            src = r.get("_source") if isinstance(r.get("_source"), dict) else r
            alert = src.get("alert") if isinstance(src.get("alert"), dict) else {}
            ts = str(src.get("timestamp") or r.get("timestamp") or "")
            src_ip = str(src.get("src_ip") or src.get("src") or "").strip()
            dst_ip = str(src.get("dest_ip") or src.get("dst") or "").strip()
            signature = str(
                alert.get("signature") or src.get("signature") or ""
            ).strip()
            severity = int(alert.get("severity") or src.get("severity") or 3)
            category = str(alert.get("category") or src.get("category") or "").strip()
            protocol = str(src.get("proto") or src.get("protocol") or "").strip()
            # Skip empty signatures — those are usually noise from
            # flow-logging rules that aren't actual alerts.
            if not signature:
                continue
            # Dedup fingerprint: same src+dst+sig inside a 1-minute
            # bucket collapses to one alarm. The alarm service treats
            # identical fingerprints as updates, not new events.
            ts_bucket = ts[:16]  # YYYY-MM-DDTHH:MM
            fingerprint = f"{src_ip}|{dst_ip}|{signature}|{ts_bucket}"
            out.append(
                OPNsenseAlert(
                    timestamp=ts,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    signature=signature,
                    severity=severity,
                    category=category,
                    protocol=protocol,
                    fingerprint=fingerprint,
                )
            )
        return out

    async def fetch_snapshot(self) -> OPNsenseSnapshot:
        """One-shot poll. Runs lease/arp/system/alerts in parallel so
        a slow IDS log query doesn't serialise the whole cycle.
        """
        try:
            async with self._client() as c:
                leases, arp, system, alerts = await asyncio.gather(
                    self.fetch_leases(c),
                    self.fetch_arp(c),
                    self.fetch_system_info(c),
                    self.fetch_alerts(c) if self._ids_enabled else _empty_alerts(),
                    return_exceptions=True,
                )
            # gather(return_exceptions=True) means each element is
            # either a result or an Exception. Downgrade exceptions to
            # empty results + a warning so one subsystem outage can't
            # kill the whole poll.
            leases = leases if isinstance(leases, list) else []
            arp = arp if isinstance(arp, list) else []
            system = system if isinstance(system, OPNsenseSystemInfo) else None
            alerts = alerts if isinstance(alerts, list) else []
            return OPNsenseSnapshot(
                leases=leases,
                arp=arp,
                alerts=alerts,
                system=system,
            )
        except Exception as e:
            log.warning("opnsense: snapshot fetch failed: %s", self._safe_error(e))
            return OPNsenseSnapshot()


async def _empty_alerts() -> list[OPNsenseAlert]:
    """Placeholder coroutine so asyncio.gather always has a callable to
    schedule even when IDS alerts are disabled. Avoids a conditional
    gather and keeps the parallel-fetch shape uniform."""
    return []
