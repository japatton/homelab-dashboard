"""Firewalla integration (MSP + local modes).

Firewalla sells a turnkey security gateway/firewall. What we harvest
is device inventory and security alarms — it's not a controller in
the UniFi sense, so we don't get L2 topology edges, but we do get:

  - A per-MAC device inventory with rich metadata (vendor, current
    IP, online state, last-seen timestamp)
  - An active-alarms feed covering intrusions, new-device joins,
    abnormal uploads/bandwidth, VPN events, etc.

Two modes, mutually exclusive (controlled by FirewallaConfig.mode):

  - **MSP** (default, supported): HTTPS → `https://<msp_domain>/v2/`
    authenticated with a Personal Access Token. Token generated in the
    MSP portal (Account Settings → Create New Token). Auth header is
    `Authorization: Token <pat>` (note: Token, not Bearer).

  - **Local** (best-effort, experimental): direct to the box on
    port 8833 using a fireguard token. The local API surface isn't
    officially documented by Firewalla; we expose enough of it to let
    users opt in but warn loudly in the Settings UI that it's
    best-effort. MSP is the recommended path.

### API quirks we handle

1. **No `severity` field on alarms.** Firewalla tags alarms with a
   numeric `type` code (1..16 documented). We map the most-common
   codes into our 5-level severity vocabulary and fall back to "info".

2. **`lastSeen` field type.** Documented as number on boxes and string
   on devices — we coerce at parse time.

3. **Box identifier is `gid` (UUID), not a MAC.** Devices carry a
   `gid` pointing back to their owning box so a single MSP tenant
   with multiple boxes still merges cleanly. We expose `gid` as the
   `source_label`-stable key so our alarm dedup can survive box names
   changing.

4. **Pagination on alarms/devices.** Cursor-based with `next_cursor`.
   We loop until exhausted OR a hard page cap (safety — don't let a
   pathological tenant with 50k alarms monopolise the poll budget).

References:
  - docs.firewalla.net (Getting Started, /v2/boxes, /v2/devices,
    /v2/alarms, data-models/alarm)
  - github.com/firewalla/msp-api-examples
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Literal, Optional

import httpx

from .base import BaseIntegration, ConnectionResult

log = logging.getLogger(__name__)


# Firewalla alarm `type` code → our severity vocabulary. Keys are the
# string form because that's what the API returns ("5", not 5). Any
# code not listed falls back to "info" — better to surface a low-
# confidence event than drop it silently.
_ALARM_TYPE_SEVERITY: dict[str, str] = {
    "1": "high",  # Security Activity
    "2": "medium",  # Abnormal Upload
    "3": "low",  # Large Bandwidth Usage
    "4": "low",  # Monthly Data Plan
    "5": "info",  # New Device
    "6": "info",  # Device Back Online
    "7": "info",  # Device Offline
    "8": "info",  # Video
    "9": "info",  # Gaming
    "10": "medium",  # Porn
    "11": "info",  # VPN Activity
    "12": "info",  # VPN Restored
    "13": "medium",  # VPN Error
    "14": "medium",  # Open Port
    "15": "high",  # Internet Connectivity
    "16": "low",  # Large Upload
}

# Human-readable labels for the same type codes — surfaced as the
# alarm category so the Security page can show "Security Activity"
# instead of an opaque "5".
_ALARM_TYPE_LABEL: dict[str, str] = {
    "1": "Security Activity",
    "2": "Abnormal Upload",
    "3": "Large Bandwidth Usage",
    "4": "Monthly Data Plan",
    "5": "New Device",
    "6": "Device Back Online",
    "7": "Device Offline",
    "8": "Video",
    "9": "Gaming",
    "10": "Porn",
    "11": "VPN Activity",
    "12": "VPN Restored",
    "13": "VPN Error",
    "14": "Open Port",
    "15": "Internet Connectivity",
    "16": "Large Upload",
}


def _type_to_severity(type_code) -> str:
    """Firewalla's `type` arrives as a string on most responses but
    occasionally as an int. Coerce + look up. Default "info"."""
    key = str(type_code).strip() if type_code is not None else ""
    return _ALARM_TYPE_SEVERITY.get(key, "info")


def _type_to_label(type_code) -> str:
    key = str(type_code).strip() if type_code is not None else ""
    return _ALARM_TYPE_LABEL.get(key, f"Type {key}" if key else "Unknown")


# ─── Dataclasses ──────────────────────────────────────────────────────


@dataclass
class FirewallaBox:
    """One Firewalla appliance."""

    gid: str  # UUID; primary key inside an MSP tenant
    name: str = ""
    model: str = ""
    online: bool = False
    version: str = ""
    location: str = ""
    # `lastSeen` is a unix-timestamp float — preserved as-is because
    # we present it as a relative "last seen 3m ago" string rather
    # than a full ISO timestamp. Downstream can convert on render.
    last_seen: Optional[float] = None
    public_ip: str = ""
    device_count: int = 0
    alarm_count: int = 0


@dataclass
class FirewallaDevice:
    """One LAN device as Firewalla sees it."""

    # The MAC address. Firewalla's `id` field IS the MAC (uppercase
    # with colons). We normalise to lowercase to match our devices
    # table's convention and avoid joining mismatches.
    mac: str
    ip: str = ""
    name: str = ""
    vendor: str = ""  # from macVendor
    online: bool = False
    gid: str = ""  # which box saw this device
    # Number or string in docs — coerced to float|None at parse time.
    last_seen: Optional[float] = None
    network_name: str = ""
    group_name: str = ""


@dataclass
class FirewallaAlarm:
    """Normalised alarm row, shaped to match the generic
    `AlarmInput` that alarm_service.upsert_alarms consumes."""

    fingerprint: str  # dedup key: gid|device|type|minute_bucket
    message: str
    severity: str  # our vocab: critical/high/medium/low/info
    category: str  # human label like "Security Activity"
    signature: str  # same as category — Firewalla doesn't
    # expose a distinct signature string;
    # kept separate so the GatewayAlarm
    # schema matches OPNsense's shape.
    src_ip: str = ""
    dst_ip: str = ""
    device_id: Optional[str] = None  # MAC if the alarm was scoped
    device_name: str = ""
    timestamp: Optional[str] = None  # ISO8601; best-effort from ts
    raw: dict = field(default_factory=dict)


@dataclass
class FirewallaSnapshot:
    """One poll cycle of data.

    `box_label` is a pretty string for UI display — "HomeLab Firewalla
    Gold" rather than the raw gid. We pick the first online box's
    name; if no boxes come back (shouldn't happen in practice), we
    fall back to "Firewalla".
    """

    boxes: list[FirewallaBox] = field(default_factory=list)
    devices: list[FirewallaDevice] = field(default_factory=list)
    alarms: list[FirewallaAlarm] = field(default_factory=list)
    box_label: str = ""


# ─── Integration class ────────────────────────────────────────────────


class FirewallaIntegration(BaseIntegration):
    """Read-only client over Firewalla's MSP (and optionally local) API.

    One instance handles one MSP tenant (which may front many boxes
    as a single logical Firewalla). Scope is read-only: we never
    create/delete/modify rules, alarms, or device settings. If an
    upstream integration (Claude) ever tried to issue a write call
    through us, it would fail at this class boundary — no POST/PATCH
    methods exist.
    """

    name = "firewalla"

    def __init__(
        self,
        mode: Literal["msp", "local"] = "msp",
        msp_domain: str = "",
        msp_token: str = "",
        local_url: str = "",
        local_token: str = "",
        verify_ssl: bool = False,
    ):
        self._mode = mode
        self._msp_domain = (msp_domain or "").strip().rstrip("/")
        self._msp_token = msp_token or ""
        self._local_url = (local_url or "").rstrip("/")
        self._local_token = local_token or ""
        self._verify_ssl = verify_ssl

    def is_configured(self) -> bool:
        """Cheap check that callers (scheduler) use before instantiating
        a client. Lets the poll job silent-skip an enabled-but-empty
        config without raising."""
        if self._mode == "msp":
            return bool(self._msp_domain and self._msp_token)
        return bool(self._local_url)

    # ── low-level helpers ────────────────────────────────────────────

    def _base_url(self) -> str:
        if self._mode == "msp":
            return f"https://{self._msp_domain}/v2"
        return f"{self._local_url}"

    def _headers(self) -> dict:
        """Firewalla's MSP API uses `Authorization: Token <pat>` —
        NOT `Bearer`. Getting this wrong returns a 401 with a
        deceptively generic error. The local API is less documented;
        we send the same shape as a best-effort and let the box reject
        it if it's wrong."""
        if self._mode == "msp" and self._msp_token:
            return {"Authorization": f"Token {self._msp_token}"}
        if self._mode == "local" and self._local_token:
            # Local-mode auth is undocumented; some community projects
            # use `Authorization: Token`, others use `X-Auth-Token`.
            # We send both to maximise compatibility.
            return {
                "Authorization": f"Token {self._local_token}",
                "X-Auth-Token": self._local_token,
            }
        return {}

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            verify=self._verify_ssl,
            headers=self._headers(),
            timeout=httpx.Timeout(15.0, connect=5.0),
            follow_redirects=True,
        )

    async def _get(
        self, client: httpx.AsyncClient, path: str, params: Optional[dict] = None
    ) -> dict | list:
        r = await client.get(
            f"{self._base_url()}/{path.lstrip('/')}", params=params or None
        )
        # Rate-limit graceful handling: if the server says we're going
        # too fast, log and return an empty result rather than raise.
        # Firewalla doesn't publish hard limits, but a 429 at any rate
        # is a signal to back off rather than retry-hammer.
        if r.status_code == 429:
            log.warning(
                "firewalla: rate-limited (429) on %s — skipping this fetch", path
            )
            return []
        r.raise_for_status()
        ct = r.headers.get("content-type", "")
        if "json" not in ct.lower():
            raise RuntimeError(f"non-JSON response from {path} ({ct})")
        return r.json()

    # ── public operations ────────────────────────────────────────────

    async def test_connection(self) -> ConnectionResult:
        """Ping /boxes (MSP) or the local equivalent and return box
        count + box names. The Settings UI shows this in the
        "Connected ✓" confirmation so the user sees what we can see.

        For local mode — which is experimental and endpoint-unstable —
        we accept a wider set of non-error responses as "success" than
        we would for MSP. The tradeoff: easier first-time setup at the
        cost of letting some misconfigured local setups look "OK"
        until the actual poll fires and fails. Acceptable; the poll
        job writes job-state errors that the UI surfaces separately.
        """
        if not self.is_configured():
            return ConnectionResult.offline(
                "Firewalla is not fully configured — fill in domain/token "
                "(MSP mode) or box URL (local mode)."
            )

        try:
            async with self._client() as c:
                if self._mode == "msp":
                    data = await self._get(c, "boxes")
                    if isinstance(data, dict):
                        # Some tenants return {results: [...]} wrappers.
                        boxes = data.get("results") or data.get("boxes") or []
                    else:
                        boxes = data
                    if not isinstance(boxes, list):
                        boxes = []
                    summary = [
                        {
                            "name": b.get("name") or "(unnamed)",
                            "model": b.get("model") or "",
                            "online": bool(b.get("online")),
                        }
                        for b in boxes
                        if isinstance(b, dict)
                    ][:5]
                    return ConnectionResult.success(
                        f"Found {len(boxes)} box{'es' if len(boxes) != 1 else ''}",
                        box_count=len(boxes),
                        boxes=summary,
                    )
                else:
                    # Local mode — the exact "list boxes" endpoint isn't
                    # documented for the box API. A plain GET on the
                    # base URL usually returns a status page; treat any
                    # 2xx as success and leave box details blank.
                    r = await c.get(self._base_url())
                    if r.status_code >= 400:
                        return ConnectionResult.offline(
                            f"Local box returned HTTP {r.status_code} — "
                            f"verify the URL and token."
                        )
                    return ConnectionResult.success(
                        "Local box reachable (best-effort — local API is experimental)",
                        box_count=1,
                        boxes=[],
                    )
        except httpx.HTTPStatusError as e:
            if e.response.status_code in (401, 403):
                return ConnectionResult.offline(
                    "Authentication failed — check the Personal Access Token "
                    "(MSP portal → Account Settings → Create New Token)."
                )
            return ConnectionResult.offline(
                f"HTTP {e.response.status_code} from Firewalla"
            )
        except httpx.ConnectError as e:
            return ConnectionResult.offline(
                f"Cannot reach Firewalla: {self._safe_error(e)}"
            )
        except Exception as e:
            return ConnectionResult.offline(self._safe_error(e))

    # ── MSP fetchers ─────────────────────────────────────────────────

    async def fetch_boxes(self, client: httpx.AsyncClient) -> list[FirewallaBox]:
        try:
            data = await self._get(client, "boxes")
        except Exception as e:
            log.debug("firewalla: fetch_boxes failed: %s", self._safe_error(e))
            return []
        rows = data.get("results") if isinstance(data, dict) else data
        if not isinstance(rows, list):
            return []
        out: list[FirewallaBox] = []
        for r in rows:
            if not isinstance(r, dict):
                continue
            gid = str(r.get("gid") or "").strip()
            if not gid:
                continue
            out.append(
                FirewallaBox(
                    gid=gid,
                    name=str(r.get("name") or "").strip(),
                    model=str(r.get("model") or "").strip(),
                    online=bool(r.get("online")),
                    version=str(r.get("version") or "").strip(),
                    location=str(r.get("location") or "").strip(),
                    last_seen=_coerce_float(r.get("lastSeen")),
                    public_ip=str(r.get("publicIP") or "").strip(),
                    device_count=int(r.get("deviceCount") or 0),
                    alarm_count=int(r.get("alarmCount") or 0),
                )
            )
        return out

    async def fetch_devices(self, client: httpx.AsyncClient) -> list[FirewallaDevice]:
        """GET /v2/devices. Returns every device across every box the
        token can see, flat. We walk pagination cursors until the
        server returns no more or we hit the page cap.

        Page cap = 10 × default limit = ~5000 devices. A homelab
        Firewalla should never hit that; this is purely a safety
        valve against a runaway tenant (e.g. MSP managing 100 boxes)
        where a single poll cycle could otherwise monopolise memory.
        """
        out: list[FirewallaDevice] = []
        cursor: Optional[str] = None
        page_cap = 10
        for _ in range(page_cap):
            params: dict = {"limit": 500}
            if cursor:
                params["cursor"] = cursor
            try:
                data = await self._get(client, "devices", params=params)
            except Exception as e:
                log.debug(
                    "firewalla: fetch_devices page failed: %s", self._safe_error(e)
                )
                break

            if isinstance(data, dict):
                rows = data.get("results") or data.get("devices") or []
                cursor = data.get("next_cursor") or data.get("cursor")
            else:
                rows = data
                cursor = None

            if not isinstance(rows, list):
                break

            for r in rows:
                if not isinstance(r, dict):
                    continue
                # Firewalla's device `id` is the MAC; normalise to lower.
                mac = str(r.get("id") or r.get("mac") or "").strip().lower()
                if not mac:
                    continue
                net = r.get("network") or {}
                grp = r.get("group") or {}
                out.append(
                    FirewallaDevice(
                        mac=mac,
                        ip=str(r.get("ip") or "").strip(),
                        name=str(r.get("name") or "").strip(),
                        vendor=str(r.get("macVendor") or r.get("vendor") or "").strip(),
                        online=bool(r.get("online")),
                        gid=str(r.get("gid") or "").strip(),
                        last_seen=_coerce_float(r.get("lastSeen")),
                        network_name=str(net.get("name") or "").strip()
                        if isinstance(net, dict)
                        else "",
                        group_name=str(grp.get("name") or "").strip()
                        if isinstance(grp, dict)
                        else "",
                    )
                )

            if not cursor:
                break
        return out

    async def fetch_alarms(self, client: httpx.AsyncClient) -> list[FirewallaAlarm]:
        """GET /v2/alarms?query=status:active. Returns active alarms
        across all boxes, cursor-paginated.

        We filter to `status:active` so dismissed/archived alarms
        don't re-enter our feed on every poll. The alarm service's
        own dedup (source+fingerprint) protects us if an alarm
        lingers across polls — count++ rather than duplicate.
        """
        out: list[FirewallaAlarm] = []
        cursor: Optional[str] = None
        page_cap = 5  # 5 × 200 = 1000 alarms per poll; plenty for a homelab
        for _ in range(page_cap):
            params: dict = {
                "query": "status:active",
                "limit": 200,
                "sortBy": "ts:desc",
            }
            if cursor:
                params["cursor"] = cursor
            try:
                data = await self._get(client, "alarms", params=params)
            except Exception as e:
                log.debug(
                    "firewalla: fetch_alarms page failed: %s", self._safe_error(e)
                )
                break

            if isinstance(data, dict):
                rows = data.get("results") or []
                cursor = data.get("next_cursor")
            else:
                rows = data
                cursor = None

            if not isinstance(rows, list):
                break

            for r in rows:
                if not isinstance(r, dict):
                    continue
                parsed = _parse_alarm(r)
                if parsed is not None:
                    out.append(parsed)

            if not cursor:
                break
        return out

    # ── snapshot ─────────────────────────────────────────────────────

    async def fetch_snapshot(self, with_alarms: bool = True) -> FirewallaSnapshot:
        """One-shot poll. Runs boxes/devices/alarms in parallel so a
        slow alarm page-walk doesn't serialise the whole cycle.

        If we're in local mode (experimental), only device
        enumeration is attempted; boxes and alarms return empty. The
        scheduler logs this as a degraded-but-running state.
        """
        if not self.is_configured():
            return FirewallaSnapshot()

        if self._mode != "msp":
            # Local-mode snapshot: we don't currently have a working
            # device list endpoint definition we trust, so we return
            # an empty snapshot. Users who set local mode will see a
            # "connected but 0 devices" state — intentional; the UI
            # tells them local is experimental.
            return FirewallaSnapshot()

        try:
            async with self._client() as c:
                alarm_task = self.fetch_alarms(c) if with_alarms else _empty_alarms()
                boxes, devices, alarms = await asyncio.gather(
                    self.fetch_boxes(c),
                    self.fetch_devices(c),
                    alarm_task,
                    return_exceptions=True,
                )

            boxes = boxes if isinstance(boxes, list) else []
            devices = devices if isinstance(devices, list) else []
            alarms = alarms if isinstance(alarms, list) else []

            # Pick a display label: first online box wins, else first
            # box regardless of state, else "Firewalla".
            box_label = "Firewalla"
            if boxes:
                online = next((b for b in boxes if b.online), None)
                chosen = online or boxes[0]
                if chosen.name:
                    box_label = chosen.name
                elif chosen.model:
                    box_label = f"Firewalla {chosen.model}"

            return FirewallaSnapshot(
                boxes=boxes,
                devices=devices,
                alarms=alarms,
                box_label=box_label,
            )
        except Exception as e:
            log.warning("firewalla: snapshot fetch failed: %s", self._safe_error(e))
            return FirewallaSnapshot()


# ─── Helpers ──────────────────────────────────────────────────────────


def _coerce_float(v) -> Optional[float]:
    """`lastSeen` arrives as int, float, or numeric string across
    different Firewalla endpoints. One normaliser keeps downstream
    code simple."""
    if v is None or v == "":
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _parse_alarm(r: dict) -> Optional[FirewallaAlarm]:
    """Flatten a raw Firewalla alarm dict into our dataclass.

    Returns None when the row is unusable (no message + no type
    code — nothing we could show the user). Also skips rows whose
    `status` isn't 'active' even though we already filtered the
    query: defence against the filter not being honoured on older
    MSP API versions.
    """
    status = str(r.get("status") or "").lower()
    if status and status != "active":
        return None

    type_code = r.get("type")
    message = str(r.get("message") or "").strip()
    if not message and type_code is None:
        return None

    label = _type_to_label(type_code)
    severity = _type_to_severity(type_code)

    device = r.get("device") if isinstance(r.get("device"), dict) else {}
    remote = r.get("remote") if isinstance(r.get("remote"), dict) else {}

    device_mac = (
        str(device.get("id") or device.get("mac") or "").strip().lower() or None
    )
    device_name = str(device.get("name") or "").strip()
    src_ip = str(device.get("ip") or "").strip()
    dst_ip = str(remote.get("ip") or remote.get("domain") or "").strip()

    gid = str(r.get("gid") or "").strip()
    ts = r.get("ts")
    ts_iso = ""
    ts_bucket = ""
    if ts:
        try:
            from datetime import datetime, timezone

            dt = datetime.fromtimestamp(float(ts), tz=timezone.utc)
            ts_iso = dt.isoformat()
            ts_bucket = ts_iso[:16]  # YYYY-MM-DDTHH:MM — 1-minute dedup window
        except (TypeError, ValueError, OSError):
            pass

    # Dedup key: same box + same device + same type inside a minute
    # bucket collapses to one alarm. Alarm storms (e.g. Open Port
    # firing on every handshake) are re-counted rather than re-listed.
    fingerprint = f"{gid}|{device_mac or ''}|{type_code}|{ts_bucket}"

    # If message is blank (rare but possible), synthesise one from
    # the label + device name so the Security page always has
    # something renderable.
    display_message = (
        message or f"{label}: {device_name or device_mac or 'unknown device'}"
    )

    return FirewallaAlarm(
        fingerprint=fingerprint,
        message=display_message,
        severity=severity,
        category=label,
        signature=label,
        src_ip=src_ip,
        dst_ip=dst_ip,
        device_id=device_mac,
        device_name=device_name,
        timestamp=ts_iso or None,
        raw={
            "aid": r.get("aid"),
            "type": type_code,
            "gid": gid,
            "direction": r.get("direction"),
            "protocol": r.get("protocol"),
            "transfer": r.get("transfer"),
            "ts": ts,
        },
    )


async def _empty_alarms() -> list[FirewallaAlarm]:
    """Placeholder coroutine mirroring opnsense._empty_alerts so the
    gather() shape stays uniform whether alarms are enabled or not."""
    return []
