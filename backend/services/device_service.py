from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from database import get_db
from models.device import Device, DeviceService, DeviceType, VulnSummary
from models.scan import NmapResult, NmapHost

log = logging.getLogger(__name__)

# Ports that strongly suggest a specific device type
_PORT_TYPE_MAP: dict[int, str] = {
    554:  "camera",   # RTSP
    8554: "camera",
    7080: "camera",   # UniFi Protect camera HTTP
    2323: "camera",
    179:  "gateway",  # BGP
    520:  "gateway",  # RIP
    1194: "gateway",  # OpenVPN
    3000: "server",
    8080: "server",
    8443: "server",
    9000: "server",
    5000: "server",
    2375: "server",   # Docker
    2376: "server",
}

_SERVICE_LAUNCH_PORTS = {
    80: "http", 443: "https", 8080: "http", 8443: "https",
    8888: "http", 3000: "http", 5000: "http", 9000: "http", 9090: "http",
    9443: "https",
}


def _classify_from_nmap(host: NmapHost) -> tuple[DeviceType, float]:
    """Return (device_type, confidence) from nmap host data."""
    open_ports = {p.port for p in host.ports}
    services = {p.port: p.service for p in host.ports}
    os = (host.os_guess or "").lower()

    # Camera signals
    if open_ports & {554, 8554, 7080, 2323}:
        return "camera", 0.85

    # Gateway signals
    if open_ports & {179, 520} or ("router" in os or "gateway" in os):
        return "gateway", 0.8

    # Server signals
    if open_ports & {2375, 2376}:  # Docker
        return "server", 0.9
    if open_ports & {22} and open_ports & {80, 443, 8080, 8443, 3000, 5000}:
        return "server", 0.75

    # Windows workstation
    if open_ports & {135, 139, 445} and "windows" in os:
        return "workstation", 0.8

    # IoT / smart device — common ports with no SSH
    if open_ports and 22 not in open_ports and open_ports & {80, 443, 1883, 8883, 5683}:
        return "iot", 0.5

    # Laptop/phone heuristic — few open ports, probably a client device
    if len(open_ports) == 0:
        return "unknown", 0.0

    if len(open_ports) <= 2 and open_ports & {22, 5900}:
        return "laptop", 0.5

    return "unknown", 0.0


def _build_services(host: NmapHost) -> list[DeviceService]:
    services = []
    for p in host.ports:
        launch_url = None
        if p.port in _SERVICE_LAUNCH_PORTS:
            scheme = _SERVICE_LAUNCH_PORTS[p.port]
            launch_url = f"{scheme}://{host.ip}:{p.port}" if p.port not in (80, 443) else f"{scheme}://{host.ip}"
        services.append(DeviceService(
            port=p.port,
            protocol=p.protocol,
            name=p.service or "unknown",
            version=p.version,
            launch_url=launch_url,
        ))
    return services


def _device_id_from_mac(mac: Optional[str], ip: Optional[str]) -> str:
    if mac:
        return f"dev-{mac.replace(':', '').lower()}"
    if ip:
        return f"dev-ip-{ip.replace('.', '-')}"
    return f"dev-{uuid.uuid4().hex[:8]}"


async def merge_nmap_result(result: NmapResult) -> list[Device]:
    """Upsert devices from a Nmap scan result. Returns updated Device list."""
    updated: list[Device] = []
    now = datetime.now(timezone.utc).isoformat()

    async with get_db() as db:
        for host in result.hosts:
            device_id = _device_id_from_mac(host.mac, host.ip)
            device_type, confidence = _classify_from_nmap(host)
            services = _build_services(host)
            metadata = {}
            if host.os_guess:
                metadata["os_guess"] = host.os_guess
            meta_json = json.dumps(metadata)

            # Check if device exists
            row = await (await db.execute(
                "SELECT id, position_x, position_y, label FROM devices WHERE id = ?",
                (device_id,)
            )).fetchone()

            if row:
                await db.execute(
                    """UPDATE devices SET ip=?, mac=?, hostname=?, device_type=?,
                       confidence=?, metadata=?, is_online=1, last_seen=?
                       WHERE id=?""",
                    (host.ip, host.mac, host.hostname, device_type,
                     confidence, meta_json, now, device_id),
                )
            else:
                await db.execute(
                    """INSERT INTO devices
                       (id, mac, ip, hostname, device_type, confidence, metadata,
                        is_online, first_seen, last_seen)
                       VALUES (?,?,?,?,?,?,?,1,?,?)""",
                    (device_id, host.mac, host.ip, host.hostname,
                     device_type, confidence, meta_json, now, now),
                )

            # Persist services — replace the full set for this device.
            await _replace_services(db, device_id, services, now)

            await db.commit()

            updated.append(Device(
                id=device_id,
                mac=host.mac,
                ip=host.ip,
                hostname=host.hostname,
                device_type=device_type,  # type: ignore[arg-type]
                status="online",
                confidence=confidence,
                services=services,
                metadata=metadata,
                is_online=True,
                last_seen=datetime.fromisoformat(now),
            ))

    return updated


async def _replace_services(db, device_id: str, services: list[DeviceService], now: str) -> None:
    """Wipe and re-insert the service set for one device."""
    await db.execute("DELETE FROM device_services WHERE device_id = ?", (device_id,))
    for s in services:
        await db.execute(
            """INSERT INTO device_services
               (device_id, port, protocol, name, version, launch_url, updated_at)
               VALUES (?,?,?,?,?,?,?)""",
            (device_id, s.port, s.protocol, s.name, s.version, s.launch_url, now),
        )


async def _load_services_for_device(db, device_id: str) -> list[DeviceService]:
    cursor = await db.execute(
        """SELECT port, protocol, name, version, launch_url
           FROM device_services WHERE device_id = ?
           ORDER BY port""",
        (device_id,),
    )
    rows = await cursor.fetchall()
    return [
        DeviceService(
            port=r["port"],
            protocol=r["protocol"],
            name=r["name"] or "unknown",
            version=r["version"] or "",
            launch_url=r["launch_url"],
        )
        for r in rows
    ]


async def merge_unifi_topology(topology) -> list[Device]:
    """Upsert UniFi-managed devices. Returns updated list."""
    from integrations.unifi import UniFiTopology, UniFiDevice, UniFiClient

    updated: list[Device] = []
    now = datetime.now(timezone.utc).isoformat()

    async with get_db() as db:
        for dev in topology.devices:
            device_id = _device_id_from_mac(dev.mac, dev.ip)
            metadata = {
                "model": dev.model,
                "firmware": dev.firmware,
                "unifi_managed": True,
                "port_count": dev.port_count,
            }
            meta_json = json.dumps(metadata)

            row = await (await db.execute(
                "SELECT id FROM devices WHERE id = ?", (device_id,)
            )).fetchone()

            if row:
                await db.execute(
                    """UPDATE devices SET ip=?, mac=?, hostname=?, device_type=?,
                       confidence=1.0, metadata=?, is_online=1, last_seen=?
                       WHERE id=?""",
                    (dev.ip, dev.mac, dev.name, dev.device_type, meta_json, now, device_id),
                )
            else:
                await db.execute(
                    """INSERT INTO devices
                       (id, mac, ip, hostname, device_type, confidence, metadata,
                        is_online, first_seen, last_seen)
                       VALUES (?,?,?,?,?,1.0,?,1,?,?)""",
                    (device_id, dev.mac, dev.ip, dev.name,
                     dev.device_type, meta_json, now, now),
                )

        # Mark UniFi clients as online
        for client in topology.clients:
            cid = _device_id_from_mac(client.mac, client.ip)
            row = await (await db.execute(
                "SELECT id FROM devices WHERE id = ?", (cid,)
            )).fetchone()
            if row:
                await db.execute(
                    "UPDATE devices SET ip=?, hostname=?, is_online=1, last_seen=? WHERE id=?",
                    (client.ip, client.hostname, now, cid),
                )
            else:
                meta = json.dumps({"oui": client.oui, "is_wired": client.is_wired})
                await db.execute(
                    """INSERT OR IGNORE INTO devices
                       (id, mac, ip, hostname, device_type, confidence, metadata,
                        is_online, first_seen, last_seen)
                       VALUES (?,?,?,?,'unknown',0.0,?,1,?,?)""",
                    (cid, client.mac, client.ip, client.hostname, meta, now, now),
                )

        await db.commit()

    return await get_all_devices()


async def merge_gateway_leases(
    *,
    source: str,
    source_label: str,
    leases: list,
    arp: list | None = None,
) -> list[Device]:
    """Merge DHCP + ARP data from an edge-gateway integration (OPNsense,
    pfSense-compatible future additions) into the devices table.

    Precedence rules the merger obeys:

    1. **MAC is always the identity key** — same as every other
       integration. _device_id_from_mac() handles the collision.
    2. **Do NOT overwrite authoritative fields from higher-confidence
       sources.** UniFi upserts with confidence=1.0; a lease should
       never downgrade those devices' device_type or hostname. We
       check current confidence before writing device_type.
    3. **DHCP hostname + description beat Nmap reverse-DNS.** If the
       lease has a non-empty hostname or description, upsert it as
       the hostname. Description wins over hostname when both exist
       (user-set static names are the most human-curated value
       anywhere in the stack).
    4. **We mark online=True on observation but NEVER online=False.**
       Gateways can't authoritatively say "offline" — ARP timeout and
       DHCP-lease expiry are noisy signals. Nmap + UniFi own online
       state transitions; we only report on positive sightings.
    5. **Metadata is merged, not replaced.** A key like `opnsense_lease`
       is tucked into the existing metadata JSON so we don't clobber
       `model` / `firmware` / `unifi_managed` that UniFi wrote.

    Arguments:
        source: short slug ("opnsense" / "firewalla") stored in
            metadata for provenance chips on the device detail page.
        source_label: human label ("OPNsense 24.7") shown in UI.
        leases: list of objects with .address, .mac, .hostname,
            .description, .state, .interface, .interface_description,
            .manufacturer (OPNsenseLease-shaped; duck-typed).
        arp: optional list with .mac, .ip, .hostname, .interface —
            used to catch hosts that have an ARP entry but no active
            lease (static configs).
    """
    if not leases and not arp:
        return await get_all_devices()

    now = datetime.now(timezone.utc).isoformat()
    # Build a MAC→lease map first so arp-only MACs don't overwrite
    # richer lease data when we process them afterwards.
    by_mac: dict[str, dict] = {}
    for lease in leases or []:
        mac = (getattr(lease, "mac", "") or "").lower()
        if not mac:
            continue
        # Prefer description ("Alex's iPad") over hostname
        # ("iPhone-von-Alex" auto-generated) when both are set.
        hostname = (
            getattr(lease, "description", None)
            or getattr(lease, "hostname", None)
            or None
        )
        by_mac[mac] = {
            "ip": getattr(lease, "address", None),
            "hostname": hostname,
            "state": getattr(lease, "state", "") or "",
            "interface": getattr(lease, "interface", "") or "",
            "interface_description": getattr(lease, "interface_description", "") or "",
            "manufacturer": getattr(lease, "manufacturer", "") or "",
            "origin": "dhcp",
        }
    for entry in arp or []:
        mac = (getattr(entry, "mac", "") or "").lower()
        if not mac:
            continue
        # If we already have this MAC from a lease, only fill in
        # missing fields from ARP — never overwrite DHCP data.
        slot = by_mac.setdefault(mac, {
            "ip": getattr(entry, "ip", None),
            "hostname": None,
            "state": "",
            "interface": getattr(entry, "interface", "") or "",
            "interface_description": "",
            "manufacturer": "",
            "origin": "arp",
        })
        if not slot.get("ip"):
            slot["ip"] = getattr(entry, "ip", None)
        if not slot.get("hostname") and getattr(entry, "hostname", None):
            slot["hostname"] = getattr(entry, "hostname")
        if not slot.get("interface") and getattr(entry, "interface", None):
            slot["interface"] = getattr(entry, "interface")

    async with get_db() as db:
        for mac, info in by_mac.items():
            device_id = _device_id_from_mac(mac, info.get("ip"))

            # Read existing row so we can honour the precedence rules.
            row = await (await db.execute(
                "SELECT id, hostname, device_type, confidence, metadata "
                "FROM devices WHERE id = ?", (device_id,)
            )).fetchone()

            # Merge metadata: keep whatever was there, add our chunk.
            existing_meta: dict = {}
            if row and row["metadata"]:
                try:
                    existing_meta = json.loads(row["metadata"])
                except Exception:
                    existing_meta = {}
            gw_meta = existing_meta.get(f"{source}_gateway", {})
            gw_meta.update({
                "source_label": source_label,
                "interface": info["interface"],
                "interface_description": info["interface_description"],
                "manufacturer": info["manufacturer"],
                "state": info["state"],
                "origin": info["origin"],
            })
            existing_meta[f"{source}_gateway"] = gw_meta
            # Provenance chips list: union of sources the device has
            # ever been seen from. Purely for the device-detail UI.
            sources = set(existing_meta.get("seen_by", []))
            sources.add(source)
            existing_meta["seen_by"] = sorted(sources)
            meta_json = json.dumps(existing_meta)

            # Choose the hostname we commit: never downgrade an
            # existing non-empty value with a blank one.
            hostname_to_write = info.get("hostname")
            if row and row["hostname"] and not hostname_to_write:
                hostname_to_write = row["hostname"]

            if row:
                # UPDATE path — the NULL-coalesce guards protect
                # against the lease reporting less data than we
                # already stored. We also leave device_type alone;
                # it's someone else's authority.
                await db.execute(
                    """UPDATE devices
                       SET ip       = COALESCE(?, ip),
                           hostname = COALESCE(?, hostname),
                           metadata = ?,
                           is_online = 1,
                           last_seen = ?
                       WHERE id = ?""",
                    (info.get("ip"), hostname_to_write, meta_json, now, device_id),
                )
            else:
                # INSERT path — brand new device. device_type stays
                # "unknown" with confidence 0.2 (low because we only
                # saw a MAC, no port/service fingerprint), leaving
                # room for Nmap/UniFi to overwrite later.
                await db.execute(
                    """INSERT INTO devices
                       (id, mac, ip, hostname, device_type, confidence, metadata,
                        is_online, first_seen, last_seen)
                       VALUES (?, ?, ?, ?, 'unknown', 0.2, ?, 1, ?, ?)""",
                    (device_id, mac, info.get("ip"), hostname_to_write, meta_json, now, now),
                )
        await db.commit()

    return await get_all_devices()


async def merge_firewalla_devices(
    *,
    source_label: str,
    devices: list,
) -> list[Device]:
    """Merge Firewalla-sourced device inventory into the devices table.

    Firewalla speaks a richer shape than DHCP leases (vendor metadata,
    authoritative last-seen, authoritative online bool), but the same
    precedence rules as merge_gateway_leases apply:

    1. **MAC is identity.** Devices are keyed off MAC.
    2. **Do not downgrade higher-confidence sources.** UniFi
       (confidence=1.0) wins — we never overwrite device_type or
       lower a higher-confidence row here.
    3. **Hostnames:** Firewalla's `name` is user-editable in the
       Firewalla app and is usually high-quality. Prefer it over a
       Nmap reverse-DNS, but never overwrite a non-empty existing
       hostname with a blank one.
    4. **Online state:** Firewalla HAS authoritative online/offline
       (the agent on the box sees L2 in real time), but we still
       only flip devices to online=True here. Online→offline is
       owned by the Nmap+UniFi side to avoid thrash when one source
       sees a device and the other doesn't.
    5. **Metadata merged under `firewalla_gateway`** so we don't
       clobber keys owned by OPNsense, UniFi, or Nmap.

    Arguments:
        source_label: human label ("My Firewalla Gold") shown in UI.
        devices: list of FirewallaDevice-like objects (duck-typed:
            .mac, .ip, .name, .vendor, .online, .gid, .last_seen,
            .network_name, .group_name).
    """
    if not devices:
        return await get_all_devices()

    now = datetime.now(timezone.utc).isoformat()
    source = "firewalla"

    async with get_db() as db:
        for d in devices:
            mac = (getattr(d, "mac", "") or "").lower()
            if not mac:
                continue
            ip = (getattr(d, "ip", "") or "").strip() or None
            name = (getattr(d, "name", "") or "").strip() or None
            vendor = (getattr(d, "vendor", "") or "").strip()
            gid = (getattr(d, "gid", "") or "").strip()
            network_name = (getattr(d, "network_name", "") or "").strip()
            group_name = (getattr(d, "group_name", "") or "").strip()
            # Firewalla's `online` is trusted for positive transitions
            # only — a False here still commits is_online=1 because we
            # don't want a transient Firewalla miss to flip Nmap's view.
            online = bool(getattr(d, "online", False))

            device_id = _device_id_from_mac(mac, ip)

            row = await (await db.execute(
                "SELECT id, hostname, device_type, confidence, metadata "
                "FROM devices WHERE id = ?", (device_id,)
            )).fetchone()

            # Merge metadata under our own subkey.
            existing_meta: dict = {}
            if row and row["metadata"]:
                try:
                    existing_meta = json.loads(row["metadata"])
                except Exception:
                    existing_meta = {}
            fw_meta = existing_meta.get(f"{source}_gateway", {})
            fw_meta.update({
                "source_label": source_label,
                "gid": gid,
                "vendor": vendor,
                "network": network_name,
                "group": group_name,
                "firewalla_online": online,
                "last_seen_ts": getattr(d, "last_seen", None),
            })
            existing_meta[f"{source}_gateway"] = fw_meta
            sources = set(existing_meta.get("seen_by", []))
            sources.add(source)
            existing_meta["seen_by"] = sorted(sources)
            meta_json = json.dumps(existing_meta)

            # Hostname precedence: prefer Firewalla's name, but never
            # clobber an existing non-empty hostname with blank.
            hostname_to_write = name
            if row and row["hostname"] and not hostname_to_write:
                hostname_to_write = row["hostname"]

            # We only commit is_online=1 on a positive sighting. A
            # Firewalla-reported offline is logged via metadata but
            # not flipped here (see precedence rule #4 above).
            if online:
                online_sql = ", is_online = 1"
            else:
                online_sql = ""

            if row:
                await db.execute(
                    f"""UPDATE devices
                       SET ip       = COALESCE(?, ip),
                           hostname = COALESCE(?, hostname),
                           metadata = ?,
                           last_seen = ?{online_sql}
                       WHERE id = ?""",
                    (ip, hostname_to_write, meta_json, now, device_id),
                )
            else:
                await db.execute(
                    """INSERT INTO devices
                       (id, mac, ip, hostname, device_type, confidence, metadata,
                        is_online, first_seen, last_seen)
                       VALUES (?, ?, ?, ?, 'unknown', 0.25, ?, ?, ?, ?)""",
                    (
                        device_id, mac, ip, hostname_to_write, meta_json,
                        1 if online else 0, now, now,
                    ),
                )
        await db.commit()

    return await get_all_devices()


async def get_all_devices() -> list[Device]:
    async with get_db() as db:
        cursor = await db.execute(
            """SELECT d.*,
               (SELECT COUNT(*) FROM vuln_results v WHERE v.device_id=d.id AND v.severity='critical') as vcrit,
               (SELECT COUNT(*) FROM vuln_results v WHERE v.device_id=d.id AND v.severity='high')     as vhigh,
               (SELECT COUNT(*) FROM vuln_results v WHERE v.device_id=d.id AND v.severity='medium')   as vmed,
               (SELECT COUNT(*) FROM vuln_results v WHERE v.device_id=d.id AND v.severity='low')      as vlow
               FROM devices d"""
        )
        rows = await cursor.fetchall()

        # Load all services in a single query, then group by device_id
        svc_cursor = await db.execute(
            """SELECT device_id, port, protocol, name, version, launch_url
               FROM device_services ORDER BY device_id, port"""
        )
        svc_rows = await svc_cursor.fetchall()

    services_by_device: dict[str, list[DeviceService]] = {}
    for sr in svc_rows:
        services_by_device.setdefault(sr["device_id"], []).append(
            DeviceService(
                port=sr["port"],
                protocol=sr["protocol"],
                name=sr["name"] or "unknown",
                version=sr["version"] or "",
                launch_url=sr["launch_url"],
            )
        )

    devices = []
    for row in rows:
        meta = json.loads(row["metadata"] or "{}")
        devices.append(Device(
            id=row["id"],
            mac=row["mac"],
            ip=row["ip"],
            hostname=row["hostname"],
            label=row["label"],
            device_type=row["device_type"] or "unknown",  # type: ignore[arg-type]
            status="online" if row["is_online"] else "offline",
            confidence=row["confidence"] or 0.0,
            metadata=meta,
            services=services_by_device.get(row["id"], []),
            is_online=bool(row["is_online"]),
            first_seen=datetime.fromisoformat(row["first_seen"]) if row["first_seen"] else None,
            last_seen=datetime.fromisoformat(row["last_seen"]) if row["last_seen"] else None,
            vuln_summary=VulnSummary(
                critical=row["vcrit"] or 0,
                high=row["vhigh"] or 0,
                medium=row["vmed"] or 0,
                low=row["vlow"] or 0,
            ),
        ))
    return devices


def detect_unknown_devices(devices: list[Device]) -> list[Device]:
    """Return devices that need Claude integration (unknown type, low confidence, has services)."""
    return [
        d for d in devices
        if d.device_type == "unknown"
        and len(d.services) > 0
        and d.confidence < 0.3
    ]
