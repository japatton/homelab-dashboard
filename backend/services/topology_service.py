from __future__ import annotations

import json
import logging
import math
from datetime import datetime, timezone
from typing import Iterable, Optional

from database import get_db
from models.topology import EdgeData, NetworkEdge, NetworkNode, NodeData, NodePosition, TopologyGraph

log = logging.getLogger(__name__)

# Circular layout radii. Gateway sits at (0,0); infra devices ring around it;
# endpoints fan out in one or more outer rings. Tuned for a ~150-device homelab.
_CENTER_X = 0.0
_CENTER_Y = 0.0
_INFRA_RADIUS = 260.0
_ENDPOINT_BASE_RADIUS = 560.0
_ENDPOINT_RING_STEP = 220.0          # radius added per additional ring
_MAX_PER_RING = 36                   # split endpoints into rings of <= this many

_GATEWAY_TYPES = {"gateway"}
_INFRA_TYPES = {"switch", "ap"}


def _ring_positions(
    count: int,
    radius: float,
    cx: float = _CENTER_X,
    cy: float = _CENTER_Y,
    angle_offset: float = 0.0,
) -> Iterable[tuple[float, float]]:
    """Yield (x, y) for `count` points evenly spaced on a circle."""
    if count <= 0:
        return
    for i in range(count):
        angle = angle_offset + (2.0 * math.pi * i / count)
        yield (cx + radius * math.cos(angle), cy + radius * math.sin(angle))


async def build_topology_graph(devices: list, unifi_topology=None) -> TopologyGraph:
    """Build a React Flow-compatible TopologyGraph from devices.

    Layout: gateway(s) at center, infra (switches/APs) in an inner ring,
    endpoints in one or more concentric outer rings. Saved positions
    (user-dragged) always win.
    """
    from models.device import Device

    # Load saved node positions + staged-integration ids
    saved_positions: dict[str, tuple[float, float]] = {}
    staged_ids: set[str] = set()

    async with get_db() as db:
        rows = await (await db.execute(
            "SELECT id, position_x, position_y FROM devices WHERE position_x != 0 OR position_y != 0"
        )).fetchall()
        for row in rows:
            saved_positions[row["id"]] = (row["position_x"], row["position_y"])

        staged_rows = await (await db.execute(
            "SELECT device_id FROM claude_staged_changes WHERE status = 'pending'"
        )).fetchall()
        staged_ids = {r["device_id"] for r in staged_rows}

    gateways = [d for d in devices if d.device_type in _GATEWAY_TYPES]
    infra = [d for d in devices if d.device_type in _INFRA_TYPES]
    endpoints = [d for d in devices if d.device_type not in _GATEWAY_TYPES | _INFRA_TYPES]

    # --- Gateway(s) ---
    # Single gateway → center. Multiple gateways → small inner cluster.
    gateway_positions: dict[str, tuple[float, float]] = {}
    if len(gateways) == 1:
        gateway_positions[gateways[0].id] = (_CENTER_X, _CENTER_Y)
    else:
        for gw, (x, y) in zip(gateways, _ring_positions(len(gateways), 80.0)):
            gateway_positions[gw.id] = (x, y)

    # --- Infra ring ---
    infra_positions: dict[str, tuple[float, float]] = {}
    # Slight rotational offset so switches don't sit directly above the gateway icon
    for dev, (x, y) in zip(infra, _ring_positions(len(infra), _INFRA_RADIUS, angle_offset=-math.pi / 2)):
        infra_positions[dev.id] = (x, y)

    # --- Endpoint ring(s) ---
    endpoint_positions: dict[str, tuple[float, float]] = {}
    if endpoints:
        ring_count = math.ceil(len(endpoints) / _MAX_PER_RING)
        # Fill outer rings evenly: distribute endpoints round-robin across rings
        rings: list[list] = [[] for _ in range(ring_count)]
        for i, dev in enumerate(endpoints):
            rings[i % ring_count].append(dev)
        for ring_idx, ring_devs in enumerate(rings):
            radius = _ENDPOINT_BASE_RADIUS + (ring_idx * _ENDPOINT_RING_STEP)
            # Stagger adjacent rings so labels don't line up radially
            offset = (math.pi / _MAX_PER_RING) if ring_idx % 2 else 0.0
            for dev, (x, y) in zip(ring_devs, _ring_positions(len(ring_devs), radius, angle_offset=offset)):
                endpoint_positions[dev.id] = (x, y)

    computed = {**gateway_positions, **infra_positions, **endpoint_positions}

    # --- Emit nodes ---
    nodes: list[NetworkNode] = []
    for device in devices:
        if device.id in saved_positions:
            x, y = saved_positions[device.id]
        elif device.id in computed:
            x, y = computed[device.id]
        else:
            # Fallback: place on a far outer ring so it's visible but out of the way
            x, y = _CENTER_X, _CENTER_Y + _ENDPOINT_BASE_RADIUS + (3 * _ENDPOINT_RING_STEP)

        nodes.append(NetworkNode(
            id=device.id,
            position=NodePosition(x=x, y=y),
            data=NodeData(
                device_id=device.id,
                label=device.label or device.hostname or device.ip or device.id,
                device_type=device.device_type,
                status=device.status,
                ip=device.ip,
                mac=device.mac,
                services_count=len(device.services),
                vuln_critical=device.vuln_summary.critical,
                vuln_high=device.vuln_summary.high,
                has_staged_integration=device.id in staged_ids,
            ),
        ))

    edges = _build_edges(devices, unifi_topology)

    return TopologyGraph(
        nodes=nodes,
        edges=edges,
        last_updated=datetime.now(timezone.utc).isoformat(),
    )


def _build_edges(devices: list, unifi_topology) -> list[NetworkEdge]:
    """Build edges from UniFi topology data, falling back to heuristic tier connections."""
    edges: list[NetworkEdge] = []
    device_by_mac: dict[str, str] = {d.mac: d.id for d in devices if d.mac}
    device_ids = {d.id for d in devices}
    seen: set[str] = set()

    def add_edge(src: str, tgt: str, conn_type: str, bandwidth: Optional[float] = None, signal: Optional[int] = None):
        edge_id = f"e-{src[:8]}-{tgt[:8]}"
        if edge_id in seen:
            return
        seen.add(edge_id)
        edges.append(NetworkEdge(
            id=edge_id,
            source=src,
            target=tgt,
            # Animation only on wireless links — avoids 100+ animated wired
            # edges chewing repaint time on large homelabs.
            animated=(conn_type == "wireless"),
            data=EdgeData(
                connection_type=conn_type,  # type: ignore[arg-type]
                bandwidth_mbps=bandwidth,
                signal_strength=signal,
                is_active=True,
            ),
        ))

    if unifi_topology:
        # Use actual UniFi topology data for managed devices
        for dev in unifi_topology.devices:
            dev_id = device_by_mac.get(dev.mac)
            if not dev_id or dev_id not in device_ids:
                continue
            if dev.uplink_mac:
                uplink_id = device_by_mac.get(dev.uplink_mac)
                if uplink_id and uplink_id in device_ids:
                    add_edge(uplink_id, dev_id, "wired", 1000)

        for client in unifi_topology.clients:
            client_id = device_by_mac.get(client.mac)
            if not client_id or client_id not in device_ids:
                continue
            if client.is_wired and client.sw_mac:
                sw_id = device_by_mac.get(client.sw_mac)
                if sw_id and sw_id in device_ids:
                    add_edge(sw_id, client_id, "wired")
            elif not client.is_wired and client.ap_mac:
                ap_id = device_by_mac.get(client.ap_mac)
                if ap_id and ap_id in device_ids:
                    add_edge(ap_id, client_id, "wireless", signal=client.signal)

    # Heuristic fallback: connect tiers top-down
    gateways = [d for d in devices if d.device_type == "gateway"]
    infra = [d for d in devices if d.device_type in ("switch", "ap")]
    endpoints = [d for d in devices if d.device_type not in ("gateway", "switch", "ap")]

    for gw in gateways:
        for inf in infra:
            if not any(e.source == gw.id and e.target == inf.id for e in edges):
                add_edge(gw.id, inf.id, "wired", 1000)

    if not infra:
        for gw in gateways:
            for ep in endpoints:
                if not any(e.target == ep.id for e in edges):
                    add_edge(gw.id, ep.id, "wired")
    else:
        switches = [d for d in infra if d.device_type == "switch"]
        aps = [d for d in infra if d.device_type == "ap"]
        anchor = switches[0] if switches else (gateways[0] if gateways else None)

        for ep in endpoints:
            if any(e.target == ep.id for e in edges):
                continue
            if anchor:
                add_edge(anchor.id, ep.id, "wired")

    return edges
