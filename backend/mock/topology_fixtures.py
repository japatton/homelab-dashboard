from __future__ import annotations

from datetime import datetime

from models.topology import EdgeData, NetworkEdge, NetworkNode, NodeData, NodePosition, TopologyGraph

# Three-tier layout:
# Tier 0 (top):    Gateway (UDM Pro)
# Tier 1 (middle): Switches, APs
# Tier 2 (bottom): Servers, cameras, end devices, IoT

_TIER_Y = {0: 50, 1: 250, 2: 480}
_TIER_SPACING = 200

MOCK_NODES: list[NetworkNode] = [
    # --- Tier 0: Gateway ---
    NetworkNode(
        id="dev-udm-pro",
        position=NodePosition(x=600, y=_TIER_Y[0]),
        data=NodeData(
            device_id="dev-udm-pro",
            label="UDM Pro",
            device_type="gateway",
            status="online",
            ip="192.168.1.1",
            mac="dc:9f:db:aa:bb:01",
            services_count=2,
            vuln_critical=0,
            vuln_high=1,
        ),
    ),

    # --- Tier 1: Network infrastructure ---
    NetworkNode(
        id="dev-sw-24",
        position=NodePosition(x=300, y=_TIER_Y[1]),
        data=NodeData(
            device_id="dev-sw-24",
            label="Core Switch",
            device_type="switch",
            status="online",
            ip="192.168.1.2",
            mac="dc:9f:db:aa:bb:02",
            services_count=1,
            vuln_critical=0,
            vuln_high=0,
        ),
    ),
    NetworkNode(
        id="dev-ap-lr",
        position=NodePosition(x=700, y=_TIER_Y[1]),
        data=NodeData(
            device_id="dev-ap-lr",
            label="Living Room AP",
            device_type="ap",
            status="online",
            ip="192.168.1.10",
            mac="dc:9f:db:aa:bb:03",
            services_count=0,
        ),
    ),
    NetworkNode(
        id="dev-ap-office",
        position=NodePosition(x=950, y=_TIER_Y[1]),
        data=NodeData(
            device_id="dev-ap-office",
            label="Office AP",
            device_type="ap",
            status="online",
            ip="192.168.1.11",
            mac="dc:9f:db:aa:bb:04",
            services_count=0,
        ),
    ),

    # --- Tier 2: End devices ---
    NetworkNode(
        id="dev-homelab-server",
        position=NodePosition(x=100, y=_TIER_Y[2]),
        data=NodeData(
            device_id="dev-homelab-server",
            label="Homelab Server",
            device_type="server",
            status="online",
            ip="192.168.1.50",
            mac="00:11:22:aa:bb:cc",
            services_count=3,
            vuln_critical=0,
            vuln_high=2,
        ),
    ),
    NetworkNode(
        id="dev-nas",
        position=NodePosition(x=300, y=_TIER_Y[2]),
        data=NodeData(
            device_id="dev-nas",
            label="TrueNAS",
            device_type="server",
            status="online",
            ip="192.168.1.51",
            mac="00:11:22:aa:bb:dd",
            services_count=4,
            vuln_critical=0,
            vuln_high=1,
        ),
    ),
    NetworkNode(
        id="dev-workstation",
        position=NodePosition(x=500, y=_TIER_Y[2]),
        data=NodeData(
            device_id="dev-workstation",
            label="MacBook Pro",
            device_type="laptop",
            status="online",
            ip="192.168.1.100",
            mac="aa:bb:cc:dd:ee:01",
            services_count=0,
        ),
    ),
    NetworkNode(
        id="dev-cam-front",
        position=NodePosition(x=700, y=_TIER_Y[2]),
        data=NodeData(
            device_id="dev-cam-front",
            label="Front Door Camera",
            device_type="doorbell",
            status="online",
            ip="192.168.20.10",
            mac="00:aa:bb:cc:dd:01",
            services_count=2,
        ),
    ),
    NetworkNode(
        id="dev-cam-back",
        position=NodePosition(x=900, y=_TIER_Y[2]),
        data=NodeData(
            device_id="dev-cam-back",
            label="Backyard Camera",
            device_type="camera",
            status="online",
            ip="192.168.20.11",
            mac="00:aa:bb:cc:dd:02",
            services_count=1,
        ),
    ),
    NetworkNode(
        id="dev-iot-thermostat",
        position=NodePosition(x=1100, y=_TIER_Y[2]),
        data=NodeData(
            device_id="dev-iot-thermostat",
            label="Thermostat",
            device_type="iot",
            status="online",
            ip="192.168.30.10",
            mac="aa:bb:cc:dd:ee:10",
            services_count=1,
        ),
    ),
    NetworkNode(
        id="dev-unknown-01",
        position=NodePosition(x=1300, y=_TIER_Y[2]),
        data=NodeData(
            device_id="dev-unknown-01",
            label="192.168.1.200",
            device_type="unknown",
            status="online",
            ip="192.168.1.200",
            mac="ff:ee:dd:cc:bb:01",
            services_count=2,
            has_staged_integration=True,
        ),
    ),
]

MOCK_EDGES: list[NetworkEdge] = [
    # Gateway → Switch (wired uplink)
    NetworkEdge(
        id="e-udm-sw24",
        source="dev-udm-pro",
        target="dev-sw-24",
        animated=True,
        data=EdgeData(connection_type="wired", bandwidth_mbps=1000, is_active=True),
    ),
    # Gateway → APs (wired PoE)
    NetworkEdge(
        id="e-udm-ap-lr",
        source="dev-udm-pro",
        target="dev-ap-lr",
        animated=True,
        data=EdgeData(connection_type="wired", bandwidth_mbps=1000, is_active=True),
    ),
    NetworkEdge(
        id="e-udm-ap-office",
        source="dev-udm-pro",
        target="dev-ap-office",
        animated=True,
        data=EdgeData(connection_type="wired", bandwidth_mbps=1000, is_active=True),
    ),
    # Switch → Servers (wired)
    NetworkEdge(
        id="e-sw24-server",
        source="dev-sw-24",
        target="dev-homelab-server",
        animated=True,
        data=EdgeData(connection_type="wired", bandwidth_mbps=1000, port_number=1, is_active=True),
    ),
    NetworkEdge(
        id="e-sw24-nas",
        source="dev-sw-24",
        target="dev-nas",
        animated=True,
        data=EdgeData(connection_type="wired", bandwidth_mbps=1000, port_number=2, is_active=True),
    ),
    NetworkEdge(
        id="e-sw24-unknown",
        source="dev-sw-24",
        target="dev-unknown-01",
        animated=False,
        data=EdgeData(connection_type="wired", bandwidth_mbps=100, port_number=24, is_active=True),
    ),
    # AP → Wireless clients
    NetworkEdge(
        id="e-ap-lr-mbp",
        source="dev-ap-lr",
        target="dev-workstation",
        animated=True,
        data=EdgeData(connection_type="wireless", bandwidth_mbps=600, signal_strength=-55, is_active=True),
    ),
    NetworkEdge(
        id="e-ap-lr-thermostat",
        source="dev-ap-lr",
        target="dev-iot-thermostat",
        animated=False,
        data=EdgeData(connection_type="wireless", bandwidth_mbps=54, signal_strength=-68, is_active=True),
    ),
    # Gateway → Cameras (PoE/separate VLAN)
    NetworkEdge(
        id="e-udm-cam-front",
        source="dev-udm-pro",
        target="dev-cam-front",
        animated=True,
        data=EdgeData(connection_type="wired", bandwidth_mbps=100, is_active=True),
    ),
    NetworkEdge(
        id="e-udm-cam-back",
        source="dev-udm-pro",
        target="dev-cam-back",
        animated=True,
        data=EdgeData(connection_type="wired", bandwidth_mbps=100, is_active=True),
    ),
]

MOCK_TOPOLOGY = TopologyGraph(
    nodes=MOCK_NODES,
    edges=MOCK_EDGES,
    last_updated=datetime.utcnow().isoformat(),
)
