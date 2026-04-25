from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field


class NodePosition(BaseModel):
    x: float = 0.0
    y: float = 0.0


class NodeData(BaseModel):
    device_id: str
    label: str
    device_type: str = "unknown"
    status: str = "unknown"
    ip: Optional[str] = None
    mac: Optional[str] = None
    services_count: int = 0
    vuln_critical: int = 0
    vuln_high: int = 0
    has_staged_integration: bool = False
    metadata: dict = Field(default_factory=dict)


class NetworkNode(BaseModel):
    id: str
    type: str = "deviceNode"
    position: NodePosition = Field(default_factory=NodePosition)
    data: NodeData
    draggable: bool = True


class EdgeData(BaseModel):
    connection_type: Literal["wired", "wireless"] = "wired"
    bandwidth_mbps: Optional[float] = None
    signal_strength: Optional[int] = None
    port_number: Optional[int] = None
    is_active: bool = True


class NetworkEdge(BaseModel):
    id: str
    source: str
    target: str
    type: str = "connectionEdge"
    animated: bool = False
    data: EdgeData = Field(default_factory=EdgeData)


class TopologyGraph(BaseModel):
    nodes: list[NetworkNode] = Field(default_factory=list)
    edges: list[NetworkEdge] = Field(default_factory=list)
    last_updated: Optional[str] = None
