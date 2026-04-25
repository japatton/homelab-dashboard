from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field

DeviceType = Literal[
    "gateway",
    "switch",
    "ap",
    "server",
    "workstation",
    "laptop",
    "camera",
    "doorbell",
    "iot",
    "phone",
    "unknown",
]

DeviceStatus = Literal["online", "offline", "scanning", "unknown"]


class DeviceService(BaseModel):
    port: int
    protocol: str = "tcp"
    name: str = ""
    version: str = ""
    launch_url: Optional[str] = None


class VulnSummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low


class Device(BaseModel):
    id: str
    mac: Optional[str] = None
    ip: Optional[str] = None
    hostname: Optional[str] = None
    label: Optional[str] = None
    device_type: DeviceType = "unknown"
    status: DeviceStatus = "unknown"
    confidence: float = 0.0
    services: list[DeviceService] = Field(default_factory=list)
    vuln_summary: VulnSummary = Field(default_factory=VulnSummary)
    metadata: dict = Field(default_factory=dict)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    is_online: bool = False

    @property
    def display_name(self) -> str:
        return self.label or self.hostname or self.ip or self.mac or self.id
