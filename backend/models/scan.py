from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field

ScanType = Literal["nmap", "openvas", "unifi"]
ScanStatus = Literal["pending", "running", "completed", "failed"]
ScanProfile = Literal["quick", "standard", "full"]


class NmapPort(BaseModel):
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    version: str = ""
    product: str = ""


class NmapHost(BaseModel):
    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    status: str = "up"
    ports: list[NmapPort] = Field(default_factory=list)
    os_guess: Optional[str] = None


class NmapResult(BaseModel):
    hosts: list[NmapHost] = Field(default_factory=list)
    scan_duration_seconds: float = 0.0
    command: str = ""


class ScanJob(BaseModel):
    id: str
    scan_type: ScanType
    status: ScanStatus = "pending"
    profile: ScanProfile = "standard"
    targets: Optional[list[str]] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    progress: int = 0
    error: Optional[str] = None


class ScanResult(BaseModel):
    job_id: str
    device_id: str
    scan_type: ScanType
    completed_at: datetime
    summary: dict = Field(default_factory=dict)
