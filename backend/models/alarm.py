"""Pydantic models for the unified gateway alarms feed.

One `GatewayAlarm` = one distinct security event, deduplicated across
repeat fires from the same source. The Security page renders these in
reverse-chronological order regardless of source, so every alarm
carries its source ("opnsense" / "firewalla") inline rather than
JOINed from anywhere else.

Severity is normalised to the Nmap/OpenVAS vocabulary (critical /
high / medium / low / info) so the frontend's severity palette works
uniformly across all feeds.
"""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field


AlarmSource = Literal["opnsense", "firewalla"]
AlarmSeverity = Literal["critical", "high", "medium", "low", "info"]


class GatewayAlarm(BaseModel):
    """Single alarm entry, mapped 1:1 to gateway_alarms table."""

    id: str
    source: AlarmSource
    source_label: str = ""
    severity: AlarmSeverity = "info"
    category: str = ""
    signature: str = ""
    message: str
    src_ip: str = ""
    dst_ip: str = ""
    device_id: Optional[str] = None
    device_name: str = ""
    fingerprint: str
    first_seen_at: str
    last_seen_at: str
    count: int = 1
    acknowledged: bool = False
    acknowledged_at: Optional[str] = None
    dismissed: bool = False
    dismissed_at: Optional[str] = None
    # `raw_json` is a passthrough for the original event; exposed in
    # API responses so power users can see the full upstream payload
    # without a separate lookup, but kept as Dict[Any] so we don't
    # have to maintain source-specific schemas here.
    raw: dict = Field(default_factory=dict)


class AlarmSummary(BaseModel):
    """Counts-by-severity payload used for badges and the Security
    page header. Cheap to compute via a single GROUP BY query."""

    total: int = 0
    unacknowledged: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
