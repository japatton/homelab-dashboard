from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal

IntegrationStatus = Literal["ok", "degraded", "offline"]

# Patterns that look like credentials in error messages
_CREDENTIAL_RE = re.compile(
    r'(password|passwd|token|secret|key|auth)[=:]\S+',
    re.IGNORECASE,
)


def _sanitize_error(msg: str) -> str:
    return _CREDENTIAL_RE.sub(r'\1=***', msg)


@dataclass
class ConnectionResult:
    ok: bool
    status: IntegrationStatus
    message: str = ""
    latency_ms: float = 0.0
    detail: dict = field(default_factory=dict)

    @classmethod
    def success(cls, message: str = "", **detail) -> "ConnectionResult":
        return cls(ok=True, status="ok", message=message, detail=detail)

    @classmethod
    def degraded(cls, message: str = "", **detail) -> "ConnectionResult":
        return cls(ok=False, status="degraded", message=_sanitize_error(message), detail=detail)

    @classmethod
    def offline(cls, message: str = "", **detail) -> "ConnectionResult":
        return cls(ok=False, status="offline", message=_sanitize_error(message), detail=detail)


class BaseIntegration:
    name: str = "base"

    async def test_connection(self) -> ConnectionResult:
        raise NotImplementedError

    def _safe_error(self, exc: Exception) -> str:
        return _sanitize_error(str(exc))
