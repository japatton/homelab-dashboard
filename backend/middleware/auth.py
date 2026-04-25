"""Opt-in single-token auth.

Set `DASHBOARD_TOKEN=<something-long>` in the backend env and every
/api/* request (plus socket.io) must present it as:
    Authorization: Bearer <token>
or
    ?token=<token>   (for socket.io WebSocket handshake convenience)

Unset → middleware is a no-op, current behaviour. This exists so the
homelab dashboard can be safely exposed over a reverse proxy to the
Tailscale network / the public internet without someone stumbling onto
an unauthenticated OpenVAS-reset button.

Exempt paths (no token needed, in all cases):
  - GET /health   so external monitoring can still probe liveness
  - any path starting with /socket.io (socket.io handshake has its own
    token check in notification_service)

NOTE: This is intentionally a single shared token, not per-user auth.
The threat model is "gate the dashboard from drive-by access", not
multi-tenant. Bump to OIDC/oauth2 if you ever have multiple users.
"""

from __future__ import annotations

import hmac
import logging
import os

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

log = logging.getLogger(__name__)

# Paths that don't require the token. Keep this list short — each entry
# is a trusted, unauthenticated endpoint.
_EXEMPT_PREFIXES = ("/health",)


class DashboardTokenMiddleware(BaseHTTPMiddleware):
    """Bearer-token gate over /api/*. No-op when DASHBOARD_TOKEN unset."""

    def __init__(self, app, token: str | None):
        super().__init__(app)
        self._token = token or None
        if self._token:
            log.info("Dashboard token auth ENABLED — /api/* requires Bearer token")
        else:
            log.info("Dashboard token auth DISABLED — set DASHBOARD_TOKEN to turn on")

    async def dispatch(self, request: Request, call_next):
        if not self._token:
            return await call_next(request)

        path = request.url.path
        if any(path.startswith(p) for p in _EXEMPT_PREFIXES):
            return await call_next(request)
        # Only gate API calls — static files / socket.io handled elsewhere.
        if not path.startswith("/api/"):
            return await call_next(request)

        supplied = ""
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            supplied = auth[7:].strip()
        if not supplied:
            supplied = request.query_params.get("token", "")

        # constant-time compare to blunt timing oracles
        if not supplied or not hmac.compare_digest(supplied, self._token):
            return JSONResponse(
                {"detail": "Missing or invalid token"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )
        return await call_next(request)


def get_dashboard_token() -> str | None:
    """Read once per process. Strip whitespace so copy-paste mistakes
    (trailing newline from `echo $TOKEN | pbcopy` etc.) don't silently
    disable the gate."""
    tok = os.getenv("DASHBOARD_TOKEN", "").strip()
    return tok or None
