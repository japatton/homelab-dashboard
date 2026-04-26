"""Tests for middleware.auth — DashboardTokenMiddleware.

The middleware is the one line of defence when exposing the dashboard
over a reverse proxy. Three things must be true for every request:

  1. `/health` is always reachable (external monitoring).
  2. `/api/*` requires a valid bearer token when DASHBOARD_TOKEN is set.
  3. When DASHBOARD_TOKEN is unset, the middleware is a no-op (LAN mode).

We test by constructing a tiny FastAPI app and driving it with
TestClient, rather than importing the whole main.py — faster and
avoids scheduler/DB initialisation.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from middleware.auth import DashboardTokenMiddleware, get_dashboard_token


def _build_app(token: str | None) -> FastAPI:
    app = FastAPI()
    # Middleware must be added BEFORE routes for Starlette to wrap them.
    app.add_middleware(DashboardTokenMiddleware, token=token)

    @app.get("/health")
    async def health():
        return {"ok": True}

    @app.get("/api/ping")
    async def ping():
        return {"ok": True, "protected": True}

    @app.get("/other")
    async def other():
        return {"ok": True, "unprotected": True}

    return app


class TestUnsetToken:
    def test_passes_everything_through(self):
        # No token configured → middleware is a no-op.
        client = TestClient(_build_app(None))
        assert client.get("/health").status_code == 200
        assert client.get("/api/ping").status_code == 200
        assert client.get("/other").status_code == 200

    def test_empty_string_treated_as_unset(self):
        # Guards against `DASHBOARD_TOKEN=` accidentally disabling auth.
        client = TestClient(_build_app(""))
        assert client.get("/api/ping").status_code == 200


class TestSetToken:
    @pytest.fixture()
    def client(self) -> TestClient:
        return TestClient(_build_app("s3cret-token"))

    def test_health_always_open(self, client: TestClient):
        # /health must be reachable without a token so external
        # health-checkers can probe liveness.
        assert client.get("/health").status_code == 200

    def test_non_api_path_open(self, client: TestClient):
        # The gate only guards /api/*. Static files and socket.io are
        # handled elsewhere.
        assert client.get("/other").status_code == 200

    def test_api_without_token_is_401(self, client: TestClient):
        r = client.get("/api/ping")
        assert r.status_code == 401
        assert r.headers.get("www-authenticate", "").lower().startswith("bearer")

    def test_api_with_correct_bearer(self, client: TestClient):
        r = client.get("/api/ping", headers={"Authorization": "Bearer s3cret-token"})
        assert r.status_code == 200

    def test_api_with_wrong_bearer(self, client: TestClient):
        r = client.get("/api/ping", headers={"Authorization": "Bearer wrong"})
        assert r.status_code == 401

    def test_bearer_is_case_insensitive(self, client: TestClient):
        # "bearer" / "Bearer" / "BEARER" all work.
        for scheme in ("bearer", "Bearer", "BEARER"):
            r = client.get(
                "/api/ping", headers={"Authorization": f"{scheme} s3cret-token"}
            )
            assert r.status_code == 200, f"failed for scheme {scheme}"

    def test_query_param_token_rejected(self, client: TestClient):
        # F-005: ?token= fallback was removed. Tokens in URLs leak via
        # access logs, browser history, and Referer headers — even a
        # correct token in a query parameter is now rejected. Clients
        # must use the Authorization header (HTTP) or socket.io's
        # `auth: { token }` handshake (WebSocket).
        r = client.get("/api/ping?token=s3cret-token")
        assert r.status_code == 401

    def test_blank_bearer_does_not_fall_back(self, client: TestClient):
        # "Authorization: Bearer " with empty value used to fall back to
        # ?token=; now it just fails with 401 regardless of whether a
        # token is in the query string. Same root cause: no URL-shaped
        # token paths, full stop.
        r = client.get(
            "/api/ping?token=s3cret-token",
            headers={"Authorization": "Bearer "},
        )
        assert r.status_code == 401


class TestGetDashboardToken:
    def test_env_var_stripped(self, monkeypatch: pytest.MonkeyPatch):
        # Trailing newline from `echo $TOKEN | pbcopy` used to silently
        # disable the gate — the middleware now strips whitespace.
        monkeypatch.setenv("DASHBOARD_TOKEN", "  tok-xyz  \n")
        assert get_dashboard_token() == "tok-xyz"

    def test_unset_env_returns_none(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("DASHBOARD_TOKEN", raising=False)
        assert get_dashboard_token() is None

    def test_blank_env_returns_none(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("DASHBOARD_TOKEN", "   ")
        assert get_dashboard_token() is None
