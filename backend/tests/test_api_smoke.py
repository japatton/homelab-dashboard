"""Smoke tests for the HTTP API surface.

We boot the full FastAPI app in mock mode (BACKEND_MOCK=true) and
hit the endpoints we care about the most:

  - /health — external monitors depend on this being cheap + stable.
  - /api/setup/status — the frontend waits on this before rendering.
  - /api/alarms[, /summary] — the Security page is new and the mock
    fixtures are the only thing exercising the response shape until
    now.

These are not end-to-end tests. They verify HTTP wiring (routers
mounted, middleware order correct, response shapes match).
"""

from __future__ import annotations


class TestHealth:
    def test_health_200(self, api_client):
        r = api_client.get("/health")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "ok"
        assert body["mock"] is True


class TestSetupStatus:
    def test_setup_status_in_mock_is_complete(self, api_client):
        # BACKEND_MOCK=true short-circuits the setup-complete check so
        # the frontend renders the main app instead of the wizard.
        r = api_client.get("/api/setup/status")
        assert r.status_code == 200
        assert r.json() == {"setup_complete": True}


class TestAlarms:
    def test_list_alarms_returns_fixture(self, api_client):
        r = api_client.get("/api/alarms")
        assert r.status_code == 200
        body = r.json()
        assert "alarms" in body
        assert len(body["alarms"]) >= 1
        # First row shape spot-check — the fields the Security page
        # renders and the socket event reuses.
        a = body["alarms"][0]
        for key in (
            "id",
            "source",
            "severity",
            "message",
            "fingerprint",
            "first_seen_at",
            "last_seen_at",
            "count",
        ):
            assert key in a, f"missing {key} from alarm payload"

    def test_summary_shape(self, api_client):
        r = api_client.get("/api/alarms/summary")
        assert r.status_code == 200
        body = r.json()
        for key in (
            "total",
            "unacknowledged",
            "critical",
            "high",
            "medium",
            "low",
            "info",
        ):
            assert key in body, f"missing {key} from summary payload"
            assert isinstance(body[key], int)

    def test_list_filter_by_source(self, api_client):
        r = api_client.get("/api/alarms?source=firewalla")
        assert r.status_code == 200
        for a in r.json()["alarms"]:
            assert a["source"] == "firewalla"

    def test_list_filter_by_severity(self, api_client):
        r = api_client.get("/api/alarms?severity=critical")
        assert r.status_code == 200
        for a in r.json()["alarms"]:
            assert a["severity"] == "critical"

    def test_acknowledge_roundtrip(self, api_client):
        # Grab an unack'd id from the mock fixture, ack it.
        alarms = api_client.get("/api/alarms").json()["alarms"]
        target = next(a for a in alarms if not a["acknowledged"])
        r = api_client.post(f"/api/alarms/{target['id']}/acknowledge")
        assert r.status_code == 200
        assert r.json() == {"ok": True}
        # Re-fetch; the target is now acknowledged.
        after = api_client.get("/api/alarms").json()["alarms"]
        updated = next(a for a in after if a["id"] == target["id"])
        assert updated["acknowledged"] is True

    def test_acknowledge_unknown_returns_404(self, api_client):
        r = api_client.post("/api/alarms/alrm-does-not-exist/acknowledge")
        assert r.status_code == 404

    def test_dismiss_roundtrip(self, api_client):
        alarms = api_client.get("/api/alarms").json()["alarms"]
        target = alarms[-1]
        r = api_client.post(f"/api/alarms/{target['id']}/dismiss")
        assert r.status_code == 200
        # After dismissing, default listing should not contain it.
        after = api_client.get("/api/alarms").json()["alarms"]
        assert all(a["id"] != target["id"] for a in after)
        # But include_dismissed=true still surfaces it.
        archive = api_client.get("/api/alarms?include_dismissed=true").json()["alarms"]
        assert any(a["id"] == target["id"] for a in archive)


class TestAuthMiddlewareIntegration:
    def test_token_gate_blocks_api_when_configured(self, api_client_with_token):
        r = api_client_with_token.get("/api/alarms")
        assert r.status_code == 401

    def test_token_gate_allows_with_correct_header(self, api_client_with_token):
        r = api_client_with_token.get(
            "/api/alarms",
            headers={"Authorization": "Bearer test-token-xyz"},
        )
        assert r.status_code == 200

    def test_token_gate_leaves_health_open(self, api_client_with_token):
        assert api_client_with_token.get("/health").status_code == 200


class TestDocsExposure:
    """F-007: FastAPI's auto-generated docs (/docs, /redoc, /openapi.json)
    don't start with /api/ so the auth middleware lets them through. They
    publish the entire API surface map to anonymous callers — fine in
    development (token unset) but free recon under tunnel exposure. We
    flip them off when DASHBOARD_TOKEN is set."""

    def test_docs_open_when_token_unset(self, api_client):
        # api_client fixture leaves DASHBOARD_TOKEN unset → /docs reachable
        # for local Swagger workflows.
        assert api_client.get("/docs").status_code == 200
        assert api_client.get("/openapi.json").status_code == 200

    def test_docs_disabled_when_token_set(self, api_client_with_token):
        # api_client_with_token sets DASHBOARD_TOKEN → /docs returns 404.
        # Note: the routes are *not mounted*, so the response is FastAPI's
        # default 404, not a 401 from the middleware (since the middleware
        # only gates /api/*). 404 is correct: the routes don't exist.
        assert api_client_with_token.get("/docs").status_code == 404
        assert api_client_with_token.get("/redoc").status_code == 404
        assert api_client_with_token.get("/openapi.json").status_code == 404
