"""Shared pytest fixtures.

Key responsibilities:
  - Put `backend/` on sys.path so tests can `from services.x import ...`
    without a `backend.` prefix (matches runtime imports).
  - Point DB_PATH at a per-test temp SQLite file BEFORE the database module
    is first imported, then initialise the schema.
  - Provide a TestClient for the FastAPI app that isn't tied to the
    scheduler / Elasticsearch startup work.

Each test function gets a fresh DB (function-scope fixture) so writes in
one test never leak into another.
"""

from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

import pytest

# ─── sys.path ────────────────────────────────────────────────────────────
# Tests live at backend/tests/; we need backend/ on the path so that
# `from database import ...` / `from services.x import ...` resolves
# exactly the way the runtime does.

_BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))


# ─── Env guards ──────────────────────────────────────────────────────────
# We always run tests in mock-friendly mode: BACKEND_MOCK=true makes the
# API routers skip real scheduler/Elasticsearch startup and serve fixture
# payloads where applicable. DASHBOARD_TOKEN cleared so auth-gate tests
# can opt in locally without interference.

os.environ.setdefault("BACKEND_MOCK", "true")
os.environ.pop("DASHBOARD_TOKEN", None)
os.environ.pop("DASHBOARD_ALLOWED_ORIGINS", None)


# ─── Per-test DB_PATH ────────────────────────────────────────────────────


@pytest.fixture()
async def initialised_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Per-test SQLite file, schema initialised.

    Forces `database.DB_PATH` to point at a tmp file and awaits
    `init_db()` against it. Use in async tests to get a clean database
    for each run — no cross-test leakage.
    """
    p = tmp_path / "test.db"
    monkeypatch.setenv("DB_PATH", str(p))

    # Re-import so the module-level DB_PATH constant picks up the env
    # var we just set. Otherwise the module would keep whatever value
    # was present at first import time.
    import database

    importlib.reload(database)
    assert database.DB_PATH == p, "database.DB_PATH did not pick up the monkeypatch"

    await database.init_db()
    yield p


# ─── Config manager fixture ──────────────────────────────────────────────


@pytest.fixture()
def config_manager(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Fresh ConfigManager pointed at a temp config.yml.

    Returns the manager with a loaded (default) ConfigRoot. Use
    `.get()` to mutate and `.save()` to persist.
    """
    cfg_path = tmp_path / "config.yml"
    monkeypatch.setenv("CONFIG_PATH", str(cfg_path))

    from config import config_manager as cm_mod

    importlib.reload(cm_mod)

    mgr = cm_mod.ConfigManager(cfg_path)
    mgr.load()
    return mgr


# ─── FastAPI client ──────────────────────────────────────────────────────


@pytest.fixture()
def api_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """TestClient for the FastAPI app in mock mode.

    We import `main` lazily inside the fixture so environment monkeypatches
    are applied before module import. The ASGI Socket.io wrapper isn't
    exercised here — TestClient drives the FastAPI app directly.
    """
    monkeypatch.setenv("BACKEND_MOCK", "true")
    # Steer DB + config writes to the tmp dir even though mock mode
    # doesn't normally touch either. Belt-and-braces.
    monkeypatch.setenv("DB_PATH", str(tmp_path / "api-test.db"))
    monkeypatch.setenv("CONFIG_PATH", str(tmp_path / "api-config.yml"))

    from fastapi.testclient import TestClient
    import main

    importlib.reload(main)

    with TestClient(main.app) as c:
        yield c


@pytest.fixture()
def api_client_with_token(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """TestClient with DASHBOARD_TOKEN set. Exercises the auth middleware."""
    monkeypatch.setenv("BACKEND_MOCK", "true")
    monkeypatch.setenv("DASHBOARD_TOKEN", "test-token-xyz")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("CONFIG_PATH", str(tmp_path / "config.yml"))

    from fastapi.testclient import TestClient
    import main

    importlib.reload(main)

    with TestClient(main.app) as c:
        yield c
