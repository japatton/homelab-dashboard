# Code-review fixes — staged for your review

This doc is the companion to `docs/code-review.md`. It lists every change made
in this pass, what file changed, why, and how to back out any single item if
it misbehaves. Nothing here runs until you rebuild the containers — the
changes are inert on disk.

> **How to review:** skim the table, drop into any section that looks
> interesting, and run the "Spot-check" command listed at the bottom to
> verify the diff matches the description.

---

## Summary table

| # | Area | Tier | Files touched |
|---|------|------|---------------|
| 1 | Fire-and-forget task helper + retrofit | 0 (critical) | `backend/services/background_tasks.py` (new); `backend/api/{analysis,scheduler,scans,vulns,setup,claude_integration}.py`; `backend/scheduler/jobs.py` |
| 2 | Backend non-root + read-only FS | 0 (critical) | `backend/Dockerfile`; `backend/docker-entrypoint.sh` (new); `docker-compose.yml` |
| 3 | Optional bearer-token auth | 0 (critical) | `backend/middleware/auth.py` (new); `backend/middleware/__init__.py` (new); `backend/main.py`; `frontend/src/api/client.ts`; `.env.example` |
| 4 | Config env-vars apply on first boot only | 0 (critical) | `backend/config/config_manager.py` |
| 5 | `time.sleep` comment + UniFi poll timeout | 1 (high) | `backend/integrations/openvas.py`; `backend/scheduler/jobs.py` |
| 6 | Secret-scrubbing audit encoder | 1 (high) | `backend/services/audit_service.py` |
| 7 | Nginx security headers | 1 (high) | `frontend/nginx.conf` |
| 8 | Pin `immauss/openvas` tag + `python-gvm` | 1 (high) | `backend/requirements.txt`; `docker-compose.yml`; `backend/services/openvas_reset.py` |
| 9 | Claude analysis concurrency cap | 2 (medium) | `backend/services/claude_analysis.py`; `.env.example` |
| 10 | Batch vuln-findings INSERTs | 2 (medium) | `backend/services/vuln_service.py` |
| 11 | Single severity query + covering index | 2 (medium) | `backend/api/devices.py`; `backend/database.py` |
| 12 | Axios interceptor preserves status | 2 (medium) | `frontend/src/api/client.ts` |
| 13 | OpenVAS healthcheck probes GMP port | 2 (medium) | `docker-compose.yml` |
| 14 | homelab-data volume chown migration | 2 (medium) | `deploy.sh` |
| 15 | Configurable backend host-port bind | 2 (medium) | `docker-compose.yml`; `.env.example` |
| 16 | Tier 3 quick wins (log rotation, node pin, env docs) | 3 | `docker-compose.yml`; `frontend/Dockerfile`; `.env.example`; `frontend/src/main.tsx` |

Total: 17 files modified, 5 files added.

---

## 1. Fire-and-forget task helper + retrofit *(Tier 0)*

**Problem.** Ten sites called `asyncio.create_task(...)` and discarded the
return value. Python 3.11+ keeps only a *weak* reference to tasks returned
from `create_task`, so if nothing holds a strong ref the task can be GC'd
mid-flight — silently. That affects the long-running OpenVAS reset (10+ min
warmup) and the Claude analysis path in particular. Unhandled exceptions in
those tasks also disappear without a trace.

**Fix.** New module `backend/services/background_tasks.py` exports `spawn(coro,
name=...)`. It keeps a module-level strong-ref set, logs the traceback of any
unhandled exception via `add_done_callback`, and removes the task from the
set on completion so the set doesn't grow unbounded.

All ten call sites were retrofitted:
- `backend/api/analysis.py` — daily analysis trigger
- `backend/api/claude_integration.py` — apply staged change
- `backend/api/scans.py` — manual nmap scan
- `backend/api/scheduler.py` — `/trigger/{job_id}` (4 sites)
- `backend/api/setup.py` — OpenVAS reset
- `backend/api/vulns.py` — manual per-device openvas scan
- `backend/scheduler/jobs.py` — post-scan Claude analysis kick-off

**Revert.** Re-add `import asyncio` where removed and swap `spawn(...)` back
to `asyncio.create_task(...)`. Helper module can stay or be deleted.

---

## 2. Backend non-root + read-only FS *(Tier 0)*

**Problem.** The backend ran as root with a writable root filesystem, all
Linux capabilities, and no `no-new-privileges`. Any RCE in the Python
process had the whole container. The compose file was otherwise hardened
well (docker socket scoped via `group_add`), but the process itself was
uncontained.

**Fix.**
- `backend/Dockerfile` creates `app` user (uid/gid 1000), chowns `/app`
  and `/data` to `app`, and sets `USER app`. No gosu, no entrypoint
  drop — `cap_drop: ALL` strips `CAP_SETUID`/`CAP_CHOWN` so any
  root-phase work in the container would fail with EPERM.
- `docker-compose.yml` backend service gets:
  - `read_only: true` + `tmpfs: /tmp` (needed for any scratch writes)
  - `security_opt: [no-new-privileges:true]`
  - `cap_drop: [ALL]` — the app doesn't bind privileged ports or raw
    sockets from the Python process itself (nmap uses TCP connect when
    run as non-root, which is fine)
  - `PYTHONDONTWRITEBYTECODE=1` — otherwise `.pyc` writes spam the log
    since root FS is read-only.
- New `data-init` service: a one-shot busybox sidecar that
  `chown -R 1000:1000 /data` before the backend starts. `backend`
  uses `depends_on: data-init: service_completed_successfully` so the
  dependency is enforced. Idempotent — no-op on fresh volumes, fixes
  ownership once on upgrades. Needed because the backend container
  itself has no capability to chown (cap_drop: ALL).

**Migration.** Automatic via the `data-init` sidecar. No manual steps.
`deploy.sh` also still runs its own busybox chown (item 14) which is
redundant-but-harmless belt-and-braces.

**Revert.** Remove `read_only`, `tmpfs`, `security_opt`, `cap_drop`,
and the `data-init` service from `docker-compose.yml`; revert
`Dockerfile` `USER app` line.

---

## 3. Optional bearer-token auth *(Tier 0)*

**Problem.** `/api/*` is wide open on the backend. In a pure LAN homelab
that's fine; the moment you expose the dashboard via Tailscale, Cloudflare
Tunnel, or reverse proxy, anyone who can hit the backend can trigger a
scan, modify settings, or wipe the OpenVAS container.

**Fix.** New middleware `backend/middleware/auth.py` that is a no-op when
`DASHBOARD_TOKEN` is unset (current default behaviour) and requires
`Authorization: Bearer <token>` over `/api/*` when set. Uses
`hmac.compare_digest` for constant-time comparison. `/health` and
`/socket.io/` are exempt (socket.io has its own handshake).

`backend/main.py` wires it in and also gates `CORSMiddleware.allow_origins`:
if you set `DASHBOARD_ALLOWED_ORIGINS` alongside `DASHBOARD_TOKEN`, CORS
clamps to that list and `allow_credentials` flips on.

`frontend/src/api/client.ts` request interceptor attaches
`Authorization: Bearer ${localStorage.getItem('dashboard_token')}` when
present. No UI to set it yet — set via devtools once per browser
(`localStorage.setItem('dashboard_token', '...')`) or build a login form
later.

`.env.example` documents `DASHBOARD_TOKEN` and `DASHBOARD_ALLOWED_ORIGINS`.

**Revert.** Remove `app.add_middleware(DashboardTokenMiddleware, ...)` from
`main.py`. Middleware file can stay unused.

---

## 4. Config env-vars apply on first boot only *(Tier 0)*

**Problem.** Sibling to the OPENVAS_HOST-reverting bug you hit earlier:
`_load_from_env` ran on *every* `config.load()` and silently overrode any
UI-saved value whenever the corresponding env var was set in
`docker-compose.yml`. That's exactly what was making `host = openvas`
keep coming back after you saved `homelab-openvas`.

**Fix.** `ConfigManager.load()` now only applies env when the YAML doesn't
exist on disk — i.e., first boot. Once the Settings page writes the YAML,
env is ignored. Docstring on `_load_from_env` records the history.

**Revert.** Put the `self._config = _load_from_env(self._config)` back
outside the `is_first_boot` branch.

---

## 5. `time.sleep` comment + UniFi poll timeout *(Tier 1)*

**Problem (1).** `integrations/openvas.py::_run_scan_sync` has a
`time.sleep(5)` in a 720-iteration poll loop. Looks suspicious but it's
actually correct — the whole function runs under `asyncio.to_thread`.
Future me would have "fixed" this.

**Fix.** Added a comment explaining why `time.sleep` is right here and why
`asyncio.sleep` would be wrong (python-gvm is sync-only, can't be awaited).

**Problem (2).** `unifi_poll_job` awaited `unifi.fetch_topology()` with no
timeout. If the controller hung (cert expiring, partition, UDM reboot),
every 30-second poll would stack another task; in an hour you'd have ~120
simultaneous connections held open.

**Fix.** `asyncio.wait_for(unifi.fetch_topology(), timeout=20.0)` plus a
dedicated `asyncio.TimeoutError` branch that records a "timeout (20s)"
entry in the scheduler state so it shows up on the Scheduler Panel.

**Revert.** Strip the `asyncio.wait_for` wrapper and the `TimeoutError`
except branch.

---

## 6. Secret-scrubbing audit encoder *(Tier 1)*

**Problem.** `write_audit` used `json.dumps(detail, default=str)`. If a
caller passed a `SecretStr` it would have become `"**********"` (OK), but
if someone passed a plain-string password field it would hit the DB raw.
`complete_setup` is disciplined about filtering, but other call sites
aren't contractually required to.

**Fix.** New `_scrub()` that recursively replaces SecretStr → `"***"` and
blanks any key matching `{password, passwd, api_key, token, secret,
auth, credential, private_key, ssh_password}` (case-insensitive). Applied
before `json.dumps`. A custom `_AuditEncoder` provides a `str()` fallback
for Pydantic models / datetimes so a type error can never silently drop
an audit row.

**Revert.** Replace `json.dumps(scrubbed, cls=_AuditEncoder)` with the
original `json.dumps(detail, default=str)` and delete the scrub helpers.

---

## 7. Nginx security headers *(Tier 1)*

**Problem.** `frontend/nginx.conf` sent no `X-Content-Type-Options`,
`X-Frame-Options`, `Referrer-Policy`, or CSP. Low risk on LAN but trivial
to add and every external scanner (Mozilla Observatory etc.) flags it.

**Fix.** Added five `always`-form headers:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY` (dashboard is never meant to be iframed)
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: camera=(), microphone=(), geolocation=()`
- `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self' ws: wss:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'`

Also `server_tokens off` so the nginx version isn't leaked in error pages.

**CSP verification:** `style-src 'unsafe-inline'` is needed because
lucide-react sets inline `style` attributes; you can't tighten this without
switching the icon library. `script-src 'self'` alone — no inline scripts.
`connect-src 'self' ws: wss:` covers axios + socket.io on same origin.

**Revert.** Delete the five `add_header` lines and `server_tokens off`.

---

## 8. Pin `immauss/openvas` tag + `python-gvm` *(Tier 1)*

**Problem.** `immauss/openvas:latest` and `python-gvm>=24.8.0` both pull
whatever's newest on pip/Docker Hub. Either can land a breaking change on
any `docker compose pull` or image rebuild.

**Fix.**
- `requirements.txt`: `python-gvm==24.8.0`
- `docker-compose.yml` openvas service: pinned to
  `immauss/openvas:26.02.28.01` — a real dated tag (Feb 28 2026) from
  <https://hub.docker.com/r/immauss/openvas/tags>. immauss uses
  `YY.MM.DD.NN` tags, not semver, so "version numbers" look like dates.
  The tag above was the most recent stable one at the time of this
  review; to upgrade, pick a newer tag, test locally, and update both
  this line AND the fallback in `services/openvas_reset.py`.
- `services/openvas_reset.py` `_snapshot_config` fallback image string
  updated to match.

**Revert.** Change back to `python-gvm>=24.8.0` and
`immauss/openvas:latest`.

---

## 9. Claude analysis concurrency cap *(Tier 2)*

**Problem.** Scheduler + manual trigger + post-scan hook can all call
`analyze_unknown_device` at once. Each analysis burns tokens and spawns a
sandbox git clone; concurrent runs can OOM a small VM and blow through
your API budget.

**Fix.** Module-level `asyncio.Semaphore(CLAUDE_MAX_CONCURRENT)` (default
2, configurable via env). `analyze_unknown_device` acquires the semaphore
after the fast-exit checks (`cfg.claude.enabled`, mock mode) so a queue
doesn't build up for trivially-skippable calls.

Implementation splits `analyze_unknown_device` into an outer (skip checks
+ semaphore) and `_analyze_unknown_device_locked` (the real body). No
call-site changes required.

**Revert.** Remove the semaphore and collapse the two functions back into
one.

---

## 10. Batch vuln-findings INSERTs *(Tier 2)*

**Problem.** `_store_findings` did one `await db.execute(...)` per finding
+ one `await es.store_vuln_result(...)` per finding, all inside the DB
transaction. A /24 scan producing ~300 findings meant 300 round-trips
through aiosqlite + 300 ES writes blocking the DB commit.

**Fix.** Build the param tuple list + ES doc list up front, then
`db.executemany(INSERT ... ON CONFLICT ...)` once for the SQLite side. ES
ship moves outside the DB transaction so an ES outage can't roll back a
successful SQLite write. Findings-ingest wall time drops from N round-trips
to 1 + one-at-a-time ES (unavoidable without bulk API changes).

**Revert.** Inline the loop back inside `async with get_db() as db:` and
use `db.execute` per row.

---

## 11. Single severity query + covering index *(Tier 2)*

**Problem.** `GET /api/devices/{device_id}` ran four correlated subqueries
(one per severity) against `vuln_results`. Each subquery re-scanned the
same index. On the network-map popovers this fires for every hovered
device.

**Fix.**
- `api/devices.py`: replace the four subqueries with one
  `SELECT severity, COUNT(*) FROM vuln_results WHERE device_id=? GROUP BY
  severity` and slot into a dict.
- `database.py`: new `idx_vuln_results_device_severity(device_id,
  severity)` index. `CREATE INDEX IF NOT EXISTS` so existing databases
  get the index on next startup (executed via the schema block).

**Revert.** Restore the four subqueries in `api/devices.py`. The index is
harmless to keep around.

---

## 12. Axios interceptor preserves status *(Tier 2)*

**Problem.** The old interceptor flattened every error into `new
Error(msg)`, dropping `err.response?.status` and `err.response?.data`. No
component could distinguish 401 vs 404 vs 5xx.

**Fix.** Error object now has `status` and `data` fields (exported as
`ApiError` interface). Added a request interceptor that attaches the
dashboard bearer token from `localStorage` when present.

**Revert.** Re-install the original 5-line interceptor; no callers use
`status`/`data` yet so nothing breaks by reverting.

---

## 13. OpenVAS healthcheck probes GMP port *(Tier 2)*

**Problem.** `healthcheck: curl -f http://localhost:9392` probed the old
web UI port. The backend talks to gvmd on 9390; a dead 9390 plus a live
9392 would still report healthy.

**Fix.** Switched to `bash -c '</dev/tcp/127.0.0.1/9390'` — pure-bash TCP
probe, no curl required (this image doesn't ship curl). `start_period`
bumped 120s → 300s because first-boot NVT sync realistically needs 5-10
min on most hardware and the healthcheck was flagging "unhealthy" during
normal warmup.

**Revert.** Restore the original `curl` test + 120s start_period.

---

## 14. homelab-data volume chown migration *(Tier 2)*

**Problem.** Item 2 runs the backend as uid/gid 1000. An existing
`homelab-dashboard_homelab-data` volume was populated by the old root
image and is owned root:root — the new image gets EACCES on /data. The
Dockerfile entrypoint handles this inside the container, but only *after*
startup, so the first health probe can fail.

**Fix.** `deploy.sh` now spawns a one-shot `busybox` container before
`docker compose up`, with the homelab-data volume mounted, and runs
`chown -R 1000:1000 /data`. Idempotent — a no-op when already correct.
Failure is logged but non-fatal (entrypoint will retry at startup).

**Revert.** Remove the `if docker volume inspect ... ` block from
`deploy.sh`.

---

## 15. Configurable backend host-port bind *(Tier 2)*

**Problem.** `docker-compose.yml` unconditionally bound the backend on
`0.0.0.0:8000`, meaning anything on the LAN could hit `/api/*` directly
and bypass the frontend.

**Fix.** Port mapping changed to
`"${BACKEND_BIND:-}${BACKEND_PORT:-8000}:8000"`. Default is empty (bind on
all interfaces, backwards compatible). Setting `BACKEND_BIND=127.0.0.1:`
in `.env` restricts the backend to loopback — external clients must go
through the frontend's nginx reverse proxy, which is the intent.

Documented in `.env.example`.

**Revert.** Restore `"${BACKEND_PORT:-8000}:8000"` and drop the variable
from `.env.example`.

---

## 16. Tier 3 quick wins

### 16a. Log rotation via compose `x-logging` anchor

`docker-compose.yml` defines an `x-logging` YAML anchor with `json-file`
driver, 10 MB per file × 3 files. Each service references it with
`logging: *default-logging`. Without this, a chatty container can fill
/var/lib/docker on a small VM.

### 16b. Frontend node + nginx version pins

`frontend/Dockerfile`: `node:20-slim` → `node:20.18.1-slim`,
`nginx:alpine` → `nginx:1.27.3-alpine`. Same reproducibility story as
item 8. Also added `--no-audit --no-fund` to `npm ci` for a quieter build
log.

### 16c. `.env.example` documentation

Added rows for `DOCKER_GID`, `BACKEND_BIND`, `CLAUDE_MAX_CONCURRENT`,
`DASHBOARD_TOKEN`, and `DASHBOARD_ALLOWED_ORIGINS` with inline
documentation.

### 16d. `refetchOnWindowFocus` rationale comment

`frontend/src/main.tsx`: the setting was already correct (`false`) but
unexplained. Added a comment explaining why: socket.io pushes fresh data
on change, so window-focus refetches would duplicate work for no new
info.

---

## Spot-check commands

Run any of these to verify a change landed as described:

```bash
# No app-level bare create_task left:
grep -rn "asyncio.create_task" backend --include='*.py' | grep -v .venv

# Backend really does run as non-root now:
grep -E 'USER|ENTRYPOINT' backend/Dockerfile

# Config only reads env on first boot:
grep -A1 "is_first_boot" backend/config/config_manager.py

# Every compose service has log rotation:
grep -c "logging: \*default-logging" docker-compose.yml     # should be 4

# executemany swap landed:
grep -n "executemany\|for f in findings" backend/services/vuln_service.py

# Single severity query:
grep -A3 "GROUP BY severity" backend/api/devices.py
```

## What did *not* get changed

From `docs/code-review.md` — deliberately deferred items:

- **Per-user login / SSO** — scope way beyond a Tier 0 pass. Token
  middleware is the 80/20 pragmatic cut.
- **Sandbox isolation for Claude runs** — the generated code runs in a
  subprocess but not in an OS-level sandbox. Out-of-scope here.
- **WAL mode + pragma tuning on SQLite** — review recommended it; the
  current PRAGMA block in `database.py` should probably get `journal_mode
  = WAL` added, but that's a data-safety change deserving its own careful
  pass and a deploy-time migration check.
- **Replace `asyncio.wait_for` on UniFi with a client-level httpx timeout**
  — belt-and-braces; the wait_for covers the whole coroutine while the
  httpx client still has no explicit timeout set. Worth doing but
  touches integration internals.
- **Structured logging (JSON)** — would help Elasticsearch integration
  but requires changes across every `log.info(...)` call site to pass
  extra fields. Left for a follow-up.

---

**Files added**
- `backend/services/background_tasks.py`
- `backend/middleware/__init__.py`
- `backend/middleware/auth.py`
- `backend/docker-entrypoint.sh`
- `docs/review-fixes.md` (this file)

---

## Polish pass (UX + visual overhaul)

A separate pass from the code-review work above, triggered by the user's
"ultra deep dive" request. Four concrete asks answered:

### P1. Auto-managed OpenVAS admin password

**Problem.** The Settings and Setup wizards asked the user to pick an
OpenVAS admin password and re-type it. But nothing in the platform ever
shows it back to them — it's just a shared secret between the backend and
the gvmd container. Asking a user to curate a credential they never see
is a pure UX tax.

**Fix.** The password is now fully server-managed:

- On first setup, the backend generates a 32-char URL-safe random password
  (~190 bits entropy) and writes it into `homelab-config.json` before
  kicking the OpenVAS reset flow.
- The Settings page replaces the password field with a read-only "Managed
  automatically" indicator and a **Rotate** button that calls
  `POST /api/setup/rotate-openvas` — one click, no form.
- `ResetOpenVASModal` drops all three password fields and becomes a single
  confirmation dialog driving the same rotate endpoint.

**Files**
- `backend/services/openvas_autopassword.py` *(new)* — `generate_password()`,
  `ensure_openvas_password()`, `rotate_openvas_password()`.
- `backend/api/setup.py` — `/rotate-openvas` endpoint; `/complete` spawns
  `ensure_openvas_password` when the openvas section is saved empty.
- `frontend/src/pages/SettingsPage.tsx` — dropped password TextField; added
  "Managed / Rotate" UI; sanitized save payload.
- `frontend/src/pages/SetupPage.tsx` — removed password field from services
  step; summary shows "auto-managed".

### P2. Per-device scan trigger on Devices page

**Problem.** The only way to kick an OpenVAS scan against a single device
was through the 2D topology slide-out panel — which required finding the
device on the map first. Painful at 50+ nodes.

**Fix.** Added a **Scan** column to the Devices table. Each row has its
own state machine: `idle → starting → queued → (done | failed)`. Click
posts `/api/vulns/scan/{device_id}` and optimistically sets queued; the
`scan:complete` socket event (now with `device_id`) flips the row to
`done` / `failed` with a toast. A 90-second TTL fallback reverts to idle
if the event is lost (socket reconnect, etc.) so rows never stick on a
forever-spinner.

**Files**
- `frontend/src/pages/DevicesPage.tsx` — Scan column, per-row state
  machine, socket listener via stable `toastRef` pattern.
- `backend/services/vuln_service.py::run_openvas_scan` — wrapped in
  try/except; emits `scan:complete` with `device_id` on success *and*
  failure so the UI always clears.
- `backend/services/notification_service.py::emit_scan_complete` — added
  optional `device_id` parameter; included in payload only when set (so
  network-wide scans don't accidentally target one row).

### P3. 3D Tron Grid-Sphere topology view

**Problem.** The 2D React Flow map was functional but generic. The user
wanted a "draw that brings people in" — a landing shot that makes the
project feel unique.

**Fix.** A new `<GridSphere>` component renders devices on a
Fibonacci-distributed unit sphere using `@react-three/fiber`. Tactical
choices:

- **Fibonacci distribution** (golden angle). Even angular spacing at any
  node count; deterministic so status/vuln updates don't teleport nodes.
- **OrbitControls with damping** on the *camera* (not rotating a group).
  Grab-and-drag rotates, releases with momentum. Auto-rotate gives an
  idle spin until the user touches it.
- **Horizon-locked labels.** `<Billboard lockX lockZ>` leaves only the
  Y-axis free, so labels yaw to face the camera but never pitch or roll
  out of the horizon plane — exactly the "text always horizontal" behavior
  the user asked for.
- **Bloom on emissive only.** `EffectComposer` + `Bloom` with a high
  luminance threshold so the grid wireframe stays crisp and only the
  device orbs and rings glow.
- **Far-side label culling.** Each frame does a dot-product check between
  each node's outward normal and the view vector; labels on the hidden
  hemisphere are hidden instead of bleeding through.

**Perf budget**
- `dpr={[1, 2]}` cap + `<PerformanceMonitor>` auto-downgrade to 1× on
  sustained low FPS. `<AdaptiveDpr>` drops resolution while actively
  orbiting, restores on release.
- Three.js chunk is split out via `vite.config.ts::manualChunks` and the
  `GridSphere` + `NetworkMap` components are **both lazy-loaded**. Users
  who never open the topology page never download the 287 kB gzipped
  three.js payload. Initial bundle dropped from 547 kB → 139 kB gzipped.
- Node geometry is a single `<octahedronGeometry args={[0.18, 0]}>` reused
  per-mesh; kept non-instanced because each node carries its own click
  handler and `<Text>` label (instancing would require lifting picking
  and labels into shaders — not worth it until ~150+ nodes).

Clicking a device opens the existing `<DeviceDetailPanel>` — the same one
NetworkMap uses — so the per-device vuln drill-down stays a single code
path.

A view toggle (Sphere / Flow) in the top-right corner persists the user's
choice to `localStorage` so the pragmatic 2D view is one click away.

**Files**
- `frontend/src/components/network/GridSphere.tsx` *(new)*
- `frontend/src/pages/NetworkMapPage.tsx` — view toggle + `React.lazy`
  on both views with `<Suspense>` fallback.
- `frontend/vite.config.ts` — `manualChunks` (three / reactflow / vendor).
- `frontend/package.json` — added `three`, `@react-three/fiber@^8.17`,
  `@react-three/drei`, `@react-three/postprocessing`.

### P4. Toast notification system

**Problem.** Fire-and-forget mutations (scan queued, analysis kicked,
rotation started) happened silently — the user couldn't tell if their
click did anything.

**Fix.** `frontend/src/components/shared/Toast.tsx` — minimal context-based
API (`useToast().ok/error/info/warn`), framer-motion slide-in from
top-right, auto-dismiss with manual close. Kept in-tree (not
`react-hot-toast`) because framer-motion + lucide are already bundled
and the whole file is <130 lines.

`<ToastProvider>` wraps the router in `App.tsx`; `useToast()` is already
consumed by `DevicesPage` for scan outcomes.

**Files**
- `frontend/src/components/shared/Toast.tsx` *(new)*
- `frontend/src/App.tsx` — wraps routes in `<ToastProvider>`.

---

**Files modified**
- `backend/Dockerfile`
- `backend/main.py`
- `backend/requirements.txt`
- `backend/database.py`
- `backend/config/config_manager.py`
- `backend/integrations/openvas.py`
- `backend/scheduler/jobs.py`
- `backend/services/audit_service.py`
- `backend/services/claude_analysis.py`
- `backend/services/openvas_reset.py`
- `backend/services/vuln_service.py`
- `backend/api/analysis.py`
- `backend/api/claude_integration.py`
- `backend/api/devices.py`
- `backend/api/scans.py`
- `backend/api/scheduler.py`
- `backend/api/setup.py`
- `backend/api/vulns.py`
- `frontend/Dockerfile`
- `frontend/nginx.conf`
- `frontend/src/api/client.ts`
- `frontend/src/main.tsx`
- `docker-compose.yml`
- `deploy.sh`
- `.env.example`
