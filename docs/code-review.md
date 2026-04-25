# Homelab Dashboard — Consolidated Code Review

Synthesis of three parallel reviews (backend, frontend, ops/security). Findings
are deduplicated, reconciled, and reranked for actual impact on a single-user
homelab deployment (vs. a multi-tenant SaaS). Where a subagent overclaimed, I've
annotated the correction.

---

## Tier 0 — Critical (real bugs, act first)

### 0.1 Fire-and-forget `asyncio.create_task()` without holding a reference
**Files:** `backend/api/setup.py:175`, `backend/scheduler/jobs.py` (analysis
trigger), `backend/api/scans.py`, `backend/api/analysis.py`, `backend/api/scheduler.py`

Tasks created via `asyncio.create_task(coro)` without capturing the returned
`Task` object can be garbage-collected mid-execution. Python's docs call this
out explicitly: the event loop holds only a weak reference. For short-lived
tasks this is usually fine, but the OpenVAS reset runs for **5–15 minutes** in
the background — exactly the window where a GC cycle could collect it. The
user sees "reset started" in the toast, the modal polls `openvas:reset`, but
the coroutine quietly evaporates.

**Fix:** add a module-level background task registry in each place that spawns
long-lived work. Minimal pattern:

```python
_background: set[asyncio.Task] = set()

def spawn(coro: Awaitable, *, name: str | None = None) -> asyncio.Task:
    task = asyncio.create_task(coro, name=name)
    _background.add(task)
    task.add_done_callback(_background.discard)
    return task
```

Then every `asyncio.create_task(reset_openvas_password(...))` becomes
`spawn(reset_openvas_password(...), name="openvas-reset")`. One helper, consistent
everywhere.

### 0.2 Docker socket mount is root-equivalent with no mitigations
**File:** `docker-compose.yml:46`

The `/var/run/docker.sock:/var/run/docker.sock` mount gives the backend process
full control of dockerd — which means full control of the host. The
`group_add` is only about file-mode access; it doesn't reduce capabilities.
A SSRF, template injection, or a compromised pip dep is now a host takeover.

**For a homelab this is an accepted trade-off** (the whole point of the reset
button is that it exists), but the mitigations worth adding are cheap:

- Add `USER appuser` to `backend/Dockerfile` so the process runs non-root inside
  the container even if dockerd lets it do root-on-host things.
- Add `read_only: true` to the backend service with `tmpfs: [/tmp]` and the
  existing `homelab-data` writable mount — prevents code injection from
  persisting.
- Replace the direct socket mount with a hardened proxy
  (`tecnativa/docker-socket-proxy` is the standard) scoped to exactly the API
  calls the reset flow needs: `CONTAINERS=1`, `VOLUMES=1`, `NETWORKS=1`, and
  nothing else. Takes 5 lines in compose.

### 0.3 No authentication on any API route
**Files:** `backend/main.py` (CORS + no middleware), all of `backend/api/`

Every endpoint — including the destructive `reset-openvas`, all settings writes,
scan triggers — is anonymous. `allow_origins=["*"]` + `allow_credentials=True`
is also technically invalid per the CORS spec (browsers ignore credentials when
origin is `*`, but the intent is wrong).

For a homelab bound to a private LAN this is a conscious choice, but it's worth
at least a **single-token auth** that takes an hour to add:

```python
# backend/main.py
API_TOKEN = os.getenv("HOMELAB_TOKEN")  # generated in setup-wizard.sh

async def require_token(authorization: str = Header("")) -> None:
    if API_TOKEN and authorization != f"Bearer {API_TOKEN}":
        raise HTTPException(401)

app.include_router(router, dependencies=[Depends(require_token)])
```

Frontend adds it to `client.defaults.headers.common.Authorization`. If
`HOMELAB_TOKEN` is unset (dev mode), the dep no-ops. Same approach for
socket.io via `sio.on("connect")` handshake.

### 0.4 `OPENVAS_HOST` clobber pattern exists elsewhere too
**File:** `backend/config/config_manager.py:25-75` (`_load_from_env`)

We just fixed `OPENVAS_HOST`, but every other field follows the same pattern:
`if _env("UNIFI_URL"): config.unifi.url = _env("UNIFI_URL")`. These are safe
today because `docker-compose.yml` uses `${UNIFI_URL:-}` (empty default) — but
if anyone ever hardcodes a default in an env entry, the same UI-save-reverts-
on-restart bug reappears.

**Fix:** change `_load_from_env` to apply env overrides **only when the config
file didn't exist** (first-run bootstrap):

```python
def load(self) -> ConfigRoot:
    fresh = not self._path.exists()
    if fresh:
        self._config = ConfigRoot()
        self._config = _load_from_env(self._config)  # bootstrap from env
        self.save(self._config)
    else:
        raw = yaml.safe_load(self._path.read_text()) or {}
        self._config = ConfigRoot.model_validate(_migrate(raw))
        # Do NOT re-apply env here — UI owns persisted values.
    return self._config
```

This removes a whole class of "I saved it and it reverted" bugs.

---

## Tier 1 — High priority

### 1.1 OpenVAS save handler now saves host/port — verify all save handlers
**File:** `backend/api/setup.py:232-244`

I fixed the OpenVAS save in the prior turn. Audit the other sections:
`unifi` saves url/user/site/password (good), `elasticsearch` saves host/port/user/password (good), `claude` only saves `enabled` (intentional — no API key field in the UI yet), `ollama` saves all (good). OpenVAS is now fixed. **No further action**, but add a regression test: POST `/setup/complete` with each section, GET `/settings/current`, assert all fields came back.

### 1.2 `time.sleep()` inside python-gvm scan loop
**File:** `backend/integrations/openvas.py:343`

Sits inside a `gmp` context manager that runs via `asyncio.to_thread(...)`, so
it blocks a *thread*, not the event loop. Not a bug today, but one refactor
away from becoming one. At minimum, add a comment documenting the constraint,
and cap the polling loop iterations so a stuck scan can't hang forever.

### 1.3 UniFi polling has no timeout
**File:** `backend/scheduler/jobs.py` (UniFi poll job)

`await unifi.fetch_topology()` has no `asyncio.wait_for`. A stuck controller
(wifi-hiccup, DNS flake, UDM reboot) blocks the scheduler tick and cascades
into late Nmap / OpenVAS runs. Wrap in `asyncio.wait_for(..., timeout=30)` and
log+continue on timeout. Same check for every other integration call in the
scheduler.

### 1.4 Audit log `default=str` can serialize SecretStr surfaces
**File:** `backend/services/audit_service.py:48`

`json.dumps(detail, default=str)` — in practice, Pydantic v2's `SecretStr`
returns `"**********"` from `str()`, so it's currently not a leak. But it's
one Pydantic-version-bump or one accidentally-passed plaintext dict away from
being one. Belt-and-suspenders:

```python
class _AuditEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, SecretStr):
            return "[REDACTED]"
        return str(o)

json.dumps(detail, cls=_AuditEncoder)
```

### 1.5 nginx missing security headers
**File:** `frontend/nginx.conf`

Add `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`,
`Referrer-Policy: strict-origin-when-cross-origin`, and a basic CSP:
`default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:`.
Five lines in `nginx.conf`, zero behavior change, closes clickjacking and
MIME-sniffing.

### 1.6 Backend runs as root inside the container
**File:** `backend/Dockerfile`

Combined with the docker-socket mount, any RCE is a host compromise. Adding
`USER appuser` (and a `chown -R appuser:appuser /app /data`) is a 3-line
change that materially reduces blast radius.

### 1.7 `immauss/openvas:latest` pulls unpinned
**File:** `docker-compose.yml:106`

Reproducibility + supply-chain hygiene. Pin to the exact tag you tested
against. Same story for `jc21/nginx-proxy-manager:latest`.

### 1.8 `python-gvm>=24.8.0` is a lower bound, not a pin
**File:** `backend/requirements.txt:15`

Every other dep is `==`. Pin this one too — python-gvm has changed protocol
class surface areas between versions (which is how we hit the `GMPv224` bug
originally).

---

## Tier 2 — Medium priority

### 2.1 Rate-limit concurrent Claude analyses
**File:** `backend/scheduler/jobs.py`

After every Nmap pass, every unknown device fans out to a Claude analysis
task. A first run with N=50 unknown devices queues 50 concurrent LLM calls —
which will OOM a Pi running Ollama, and is expensive if CLI-backed.

**Fix:** an `asyncio.Semaphore(1)` (or 2) guarding `run_analysis_for_device`.
Keeps throughput modest without a new dep.

### 2.2 Batch insert findings in `vuln_service._store_findings`
**File:** `backend/services/vuln_service.py`

N one-row INSERTs in a loop; easy win with `await db.executemany(...)`. On
a big scan (1000+ findings/device) this cuts ingest from ~1s to ~50ms.

### 2.3 Device-detail page does 4 scalar subqueries for severity breakdown
**File:** `backend/api/devices.py:68-71`

One query that `GROUP BY severity` and one Python loop is strictly cheaper.
Not a crisis, but adds up on a vuln-heavy host.

### 2.4 Missing index on `vuln_results(severity)`
**File:** `backend/database.py` schema

The Vulnerabilities page filters by severity. With 10k+ findings, a full-table
scan shows up. One-line migration:

```sql
CREATE INDEX IF NOT EXISTS idx_vuln_results_severity ON vuln_results(severity);
```

### 2.5 In-memory `_jobs` dict for nmap progress
**File:** `backend/api/scans.py`

State dies on backend restart, and it's not safe to shard across workers if
you ever scale to `--workers 2`. Move to an `ad_hoc_jobs` SQLite table; ship a
row per job; poll reads from DB. Frees you from a whole class of future bugs.

### 2.6 axios error interceptor drops status code
**File:** `frontend/src/api/client.ts`

Upstream catches can't tell 422 from 500 because the interceptor converts
everything to `new Error(detail)`. For the feature-level retry/UX to work
(e.g., "retry on 429"), attach the status:

```ts
const e: any = new Error(detail)
e.status = err.response?.status
e.data = err.response?.data
return Promise.reject(e)
```

### 2.7 OpenVAS healthcheck probes port 9392 (web UI) not 9390 (GMP)
**File:** `docker-compose.yml:121`

Backend talks to 9390. If GMP hangs but the HTTPS UI serves, compose reports
healthy but scans fail. Switch the check to `nc -z localhost 9390` (or a GMP
`<get_version/>` round-trip).

### 2.8 Project rename will orphan `homelab-data` on existing installs
**Files:** `docker-compose.yml` (project name pin), `deploy.sh`

We handled `openvas-data` with a two-name fallback in `openvas_reset.py`, but
`homelab-data` (the SQLite + config volume) will silently be left behind for
any user who had `passwordmanager_homelab-data` already. They'll wake up to a
"fresh install" setup wizard.

**Fix:** a pre-flight step in `deploy.sh` that detects the old volume and
either renames it (requires stop+`docker volume create` old-to-new copy) or
warns the user loudly. Or ship a one-shot migration container.

### 2.9 Uvicorn binds 0.0.0.0 and the port is published
**Files:** `backend/Dockerfile` (CMD), `docker-compose.yml:14`

`ports: ["${BACKEND_PORT:-8000}:8000"]` plus `--host 0.0.0.0` means the
backend is reachable from the host network directly, bypassing nginx's
(future) security headers. For prod-like deploys, change `ports` to `expose`
so only the docker network can reach it, and let frontend/nginx be the only
external face.

---

## Tier 3 — Low priority / nits

### 3.1 Frontend agent findings I disagree with
Flagging these because I verified them and they're wrong — listing them so
you don't chase them on my recommendation:

- **"`useSocket` singleton causes double-listeners in strict mode"** — false.
  The `on` callback has `useCallback([], ...)` so it's referentially stable;
  strict mode double-mount attaches → cleans up → reattaches cleanly. No
  duplicates.
- **"Stale closure in `ResetOpenVASModal` socket listener via `on` dep"** —
  false for the same reason. `on` doesn't change, so the effect doesn't
  re-fire.
- **"Audit log listener leaks via `on` dep in AuditLogPage"** — same.

### 3.2 Socket event names as magic strings
Cheap fix: `frontend/src/types/socketEvents.ts` with a frozen const map.
Nice-to-have, not urgent.

### 3.3 Modal disables its own close button without aria explanation
**File:** `frontend/src/pages/SettingsPage.tsx` (ResetOpenVASModal)

The close button is disabled during `stopping/wiping/starting` stages. Add
`aria-label="Close (locked while reset is in progress)"`. Screen-reader users
otherwise hit a dead button with no feedback.

### 3.4 `CredTestBadge` detail text doesn't truncate
Long gvmd error strings can push the table layout. Add `max-w-[24ch] truncate`
with a `title={detail}` so the full text is in the tooltip.

### 3.5 No `refetchOnWindowFocus: false` globally
**File:** `frontend/src/api/client.ts` or wherever react-query is configured

Not strictly broken, but tab-inactive users still burn API traffic on
30-second intervals for audit log and device list. Either disable interval
refetch and rely on socket events (better), or `refetchIntervalInBackground:
false`.

### 3.6 `SCAN_PROFILES` / `SCHEDULER_JOBS` constants would benefit from `as const`
Tiny type-safety win, zero behavior change.

### 3.7 `detail` in audit log truncates to 6 key-value pairs silently
**File:** `frontend/src/pages/AuditLogPage.tsx`

Generic fallback renderer caps at 6 entries. If we add an action with a
bigger payload, users see a half-rendered audit row. Either raise the cap,
add a "…N more" indicator, or expand on click.

### 3.8 `.env.example` should include `DOCKER_GID`
We added the field to compose but `.env.example` probably doesn't document
it. Users who just `cp .env.example .env` and bring the stack up will get
the default 999, which is wrong on RHEL/Fedora.

### 3.9 Frontend `Dockerfile` uses `node:20-slim` not a specific digest
Reproducibility. Pin to `node:20.11.1-slim` or a SHA256.

### 3.10 No log rotation inside containers
Docker's default `json-file` driver can grow unbounded. Add to compose:

```yaml
x-logging: &default-logging
  driver: "json-file"
  options:
    max-size: "10m"
    max-file: "3"

services:
  backend:
    logging: *default-logging
```

---

## Feature enhancement ideas

Ordered by "how much does this codebase already half-support it".

1. **Persistent scan job history** (2.5 extension). Once `_jobs` moves to
   SQLite, you get a trivial "Scans" page showing historical runs, durations,
   outcomes — without any new integrations. Scheduler and ad-hoc both write
   there; UI reads a unified view.

2. **Credentialed-scan coverage dashboard**. The scan_credentials table +
   device table are enough to surface "of your N online hosts, M have a
   credential configured, K tested-green in the last 7 days". This is the
   single most useful view for a homelab vuln program.

3. **Credential rotation warnings**. Store `created_at` / `last_tested_at` on
   scan_credentials; show an amber badge when a credential is >90 days old or
   hasn't been successfully tested recently. Near-free given we already have
   a test probe.

4. **Reset-flow resumability**. If the backend restarts mid-warmup, the
   socket events are gone and the UI is stuck. A tiny `reset_state` row
   (stage, percent, started_at) written at each emit point lets the UI
   reconnect and resume the progress view.

5. **Audit log filtering / search**. 100 rows is small enough that
   client-side filtering is fine — add a type-ahead on action + actor.

6. **Socket-auth pairing with Tier 0.3**. If single-token auth lands, gate
   `sio.on("connect")` on the same token via the connection handshake.
   Prevents any anonymous origin from just subscribing to live events.

7. **OpenVAS pre-flight from the UI**. The `openvas_auth_failed` audit row
   exists; surface it in the sidebar as a red dot so users catch password
   drift *before* the next scheduled scan tries 50 devices.

8. **Structured JSON logging**. One-liner in `main.py` that emits
   `{timestamp, level, logger, message, **extras}`. Makes it feasible to
   point Elasticsearch at the backend's own logs via Filebeat.

9. **Ollama model warmup ping on startup**. When AI Analysis is enabled,
   fire one dummy prompt on backend boot to pull the model into GPU memory,
   so the first "real" analysis isn't also the slow one.

10. **Scan profile per-device override**. `SCAN_PROFILES` (quick/standard/
    deep) is already a thing; the device row has no column for it. Adding
    `devices.scan_profile` + a dropdown on the device card lets you run
    aggressive scans against your own infra and light ones against your
    smart bulbs.

---

## Summary — if I only had 4 hours

1. Tier 0.1 (spawn helper for background tasks) — **30 min**, prevents the
   reset flow from silently dying.
2. Tier 0.4 (config manager env-override semantics) — **20 min**, kills a
   whole class of "I saved it and it reverted" bugs forever.
3. Tier 1.3 (UniFi timeout) — **10 min**, one `asyncio.wait_for`, protects
   the scheduler.
4. Tier 1.5 + 1.6 (nginx headers + Dockerfile USER directive) — **30 min**,
   meaningful hardening with zero UX impact.
5. Tier 2.4 (severity index) — **5 min** SQL one-liner.
6. Tier 2.8 (homelab-data volume migration in deploy.sh) — **45 min**,
   prevents a very bad first impression on upgrade.
7. Tier 3.8 (DOCKER_GID in .env.example) — **5 min**, closes the
   "docker socket isn't working" support ticket.
8. Tier 0.3 lite (env-guarded single-token) — **1 hour**, meaningful auth
   that doesn't turn the homelab into an enterprise app.

Remaining time: start on the persistent-job-history refactor (2.5 + feature
idea #1). That unlocks a lot downstream.
