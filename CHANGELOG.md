# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] — 2026-04-25

Maintenance release. Major dependency ecosystem refresh, CI hardening, and
ruff-driven code-quality cleanup. No user-visible feature changes.

### Changed
- **Backend dependencies refreshed** — fastapi 0.115 → 0.136.1,
  uvicorn 0.30 → 0.46, python-socketio 5.11 → 5.16, httpx 0.27 → 0.28.1,
  aiohttp 3.10 → 3.13.5, pydantic 2.9 → 2.13.3, pydantic-settings
  2.5 → 2.14, PyYAML 6.0.2 → 6.0.3, aiosqlite 0.20 → 0.22.1, apscheduler
  3.10 → 3.11.2, python-dotenv 1.0 → 1.2.2, asyncssh 2.17 → 2.22,
  python-multipart 0.0.9 → 0.0.26, elasticsearch[async] 8.15 → 9.3.0.
- **Backend test stack refreshed** — pytest 8.3 → 9.0.3, pytest-asyncio
  0.24 → 1.3.0, pytest-cov 5.0 → 7.1.0, types-PyYAML and httpx[http2]
  pins synced to runtime, respx 0.21 → 0.22 (required for httpx 0.28
  mock compatibility — without this, OPNsense/Firewalla integration
  tests silently returned empty results).
- **Frontend dependencies refreshed** — React + react-dom 18.3 → 19.2,
  @types/react + react-dom 18.3 → 19.2, vite 5.3 → 8.0 (Rolldown
  bundler), @vitejs/plugin-react 4 → 6, @react-three/fiber 8 → 9,
  @react-three/drei 9 → 10, @react-three/postprocessing 2 → 3,
  @tanstack/react-query 5.51 → 5.100, axios 1.7 → 1.15,
  three 0.169 → 0.184, eslint-plugin-react-hooks 5 → 7, globals 15 → 17,
  typescript-eslint 8.18 → 8.59, eslint-plugin-react-refresh 0.4 → 0.5.
- **CI actions** — actions/setup-python v5 → v6, actions/setup-node
  v4 → v6, docker/setup-buildx-action v3 → v4.
- **Docker base images** — nginx 1.27.3 → 1.29.8 (frontend), node
  20.18.1 → 20.19.6 (forced by transitive engine pins on
  @csstools/css-color-parser, eslint-visitor-keys, entities).
- **Dependabot policy hardened** — `dependabot.yml` now ignores
  semver-major + semver-minor for Docker `python` (stays on 3.12.x
  line) and semver-major for Docker `node` (stays on even-numbered
  LTS line). Pre-release Python 3.14 and odd-numbered Node 25 are no
  longer auto-proposed.
- **Vite 8 / Rolldown adoption** — `manualChunks` rewritten from object
  to function form (Rolldown requires it). Same three-way split
  (three / reactflow / vendor + app shell) is preserved so lazy-loading
  behaviour is unchanged.

### Fixed
- **Backend ruff lint clean** — 78 errors triaged (38 auto-fixable,
  40 hand-fixed across F401/F841/E402/E741) plus a `ruff format` pass
  across 55 files. `ruff check` + `ruff format --check` are now gating
  CI steps.
- **Toast dismiss test flake** — replaced `waitForElementToBeRemoved`
  with `waitFor(() => expect(...).not.toBeInTheDocument())` to fix a
  Node 20 / jsdom timing race where AnimatePresence exit was
  synchronous and the helper threw "element was already removed".
- **Frontend lockfile** — regenerated under Node 20.19.6-slim so
  `npm ci` no longer rejects in CI's pinned environment (npm 10
  vs npm 11 lockfile-v3 nested-dep handling).
- **CI coverage step** — added `@vitest/coverage-v8` to
  `devDependencies`. The previous CI run failed at startup with
  "MISSING DEPENDENCY '@vitest/coverage-v8'".
- **DeviceNode.tsx type strictness** — `Record<string, React.ElementType>`
  → `Record<string, LucideIcon>`. The new @types/react 19 infers
  `ElementType`'s prop type as `never` for the ambiguous fallback,
  which broke `<Icon size={18} style={...}>`.
- **useTopology.ts useRef** — pass an explicit `undefined` initial
  argument; React 19's @types/react no longer accepts the zero-arg
  form for non-DOM refs.

### Internal
- Code-quality follow-ups flagged for future PRs:
  - `eslint-plugin-react-hooks` v7's two new rules
    (`set-state-in-effect`, `refs`) are temporarily disabled in
    `eslint.config.js` — re-enable and refactor the 9 sites in
    `SettingsPage.tsx`, `useSocket.ts`, and `DevicesPage.tsx`.
  - `elasticsearch-py` 9 still accepts the deprecated `body=` kwarg;
    modernize the two call sites in
    `backend/integrations/elasticsearch_client.py` to explicit
    fields (`query=`, `mappings=`, `settings=`).

---

## [1.0.0] — 2026-04-24

Initial public release. Everything below shipped from the v0.1.0
baseline through the public-readiness sweep (docs, GitHub
infrastructure, test suites, security hardening).

### Added
- **Gateway integrations — OPNsense**: full REST-API adapter covering firmware
  probe, interface roster, ARP + DHCP leases, and Suricata IDS alert feed.
  Configurable `poll_interval_seconds` (default 60s). Scheduler registers an
  `opnsense_poll` job only when credentials are present.
- **Gateway integrations — Firewalla (MSP mode)**: cursor-paginated device
  roster + alarm feed against the Firewalla MSP cloud API. Type-code alarm
  severity mapping. Rate-limit-aware polling with hard page caps.
- **Gateway integrations — Firewalla (local mode)**: experimental scaffold
  for LAN-only Box API. Marked in the UI as experimental; test connection
  succeeds but snapshot returns empty until the local schema solidifies.
- **Security / Alarms page**: unified alarm feed surfacing OPNsense +
  Firewalla alarms with five-tier severity, source chips, live socket
  updates, per-row acknowledge/dismiss, and Archive-dismissed action.
  Alarm fingerprint dedup collapses storm repetition to a single row
  with `count++`.
- **Sidebar alarm badge**: Bell icon with red dot + count (capped `99+`)
  driven by `alarm:summary` socket event with a 60s poll safety net.
- **Docs — guide.html section 10 "Security & Alarms"**: full page
  documentation covering severity bands, dedup fingerprints, row actions,
  and live-update flow.
- **Docs — ROADMAP.md**: planned work, known limitations, deferred
  enhancements captured for public viewability.
- **Docs — SECURITY.md**: threat model, supported-version matrix,
  coordinated-disclosure process.
- **Docs — CONTRIBUTING.md / CODE_OF_CONDUCT.md**: dev loop, commit style,
  community standards.
- **GitHub infrastructure**: issue templates (bug, feature, security),
  pull-request template, CI workflow (lint + type-check + pytest +
  frontend build), and Dependabot configuration.
- **Backend test suite** under `backend/tests/` covering:
  - Pydantic config schema validation
  - OPNsense + Firewalla integration parsing and fingerprint determinism
  - Alarm service dedup + upsert ordering
  - Device merge precedence rules
  - `ip_expand` CIDR + dashed-range expansion
  - Audit service secret-scrubbing
  - Auth middleware token gating
  - Smoke tests for `/api/alarms`, `/health`, `/setup/status`
- **Frontend test suite** under `frontend/src/**/__tests__/` using Vitest +
  React Testing Library, covering Sidebar badge behaviour, SecurityPage
  severity sort/filter, and the Toast provider.

### Fixed
- `api/claude_integration.py::_do_apply` referenced an undefined module-level
  `log` via a runtime `log.info = __import__("logging").getLogger(__name__).info`
  hack. Added a proper module-level `log = logging.getLogger(__name__)`
  import; the hack path would have `NameError`'d on first execution.
- `main.py::_check_docker_socket` silent `except Exception: pass` on client
  close now debug-logs the exception.
- `main.py` lifespan `print()` of MOCK-mode message upgraded to
  `log.info()` so it reaches the configured logging pipeline.
- `integrations/opnsense.py::test_connection` sysinfo secondary probe now
  debug-logs the non-fatal error instead of swallowing silently.
- `frontend/src/pages/SecurityPage.tsx` dropped the `(summary as any)?.[s]`
  cast — the `AlarmSummary` interface already declares the severity keys.
- `frontend/src/pages/VulnsPage.tsx` + `components/network/DeviceDetailPanel.tsx`
  replaced `(vuln as any).cve_ids` with `vuln.cve_ids` (already on the
  `VulnResult` type) + a proper `Array.isArray` guard on the parsed value.
- `frontend/src/components/layout/Sidebar.tsx` alarm badge now exposes
  `role="status"` and a plural-aware `aria-label` for screen readers.

### Changed
- `.gitignore` expanded to cover pytest/mypy/ruff caches, coverage reports,
  local SQLite databases, `.vite/` and `*.tsbuildinfo`, editor dotdirs.
- Top-level stray `test` file (OpenVAS GMP XML dump from a debug session)
  removed from the repo root.

---

## [0.1.0] — 2026-04-18 (pre-release baseline)

First coherent build. Everything below shipped before public release prep
began; documented here for provenance since there was no prior changelog.

### Added
- **Discovery** — Nmap scan scheduler with configurable targets/interval,
  per-host service banners, and fan-out to Claude for unknown-device
  analysis.
- **UniFi integration** — UDM Pro / classic controller: site enumeration,
  client roster enrichment with hostname/switch-port/AP associations,
  latency sampling.
- **Topology views** — 3D Grid Sphere (react-three-fiber, Fibonacci
  distribution, bloom on emissive only, OrbitControls with damping) and
  2D React Flow graph. Toggle persisted in localStorage.
- **Devices page** — filterable table, per-row scan trigger, detail panel
  with service + vulnerability drilldown.
- **Vulnerabilities page** — OpenVAS-backed CVE feed with severity band
  filtering, per-row CVE detail expansion, scheduled + ad-hoc scan
  controls, optional credentialed-scan support via SSH password or key.
- **OpenVAS managed admin password** — auto-generated 32-char URL-safe
  secret on first boot, rotatable from the Settings page with a full
  container-reset flow (snapshot config → wipe volume → recreate →
  warmup verify → persist on success).
- **Claude Code integration** — scoped sandbox (`integrations/`) for
  auto-generated per-device integrations; review + apply UI with diff
  preview; audit trail.
- **Daily AI analysis** — optional Ollama-backed posture summary with
  configurable model + schedule.
- **Audit log** — 100-row ring buffer covering every scheduler run,
  settings change, scan trigger, apply/reject/rotate action. Secret
  scrubbing before persistence.
- **Settings page** — scheduler panel (run-now, pause/resume, interval
  edits), integration credentials (UniFi, Elasticsearch, OpenVAS,
  Claude, Ollama), scan credential manager, scan profiles.
- **Setup wizard** — two-stage (bash for compose-time values, in-app for
  runtime integrations). Skipped automatically in `BACKEND_MOCK=true`.
- **Deploy tooling** — `deploy.sh` (SSH + Compose, preflight, healthcheck
  polling), `undeploy.sh` (clean teardown with data preservation), and
  `setup-wizard.sh` (first-run `.env` bootstrap).
- **Optional Docker Compose profiles** — `proxy` (NGINX Proxy Manager),
  `openvas` (Greenbone scanner).

### Security
- Optional bearer-token auth middleware (`DASHBOARD_TOKEN`) gating
  `/api/*`.
- CORS clamping when `DASHBOARD_ALLOWED_ORIGINS` is set alongside the
  token.
- Backend container runs as uid 1000 with `read_only: true`,
  `cap_drop: ALL`, `no-new-privileges`, and a `tmpfs: /tmp` mount.
- Nginx security headers: CSP, X-Frame-Options: DENY, X-Content-Type-
  Options: nosniff, Referrer-Policy, Permissions-Policy.
- `immauss/openvas` and `python-gvm` pinned to exact versions.
- Audit encoder scrubs SecretStr + common secret keys recursively.
- Fire-and-forget task helper (`services/background_tasks.spawn`)
  prevents GC-collection of long-running coroutines (e.g. 10-minute
  OpenVAS reset flow).

---

[Unreleased]: https://github.com/japatton/homelab-dashboard/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/japatton/homelab-dashboard/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/japatton/homelab-dashboard/compare/v0.1.0...v1.0.0
[0.1.0]: https://github.com/japatton/homelab-dashboard/releases/tag/v0.1.0
