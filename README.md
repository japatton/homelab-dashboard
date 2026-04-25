# Homelab Dashboard

A self-hosted network-awareness console for homelabs. Discovers every device on
your network, names them, watches them, scans them for vulnerabilities, pulls
alarms from your firewalls, and gives you one cohesive surface to see the
whole thing. Built on FastAPI, React, Docker Compose, and a Tron aesthetic.

[![License: MIT](https://img.shields.io/badge/License-MIT-00e5ff.svg)](./LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![Node 20+](https://img.shields.io/badge/node-20+-green.svg)](https://nodejs.org/)
[![Docker](https://img.shields.io/badge/docker-compose-2496ED.svg)](https://docs.docker.com/compose/)
[![Status](https://img.shields.io/badge/status-beta-orange.svg)](#status)

---

## What it does

- **Discovers** every IP on your network via Nmap sweeps, with service/banner
  detection for the ones that answer.
- **Enriches** discovered hosts with a UniFi Controller / UDM Pro client list
  (hostnames, switch ports, AP associations) so your smart bulbs aren't just
  unnamed MAC addresses.
- **Pulls gateway signal** from OPNsense (Suricata alerts, DHCP/ARP leases,
  interface stats) and Firewalla MSP (device roster, alarms) into a unified
  Security feed.
- **Scans for vulnerabilities** via OpenVAS / Greenbone — scheduled or
  per-device, credentialed or not.
- **Identifies unknowns** with Claude Code (or the Anthropic API) when an
  unrecognised device shows up, generating a scoped integration module that
  you review and apply.
- **Runs local AI analysis** via Ollama for daily security posture summaries
  that stay on your own hardware.
- **Tracks everything** in a built-in audit log — every scan, every scheduler
  job, every settings change, every alarm ack.

## Screenshots

> _Screenshots land here after the first public tag — see `docs/guide.html`
> for the current in-app walkthrough._

## Status

**Beta.** The stack runs cleanly in single-instance homelab deployments and is
used in production by the author. The public API surface is stabilising; minor
breaking changes may still land before 1.0. Hardware tested:

- UniFi UDM Pro, UniFi Dream Machine, classic Controller
- OPNsense 24.x (REST API)
- Firewalla Gold / Purple / Blue Plus (MSP cloud mode)
- OpenVAS via `immauss/openvas` image

Firewalla local-mode is included as an experimental scaffold — the local API
is undocumented, so the integration ships with a warning and returns empty
snapshots until the schema solidifies. See [ROADMAP.md](./ROADMAP.md).

---

## Quick start

Zero-hardware mock mode — the stack spins up with fabricated topology so you
can walk the UI before you trust it with the real network:

```bash
git clone https://github.com/YOUR-ORG/homelab-dashboard.git
cd homelab-dashboard
make mock
# → http://localhost:8080
```

Real deployment (requires a remote host with Docker + SSH):

```bash
# 1. Configure
cp .env.example .env
$EDITOR .env          # EXTERNAL_HOST, CERT_TYPE, DOMAIN_MODE at minimum

# 2. Deploy
./deploy.sh ubuntu@192.168.1.50

# 3. Point a browser at http://<EXTERNAL_HOST>:8080
# The setup wizard walks you through UniFi, Elasticsearch, OpenVAS, Claude.
```

The full narrative walkthrough lives in [`docs/guide.html`](./docs/guide.html).
Open it locally — no server required.

---

## Architecture

```
┌────────────────┐  socket.io   ┌──────────────────┐
│  Browser (SPA) │◀────────────▶│   FastAPI (py)   │
│   React + TS   │              │  • scheduler     │
│   React-Three  │              │  • /api routes   │
│   ReactFlow    │              │  • socket server │
└────────────────┘              └──────────────────┘
                                         │
   ┌─────────────────┬─────────┬─────────┼───────────┬─────────────┐
   ▼                 ▼         ▼         ▼           ▼             ▼
┌──────┐       ┌──────────┐ ┌────────┐ ┌────────┐ ┌─────────┐ ┌──────────┐
│ Nmap │       │ UniFi    │ │OPNsense│ │Firewalla│ │ OpenVAS │ │ Claude / │
│      │       │ UDM Pro  │ │ REST   │ │  MSP    │ │  GMP    │ │ Ollama   │
└──────┘       └──────────┘ └────────┘ └────────┘ └─────────┘ └──────────┘
   ▼                 ▼         ▼         ▼           ▼
┌─────────────────────────────────────────────────────────────┐
│ SQLite (hot state + audit log)        Elasticsearch (cold)  │
└─────────────────────────────────────────────────────────────┘
```

- **Backend** — FastAPI + Socket.IO on Uvicorn. APScheduler drives recurring
  Nmap / UniFi / OpenVAS / OPNsense / Firewalla polls. SQLite holds hot state
  (devices, topology, alarms, audit log); Elasticsearch is optional for long-
  term scan result history.
- **Frontend** — React 18 + TypeScript + Vite. React Query for data fetching
  with socket-driven invalidation. React-Three-Fiber for the 3D Grid Sphere
  view. React Flow for the 2D topology graph. Tailwind for styling.
- **Deploy** — Docker Compose. Backend runs as non-root with a read-only root
  filesystem and `cap_drop: ALL`. Nginx fronts the SPA with strict security
  headers + CSP. Optional profiles for OpenVAS, NGINX Proxy Manager.

See [docs/guide.html §13](./docs/guide.html) for the deep architecture pass
(data flows, DB schema, socket event contracts).

---

## Repository layout

```
.
├── backend/              FastAPI application
│   ├── api/              Route handlers (alarms, devices, settings, …)
│   ├── config/           Pydantic schema + YAML config manager
│   ├── integrations/     Per-vendor adapters (nmap, unifi, openvas, opnsense, firewalla, ollama, …)
│   ├── middleware/       Token-auth middleware
│   ├── models/           Shared Pydantic models
│   ├── scheduler/        APScheduler jobs + state
│   ├── services/         Business logic (device merging, alarm dedup, audit, notifications, …)
│   ├── mock/             Fixtures for BACKEND_MOCK=true
│   ├── tests/            pytest suite
│   ├── database.py       SQLite schema + migrations
│   ├── main.py           ASGI app entrypoint
│   └── requirements.txt
├── frontend/             React + Vite SPA
│   ├── src/
│   │   ├── api/          Axios client
│   │   ├── components/   Shared, layout, network, notifications, devices
│   │   ├── hooks/        useSocket, useDevices, useTopology, …
│   │   ├── pages/        One file per route
│   │   └── types/
│   └── package.json
├── docs/
│   ├── guide.html        In-depth visual walkthrough (the user-facing manual)
│   ├── code-review.md    Historical audit log
│   └── review-fixes.md   Companion log of applied fixes
├── integrations/         Claude Code sandbox (generated integrations land here)
├── docker-compose.yml
├── deploy.sh             Remote deploy script (SSH + Compose)
├── setup-wizard.sh       First-run .env bootstrap
├── undeploy.sh           Clean teardown
├── Makefile              dev/mock/build/up/logs/deploy shortcuts
├── CHANGELOG.md
├── CONTRIBUTING.md
├── SECURITY.md
├── ROADMAP.md
└── LICENSE
```

---

## Integrations

| Integration | Purpose | Required? |
|-------------|---------|-----------|
| Nmap | Network discovery & service fingerprinting | ✅ Always |
| UniFi Controller / UDM Pro | Hostname + switch/AP enrichment | Recommended |
| OPNsense | Firewall leases, interface roster, Suricata IDS alerts | Optional |
| Firewalla MSP | Device roster & alarms from the cloud API | Optional |
| OpenVAS / Greenbone | CVE scanning (credentialed or not) | Optional |
| Elasticsearch | Long-term scan result history | Optional |
| Claude Code CLI / Anthropic API | Unknown-device auto-identification | Optional |
| Ollama | Local daily AI security analysis | Optional |

All optional integrations are configured from the in-app Settings page and
persisted to `config.yml` on the backend volume — never baked into the image.

---

## Development

```bash
# One-shot dev stack with mocks
make mock

# Or, piece-by-piece:
make dev-backend          # uvicorn main:socket_app --reload on :8000
make dev-frontend         # vite dev server on :5173 (proxies /api → :8000)
```

Backend dev requirements:

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
pytest                              # full suite
pytest -k "alarm"                   # scoped
pytest --cov=. --cov-report=term    # with coverage
```

Frontend dev requirements:

```bash
cd frontend
npm install
npm run lint                        # eslint, max-warnings=0
npm run build                       # tsc + vite build
npm test                            # vitest
```

See [CONTRIBUTING.md](./CONTRIBUTING.md) for the full loop.

---

## Security posture

- **No default authentication** in the single-user homelab path — bind
  `BACKEND_BIND=127.0.0.1:` and front with a reverse proxy for anything
  past your LAN.
- **Opt-in bearer-token gate** — set `DASHBOARD_TOKEN` in `.env` and every
  `/api/*` route requires `Authorization: Bearer <token>`.
- **Secrets never logged** — audit encoder scrubs password/token/key fields
  recursively before writing the audit row.
- **Non-root container** with `read_only: true`, `cap_drop: ALL`, and
  `no-new-privileges` — compromise blast radius is bounded.
- **Strict nginx security headers** — CSP, X-Frame-Options: DENY,
  X-Content-Type-Options: nosniff, Permissions-Policy denying
  camera/mic/geo.

Full threat model and mitigations in [SECURITY.md](./SECURITY.md).
Vulnerability reporting: see SECURITY.md for the coordinated-disclosure path.

---

## Documentation

| File | Contents |
|------|----------|
| [`docs/guide.html`](./docs/guide.html) | Visual walkthrough — the primary user manual |
| [`CHANGELOG.md`](./CHANGELOG.md) | What changed between versions |
| [`CONTRIBUTING.md`](./CONTRIBUTING.md) | Dev loop, commit conventions, PR checklist |
| [`SECURITY.md`](./SECURITY.md) | Threat model + vulnerability reporting |
| [`ROADMAP.md`](./ROADMAP.md) | Planned work, known limitations, deferred ideas |
| [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md) | Community standards |
| [`docs/code-review.md`](./docs/code-review.md) | Historical audit (kept for provenance) |

---

## Contributing

PRs welcome. Please read [CONTRIBUTING.md](./CONTRIBUTING.md) first — every PR
needs to pass `pytest`, `npm run lint`, and `npm run build` cleanly, with new
behaviour covered by tests.

---

## License

MIT — see [LICENSE](./LICENSE).

The `docs/guide.html` in-app narrative (Tron/Grid voice) is part of the MIT
licence grant too. Re-use it freely.

---

## Acknowledgements

- [@react-three/fiber](https://github.com/pmndrs/react-three-fiber) and
  [@react-three/drei](https://github.com/pmndrs/drei) — the Grid Sphere
  wouldn't exist without you.
- [immauss/openvas](https://hub.docker.com/r/immauss/openvas) — the easiest
  way to put a real vuln scanner into a docker-compose.
- [Firewalla](https://firewalla.com) and [OPNsense](https://opnsense.org)
  teams — for documenting APIs that third parties can actually build against.
- The UniFi community for keeping notes on the undocumented edges of the
  UDM Pro API.
