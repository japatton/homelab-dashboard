# Roadmap

Future enhancements for the Homelab Dashboard. Items here are *ideas* with
enough context to turn into an issue — they are not commitments. Community
PRs are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md) for how to propose
larger changes.

Each item lists the motivation, the rough shape of an implementation, and
the size estimate in relative terms (S / M / L). Size is about scope and
review burden, not hours.

---

## Near-term (next minor release)

### Multi-user auth with scoped tokens  ·  L
**Why:** Today the dashboard has a single shared bearer token
(`DASHBOARD_TOKEN`). That's fine for a single homelab operator, but fails
the moment a household has two admins who want separate audit trails or a
read-only viewer account.

**Shape:**
- Add a `users` table keyed by email/username with hashed passwords.
- Replace `DashboardTokenMiddleware` with a session-cookie + refresh-token
  scheme backed by the same table.
- Per-token scopes (`read:alarms`, `write:devices`, `admin:settings`)
  surfaced through the Settings UI.

**Dependencies:** `passlib[bcrypt]`, `python-jose` (already adjacent to
`httpx`'s stack).

### Alarm routing rules  ·  M
**Why:** The Security page now shows every alarm in one feed. At scale
(hundreds per day from IDS) users want "auto-ack noisy signatures",
"alert email/webhook on severity >= high", "route Firewalla-DNS-over-HTTPS
warnings to a separate tab".

**Shape:**
- `alarm_rules` table with `{source, signature_match, action, target}`.
- New `services/alarm_router.py` that runs each new alarm through the
  rules list before the dedup upsert.
- Simple UI on Security page → Rules tab.

### Webhook + email notifications  ·  M
**Why:** `notification_service.py` ships a stub for pushing alarms
outbound but doesn't actually have channels wired up. In-app badges are
nice; a phone push when your IDS catches something after you've gone to
bed is better.

**Shape:**
- Integrate `aiosmtplib` for email (SMTP settings in `config.yml`).
- Generic webhook POST for Slack/Discord/ntfy/gotify.
- Respect each user's "quiet hours" preference.

### Device grouping + labels  ·  M
**Why:** Devices page shows a flat list. When you have 60+ MACs the UX
falls apart. Labels let users group by "Living Room", "Servers", "Work"
without forcing a rigid hierarchy on the schema.

**Shape:**
- `device_labels (device_id, label)` join table.
- Multi-select label filter on DevicesPage.
- Inline label-editing from the device row.

### Vulnerability severity tuning  ·  S
**Why:** OpenVAS CVSS scores are industry-standard but miss context —
"critical" on a VM that can't reach the internet should be visually
de-escalated.

**Shape:**
- Per-device "trust zone" label (`internal`, `dmz`, `exposed`).
- Lookup table that modifies displayed severity based on zone.
- Keep raw CVSS in `raw` payload so the filter is reversible.

---

## Mid-term (next 1–2 minor releases)

### Topology map: real traffic overlay  ·  L
**Why:** `NetworkMapPage` renders a topological view of devices based on
MAC/IP relationships. Firewalla already reports per-device flow stats,
but we don't feed them into the map. Rendering a "busy" edge (line
thickness ∝ bytes/sec) would turn the map from reference diagram into
live situational awareness.

**Shape:**
- New `FirewallaIntegration.get_flows(window)` returning `(src, dst,
  bytes)` tuples.
- Per-edge animation in `components/network/TopologyGraph.tsx`.
- Sampling knob in Settings → Network → Flow overlay.

### Scheduled scan profiles  ·  M
**Why:** Nmap scans run on a fixed cadence with a single profile. Users
want "deep scan on Sunday nights, quick sweep on weekdays", "never scan
the printer because it crashes".

**Shape:**
- `scan_profiles` table with `{name, cron, targets, nmap_flags}`.
- New `background_tasks/scan_runner.py` consuming cron expressions via
  `croniter`.
- Per-device "exclude from scans" flag.

### Prometheus metrics endpoint  ·  S
**Why:** The dashboard *is* the monitor today. Power users already run
Prometheus/Grafana and would rather `/metrics` was a first-class surface
so they can build their own dashboards.

**Shape:**
- Add `prometheus_client`, mount `/metrics`.
- Export: alarm counts by severity, device online total, scan duration
  percentiles, integration error counters.
- Keep it behind the same `DASHBOARD_TOKEN` gate as `/api/*`.

### Vault-backed secret store  ·  L
**Why:** `config.yml` holds API tokens in plaintext at rest. Fine on a
single-user homelab, bad for any deployment where multiple people SSH in.

**Shape:**
- Plug `hvac` (HashiCorp Vault client) behind the `ConfigManager.get()`
  path, with Vault-free fallback to the existing YAML.
- SecretStr fields resolve from Vault at read-time, never written to
  disk.

### Export / import configuration  ·  S
**Why:** "I reinstalled my box, now I have to reconfigure everything"
is a recurring homelab pain. Users want a JSON export of their full
config (minus secrets) so they can version it in git.

**Shape:**
- `GET /api/setup/export` returning redacted YAML (SecretStr → `null`).
- `POST /api/setup/import` accepting the same shape, re-entering secrets
  via the setup wizard flow.

---

## Long-term (2+ minor releases / major release gated)

### Historical trend analytics  ·  L
**Why:** Everything in the dashboard is "right now". The data is already
there — alarms, scans, device status — but nothing summarises "your
network posture improved 15% this month because you patched CVE-2024-XYZ".

**Shape:**
- Rollup table `metrics_daily` populated from a nightly cron.
- New "Trends" page with line charts (Recharts — already a transitive
  dep).
- Drill-down from each trend into the detail events that caused it.

### Mobile-friendly PWA  ·  M
**Why:** The dashboard is designed for a widescreen Tron aesthetic. It's
*usable* on mobile, not *good*. For "check if anything is on fire" from
your phone at dinner, a PWA shell with push notifications would be
useful.

**Shape:**
- Add `vite-plugin-pwa` + service worker for offline shell.
- Web-push subscription table keyed by user_id.
- Mobile-first redesign of Security + Devices pages (cards, not tables).

### Plugin architecture for new integrations  ·  L
**Why:** Today adding a new gateway (Ubiquiti Dream Machine, Sophos XG,
pfSense native API) means editing `integrations/`, wiring into the
scheduler, and adding config shape. A proper plugin API would let the
community ship integrations without forking.

**Shape:**
- Declare an `Integration` protocol with `probe()`, `fetch()`,
  `parse_alarms()`, `parse_devices()` methods.
- Entry-point based discovery (`homelab_dashboard.integrations` group).
- Plugin config schema auto-generated from Pydantic models.

### AI-assisted incident triage  ·  L
**Why:** The Analysis page today is a one-shot prompt-and-response with
Ollama. A real operator workflow is "pull the last 100 alarms, correlate
them with the last 24h of scan diffs, propose 3 likely attack chains".

**Shape:**
- Tool-using agent loop (inspired by `ollama-tools`).
- Ground truth from the alarm/device/scan tables, not from web search.
- Per-analysis audit-log entry with the prompt + response for later
  review.

### Role-based access control (RBAC)  ·  L
Paired with multi-user auth above. Not just tokens with scopes — full
role model (`admin`, `ops`, `viewer`), per-page visibility rules, audit
trail for every mutation.

---

## Quality & DX backlog

These don't change what the dashboard does, they make it easier to work
on. Worth picking up between bigger items.

- **Coverage gate in CI.** Wire `pytest-cov` and `vitest --coverage`
  thresholds (start lenient: 60% statements, ratchet up).
- **Storybook for shared components.** `TronPanel`, `GlowButton`,
  `StatusIndicator`, `AlarmRow` in isolation with theme toggles.
- **Integration-test container.** Spin a real OPNsense / Firewalla MSP
  mock in a sidecar Docker network; mark `@pytest.mark.integration` and
  run nightly.
- **Pre-commit hooks.** `ruff` + `mypy` + `eslint` via `pre-commit` so
  local hooks match CI. Today it's honour-system.
- **Playwright end-to-end.** A single happy-path "log in → see devices
  → ack alarm → log out" run per PR. Smoke tests have caught
  two regressions already that unit tests missed.
- **ADR (Architecture Decision Records).** Kept lightweight
  (single-page, three headings) under `docs/adr/`. Start by capturing
  the dedup-fingerprint rule and the MAC-is-identity rule — both
  have bitten us in code review already.
- **Accessibility audit.** The Tron palette is low-contrast by design;
  run axe-core on each page and file the violations. Add a
  high-contrast toggle at the Settings level.

---

## Won't-do (for the record)

A few things we've considered and consciously rejected, so they don't
keep coming back as proposals:

- **Packet capture / deep-packet inspection.** Outside the project's
  scope. Talk to your gateway — that's why Firewalla / OPNsense exist.
- **Active response ("block this IP").** Too dangerous as a feature
  owned by a dashboard. Users should write their own firewall rules;
  we surface the signal, we don't pull the trigger.
- **Multi-tenant SaaS.** The threat model for this tool is "single
  homelab, trusted network". A hosted version would need a different
  architecture (proper auth, tenant isolation, audit log retention)
  and we don't want to take it there.
- **Windows-native deployment.** Docker on WSL works. A bare-metal
  Windows install is a support burden we're not equipped to take on.

---

## Contributing

If you want to work on any of the above:

1. Check existing [issues](https://github.com/your-org/your-repo/issues)
   — someone may be partway there already.
2. Open a "Feature Request" issue with the proposal before you code; we
   often have context that trims the design.
3. Smaller items can go straight to a PR (see
   [CONTRIBUTING.md](CONTRIBUTING.md)).

The author reviews proposals weekly; response times are best-effort.
