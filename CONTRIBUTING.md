# Contributing

Thanks for looking at this. Homelab Dashboard is a small-team project — PRs
are welcome, bug reports are welcome, "here's a weird device from my lab that
doesn't classify right" is welcome. This document covers the development loop
and what a PR needs to land.

## Ground rules

- **One concern per PR.** A single issue, a single commit-coherent set of
  changes. Big sprawling PRs with unrelated refactors get split before
  merge.
- **Tests for new behaviour.** If you add a feature, you add a test. If you
  fix a bug, the fix is a failing regression test + the change that makes
  it pass.
- **Keep `main` deployable.** Every commit on `main` should build and pass
  tests. CI enforces this; don't merge red.
- **Respect the Tron voice in `docs/guide.html`.** If you touch that file,
  keep the existing narrative register — it's deliberate, not a bug.

## Getting the dev loop running

Requirements on your machine:

- Docker + Docker Compose v2
- Python 3.10+ with `python3 -m venv`
- Node 20+ with `npm`
- `make` for the shortcuts (optional but recommended)

Clone, install, and fire the mock stack:

```bash
git clone https://github.com/YOUR-ORG/homelab-dashboard.git
cd homelab-dashboard
make mock
# → http://localhost:8080 with synthetic data, no real integrations
```

For hot-reload development without Docker:

```bash
# Terminal 1 — backend
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
BACKEND_MOCK=true DB_PATH=/tmp/homelab.db uvicorn main:socket_app --reload

# Terminal 2 — frontend
cd frontend
npm install
npm run dev          # → http://localhost:5173
```

Vite proxies `/api` and `/socket.io` through to port 8000 automatically.

## Running the tests

**Backend:**

```bash
cd backend
pytest                              # full suite
pytest -k "alarm"                   # a subset
pytest --cov=. --cov-report=term    # with coverage
```

**Frontend:**

```bash
cd frontend
npm run lint                        # ESLint — max-warnings=0
npm run build                       # tsc + Vite production build
npm test                            # Vitest
npm test -- --coverage              # with coverage
```

Both suites run on every PR via the CI workflow in
`.github/workflows/ci.yml`. If you want to reproduce CI exactly, a
plausible runbook lives in the workflow file.

## Commit style

Short imperative subject, optional body:

```
Fix alarm dedup fingerprint collision on identical-minute fires

The fingerprint was (src|dst|sig|minute_bucket) but 60-sec-interval
Suricata rules in a high-traffic LAN occasionally fire twice in the
same minute bucket and get collapsed. Add the event type to the
fingerprint input so distinct rules never collide.

Closes #42.
```

Conventional-commits prefixes (`feat:`, `fix:`, `docs:`, …) are welcome but
not enforced. What matters is that the subject tells a human what changed.

## PR checklist

Before you open a PR:

- [ ] `pytest` passes (backend)
- [ ] `npm run lint` passes with zero warnings (frontend)
- [ ] `npm run build` succeeds (frontend — covers `tsc --noEmit` +
      Vite bundle)
- [ ] New behaviour has a test covering it
- [ ] `CHANGELOG.md` updated under `[Unreleased]` if the change is
      user-visible
- [ ] Docs (`docs/guide.html`, README, ROADMAP) updated if the change
      affects them
- [ ] No secrets, tokens, or personal data in the diff — check twice

The PR template auto-fills from `.github/PULL_REQUEST_TEMPLATE.md`; fill it
out honestly.

## Scope of changes that go through review

Everything. Nothing lands on `main` without a PR — even doc-only changes.
This keeps history clean and gives the maintainer a chance to spot
narrative-voice slips on the guide page before they propagate.

## What needs extra care

Any change to:

- **`backend/services/background_tasks.py`** — the fire-and-forget helper
  is load-bearing. If you touch it, add a test for the specific failure
  mode you're patching.
- **`backend/middleware/auth.py`** — auth paths cross security boundaries.
  Include a negative test (token missing, token wrong, token matches) for
  anything you change.
- **`backend/database.py`** schema — migrations aren't automated past the
  `CREATE TABLE IF NOT EXISTS` idempotency we rely on. Additive changes
  (new columns with defaults, new tables, new indexes) are fine. Drops
  or renames need a write-up of the migration plan for existing
  installs.
- **`docker-compose.yml`** — container hardening (`read_only`, `cap_drop`,
  `security_opt`) is set deliberately. Loosening anything needs a
  justification in the PR description.
- **`frontend/nginx.conf`** — the CSP is hand-tuned. If you add an
  external CDN, script source, or inline style, explain why it can't be
  done without loosening CSP.

## Reporting bugs

Open an issue using the **Bug report** template. Include:

- Version (tag or commit SHA)
- Deployment mode (mock / local dev / Docker Compose / `deploy.sh` to
  remote host)
- Steps to reproduce
- What you expected vs. what you saw
- Relevant logs (`docker compose logs backend`, browser console)

## Suggesting features

Open an issue using the **Feature request** template. Features that earn
quick turnaround:

- They fit something already half-built (check `ROADMAP.md` first).
- They work for more than one homelab shape (not "I have a very specific
  router you've never heard of").
- You're willing to put up the PR yourself after we agree on the design.

## Adding a new integration

If you want to add support for another firewall, controller, or scanner:

1. **Open an issue first.** Integrations span backend schema, scheduler,
   settings UI, and docs. A design thread saves a rewrite.
2. Follow the `integrations/firewalla.py` pattern — one module per
   vendor, dataclasses for responses, async httpx client, graceful
   rate-limit/404 handling, `asyncio.gather(return_exceptions=True)` on
   parallel fetches.
3. Add a new scheduler job in `backend/scheduler/jobs.py` that only
   registers when credentials are present.
4. Add a settings UI card in `frontend/src/pages/SettingsPage.tsx`
   following the existing Gateway Integrations pattern (test-connection
   button, blank-preserves-stored semantics for secrets).
5. Write tests for the parsing, the fingerprint (if it emits alarms),
   and the scheduler registration.
6. Update `docs/guide.html` prereqs table + gateway integrations
   section.

## Code of conduct

See [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md).

## License

By contributing you agree your contributions are MIT-licensed — same as
the rest of the project. No CLA, no signed-off-by requirement.
