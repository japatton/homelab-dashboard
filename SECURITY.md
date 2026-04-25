# Security Policy

## Supported Versions

This project tags releases semver-style. Security fixes are backported one
minor version behind the current release.

| Version | Supported          |
|---------|--------------------|
| main    | :white_check_mark: |
| 0.1.x   | :white_check_mark: (pre-1.0 baseline) |
| < 0.1   | :x:                |

Once 1.0 ships, the policy becomes: current minor + previous minor receive
security patches; older minors do not.

---

## Reporting a Vulnerability

**Please do not report security vulnerabilities via public GitHub issues,
discussions, or pull requests.** Use one of the channels below so we can fix
the issue before it's public knowledge.

### Preferred channel

[**GitHub Security Advisories**](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability) — click "Report a
vulnerability" on the repo's Security tab. This creates a private thread
visible only to the repo maintainers. GitHub's tooling handles CVE
assignment and coordinated disclosure cleanly.

### Fallback channel

Email the maintainer: **security@<maintainer-domain>** (replace with the
published address on the GitHub profile). PGP key on request.

Please include:

- **Affected version** (git SHA or tag).
- **Reproduction steps** — minimal, runnable.
- **Impact** — what can an attacker do? (RCE, data exfil, auth bypass,
  lateral movement, …).
- **Suggested mitigation** if you have one.
- **Attribution preference** — how you'd like to be credited in the
  advisory (full name / handle / anonymous).

### What to expect

- **Acknowledgement within 72 hours** of receipt.
- **Initial triage within 5 business days** — severity estimate + planned
  fix timeline, or a reasoned decision to not treat it as a vulnerability.
- **Fix + advisory published** for high/critical issues typically within 14
  days of a confirmed working exploit, longer for low-severity.
- **Credit in the advisory** per your stated preference (default: your
  GitHub handle).

We follow coordinated-disclosure norms: no public disclosure until a fix
lands or a mutually agreed deadline passes.

---

## Scope

### In scope

- Authentication / authorization bypass (`DASHBOARD_TOKEN` middleware,
  socket.io handshake).
- Remote code execution in the backend, the frontend build, or any
  subprocess spawned (nmap, gvm, claude CLI, docker SDK).
- SQL injection, command injection, path traversal, SSRF.
- Cross-site scripting, content injection in the SPA, CSP bypass.
- Container escape affecting the backend service (docker-socket-related,
  not dockerd-itself).
- Secret exposure: credentials in logs, secrets leaked via the audit log,
  Docker image layers containing `.env` or `config.yml`.
- Denial of service that makes the dashboard unusable with trivial
  attacker effort (amplification, resource exhaustion via API).

### Out of scope

- **Self-XSS** in a browser where the user already has dashboard admin
  rights. You can already script the API from devtools — that's by
  design.
- **Missing rate limiting** on anonymous endpoints when `DASHBOARD_TOKEN`
  is unset. Running token-less is explicitly a LAN-only mode.
- **Missing HTTPS** when `CERT_TYPE=none`. That's a deploy-mode choice.
- **Vulnerabilities in unmodified third-party Docker images** (immauss/
  openvas, jc21/nginx-proxy-manager) — report those to the upstream
  projects. We'll rev the pinned tag once upstream has a fix.
- Social engineering against the maintainer, DNS hijacking, physical
  access to the server.
- Issues that require a malicious user to already have API access
  (triggering scans, changing settings) — those are features, not bugs.

### Security-adjacent issues we care about anyway

Report these through the same channel if you find them, even though
they're not strictly "vulnerabilities":

- Default configurations that are unsafe in common deployment patterns.
- Missing or weak security headers on the nginx frontend.
- Default tokens / passwords / keys baked into an image or config.
- Dependencies with unpatched known CVEs.
- Unsafe default permissions on files written by the backend.

---

## Threat Model (informative)

This project targets **single-user, single-instance homelab deployments
on a trusted LAN**. The design assumptions that follow from that:

1. **The network is semi-trusted.** We bind to LAN interfaces by default
   and don't require TLS. The `DASHBOARD_TOKEN` gate is opt-in because
   most users don't need it.
2. **The operator is the threat model for many actions.** The dashboard
   can trigger vulnerability scans against arbitrary CIDRs, run docker
   commands via the socket mount (for OpenVAS rotation), and execute
   Claude-generated integration code in a sandbox. If an attacker
   already has dashboard access, these are features being used as
   intended — not vulnerabilities.
3. **The external attack surface is minimal by default.** With
   `CERT_TYPE=none` the stack binds HTTP on a high port on the LAN.
   Users exposing the dashboard via reverse proxy / VPN / tunnel are
   expected to enable `DASHBOARD_TOKEN` and set `BACKEND_BIND=127.0.0.1:`.
4. **Compromise of the backend is bounded** by non-root + read-only-FS +
   cap_drop:ALL — an RCE is constrained to the container's scratch
   directories and the mounted data volume.

Issues that break these assumptions (e.g. token bypass, sandboxed Claude
code escaping, docker-socket privilege escalation beyond the documented
rotate flow) are in scope and welcome.

---

## Hall of Fame

Reporters who submit valid vulnerabilities are credited here (with their
permission) once the corresponding advisory is published.

_No advisories published yet._
