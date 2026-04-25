<!--
Thanks for opening a PR. A few things that will speed up review:

- Keep the PR focused on one concern. Unrelated refactors get split out.
- If the change is user-visible, update CHANGELOG.md under [Unreleased].
- If it affects docs/guide.html, ROADMAP.md, or README.md, update those too.
- CI will run lint + type-check + tests. A green check is faster than a
  back-and-forth about failing tests.
-->

## Summary

<!-- One or two sentences. What does this PR do, and why? -->

## Changes

<!-- Bullet list of the significant edits. Be specific about files/areas touched. -->

- 
- 
- 

## Screenshots / recordings

<!-- For frontend changes, a before/after screenshot or a short GIF goes a long way. Delete this section for backend-only changes. -->

## Testing

<!-- How did you verify this works? -->

- [ ] `pytest` passes (backend)
- [ ] `npm run lint` passes with zero warnings (frontend)
- [ ] `npm run build` succeeds (frontend — includes `tsc --noEmit`)
- [ ] `npm test` passes (Vitest)
- [ ] Manual smoke test in mock mode (`make mock`)
- [ ] Manual smoke test against real hardware (note which, below)

**Manual test notes:**

<!-- e.g. "Ran against OPNsense 24.7, verified alarms appear in /security within 60s" -->

## Checklist

- [ ] PR is scoped to one concern
- [ ] New behaviour has test coverage
- [ ] `CHANGELOG.md` updated under `[Unreleased]` if user-visible
- [ ] `docs/guide.html`, `ROADMAP.md`, or `README.md` updated if affected
- [ ] No secrets, tokens, passwords, personal data, or real hostnames in the diff
- [ ] Touched any of these? Extra care noted in CONTRIBUTING.md:
  - [ ] `backend/services/background_tasks.py`
  - [ ] `backend/middleware/auth.py`
  - [ ] `backend/database.py` (schema)
  - [ ] `docker-compose.yml` (container hardening)
  - [ ] `frontend/nginx.conf` (CSP)

## Related issues

<!-- "Closes #123" auto-closes the issue on merge. Use "Refs #123" for partial fixes. -->

Closes #
