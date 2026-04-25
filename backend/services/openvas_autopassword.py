"""Auto-managed OpenVAS admin password.

Rationale: the OpenVAS admin password only exists because `immauss/openvas`
seeds one on first boot. The user never logs into gvmd directly (we always
talk to it over GMP from the backend) and we never show the password to
the user — so having them pick one is pointless UX. Worse, they're likely
to pick something weak, forget it, and then be confused when Settings
says "authentication failed".

This module owns password lifecycle:

  ensure_openvas_password()
      Called on first setup (and as a Settings button). If no password
      is currently stored, generates a strong random one and runs the
      reset flow to recreate the container with it. If one already
      exists and works, no-op.

  rotate_openvas_password()
      "Rotate" button in Settings. Generates a new random password and
      runs the reset flow. Old password is discarded.

The actual container-recreate work lives in `openvas_reset.py`; this
module just wraps it with password generation + a "do we need it?"
pre-check.

Password format: 32 chars, alphanumeric + select punctuation. Avoids
shell-dangerous bytes (quotes, backslashes, $, `, ;) because the password
is passed through docker's `environment=` list and eventually through
bcrypt. URL-safe base64 would work too but is less readable in logs.
"""
from __future__ import annotations

import logging
import secrets
import string
from typing import Literal

log = logging.getLogger(__name__)

# Shell-safe, URL-safe, paste-safe alphabet. No quotes, no backslash, no $, `, ;.
# Keeping the set to 64 chars makes log-grep-ability decent.
_ALPHABET = string.ascii_letters + string.digits + "-_"


def generate_password(length: int = 32) -> str:
    """Cryptographically-random password from a shell-safe alphabet.

    32 chars of this alphabet = ~190 bits of entropy, way past anything
    an attacker with the docker socket would need anyway. The whole
    threat model here is "nothing on my LAN can guess the scanner creds"
    — we're not trying to survive an offline brute-force.
    """
    return "".join(secrets.choice(_ALPHABET) for _ in range(length))


EnsureResult = Literal["ok", "generated", "rotated"]


async def ensure_openvas_password() -> EnsureResult:
    """Ensure the stored OpenVAS password is non-empty.

    If the config already has a password, this is a no-op and returns
    "ok" — we don't probe gvmd here because that's both slow (auth RTT
    on cold boot can be seconds) and noisy (fills the audit log with
    false-positive reset events every restart). The scheduler's next
    scan will surface an auth failure if the stored password is stale,
    and the user can click "Rotate".

    If no password is stored, generate a random one and run the reset
    flow. Returns "generated".

    Callers: `/api/setup/complete` after a fresh wizard finish, and
    `/api/setup/rotate-openvas` for the Settings button.
    """
    from config import get_config_manager

    mgr = get_config_manager()
    cfg = mgr.get()
    if cfg.openvas.password.get_secret_value():
        return "ok"

    # No password — generate one and hand it to the reset flow.
    new_pw = generate_password()
    log.info("openvas_autopassword: no stored password; auto-generating")
    await _run_reset(new_pw, cfg.openvas.user or "admin")
    return "generated"


async def rotate_openvas_password() -> EnsureResult:
    """Unconditional rotation. Generates a new password and recreates
    the container regardless of current state. Used for the Settings
    "Rotate password" button."""
    from config import get_config_manager

    mgr = get_config_manager()
    cfg = mgr.get()
    new_pw = generate_password()
    log.info("openvas_autopassword: rotating password (user request)")
    await _run_reset(new_pw, cfg.openvas.user or "admin")
    return "rotated"


async def _run_reset(new_password: str, username: str) -> None:
    """Thin wrapper around the reset flow so we don't duplicate the
    docker/gvmd dance. Keeps `openvas_reset.py` as the single source
    of truth for how the container is recreated."""
    from services.openvas_reset import reset_openvas_password
    await reset_openvas_password(new_password, username)
