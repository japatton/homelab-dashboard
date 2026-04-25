"""
Non-interactive SSH auth probe used by the "Test Scan Credentials" button.

Given a target IP and either a password or private key, we try to complete the
SSH handshake + authentication and then immediately close the connection. We
never open a session or run a command — the only question is "do these creds
let us in?".

The return dataclass distinguishes *why* an attempt failed so the UI / audit
log can say something more useful than "it didn't work":

    ok           — authenticated successfully
    auth_failed  — TCP+banner OK but credentials rejected by sshd
    unreachable  — TCP refused / host down / no route
    timeout      — TCP connect or handshake exceeded PROBE_TIMEOUT
    error        — anything else (bad key format, protocol error, …)

The probe is deliberately single-attempt and short-timeout: this runs from a
user click, not a background job, and we don't want a room full of offline
hosts to wedge the UI for 30 seconds each.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Literal, Optional

import asyncssh

log = logging.getLogger(__name__)

# Tight timeout — a real SSH login on a LAN is well under 1s. Slow VPN links
# may need more; revisit if users report false "timeout" results.
PROBE_TIMEOUT = 6.0

ProbeStatus = Literal["ok", "auth_failed", "unreachable", "timeout", "error"]


@dataclass
class ProbeResult:
    ip: str
    status: ProbeStatus
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "status": self.status,
            "detail": self.detail,
            "ok": self.ok,
        }


async def probe_ssh(
    ip: str,
    username: str,
    *,
    password: Optional[str] = None,
    private_key: Optional[str] = None,
    key_passphrase: Optional[str] = None,
    port: int = 22,
) -> ProbeResult:
    """Try to authenticate against `ip` and immediately disconnect.

    Exactly one of `password` or `private_key` should be supplied. If both are
    given we pass both to asyncssh and let the server pick. If neither is
    given, the probe returns `error` — we never want to accidentally attempt
    agent/null auth against a user-supplied target.
    """
    if not password and not private_key:
        return ProbeResult(ip, "error", "no password or private key supplied")

    # asyncssh expects `client_keys` as a list; parse the key text here so a
    # bad key surfaces as a clear error instead of a generic auth failure.
    client_keys = None
    if private_key:
        try:
            key = asyncssh.import_private_key(
                private_key,
                passphrase=key_passphrase or None,
            )
            client_keys = [key]
        except asyncssh.KeyImportError as e:
            return ProbeResult(ip, "error", f"invalid private key: {e}")
        except Exception as e:
            return ProbeResult(ip, "error", f"key load failed: {e}")

    try:
        conn = await asyncio.wait_for(
            asyncssh.connect(
                ip,
                port=port,
                username=username,
                password=password or None,
                client_keys=client_keys,
                known_hosts=None,  # homelab — we don't maintain a known_hosts
                preferred_auth=("publickey", "password", "keyboard-interactive"),
                connect_timeout=PROBE_TIMEOUT,
            ),
            timeout=PROBE_TIMEOUT + 2.0,
        )
    except asyncio.TimeoutError:
        return ProbeResult(ip, "timeout", f"no response within {PROBE_TIMEOUT}s")
    except asyncssh.PermissionDenied as e:
        return ProbeResult(ip, "auth_failed", f"credentials rejected: {e}")
    except (OSError, ConnectionRefusedError) as e:
        return ProbeResult(ip, "unreachable", str(e))
    except asyncssh.DisconnectError as e:
        # Server disconnected mid-handshake — treat as auth-ish failure so the
        # UI red-flags it, but keep the detail so logs are clear.
        return ProbeResult(ip, "auth_failed", f"disconnect: {e}")
    except Exception as e:
        return ProbeResult(ip, "error", f"{type(e).__name__}: {e}")

    try:
        conn.close()
        await conn.wait_closed()
    except Exception:
        # We already authenticated; close hiccups are cosmetic.
        pass
    return ProbeResult(ip, "ok", "authenticated")


async def probe_many(
    ips: list[str],
    username: str,
    *,
    password: Optional[str] = None,
    private_key: Optional[str] = None,
    key_passphrase: Optional[str] = None,
    port: int = 22,
    concurrency: int = 8,
) -> list[ProbeResult]:
    """Probe every IP with the same credentials, bounded by `concurrency`.

    Results are returned in the same order as `ips`.
    """
    sem = asyncio.Semaphore(concurrency)

    async def _one(ip: str) -> ProbeResult:
        async with sem:
            return await probe_ssh(
                ip,
                username,
                password=password,
                private_key=private_key,
                key_passphrase=key_passphrase,
                port=port,
            )

    return await asyncio.gather(*(_one(ip) for ip in ips))
