"""F-006: per-device timeout in the OpenVAS scan loop.

The scan loop used to call `run_openvas_scan(...)` with no `asyncio.wait_for`,
so a single stuck gvmd response could wedge the entire 24-hour scheduled
run (apscheduler's max_instances=1 then drops the next cycle).

We test the extracted `_scan_one_device_with_timeout` helper directly:

  1. happy path — scan completes, findings are emitted via socket.io
  2. timeout — a hanging scan triggers the timeout branch, the helper
     emits a `scan:complete` with the timeout reason, and reports
     timed_out=True back to the caller
  3. arbitrary exception — caller sees (0, False); error is logged but
     not re-raised so the loop continues to the next device
"""

from __future__ import annotations

import asyncio

import pytest

from scheduler.jobs import _scan_one_device_with_timeout


pytestmark = pytest.mark.asyncio


class _RecordingNS:
    """Stand-in for notification_service that records what got emitted."""

    def __init__(self) -> None:
        self.vuln_updates: list[tuple[str, dict]] = []
        self.scan_completes: list[dict] = []

    async def emit_vuln_updated(self, device_id: str, summary: dict) -> None:
        self.vuln_updates.append((device_id, summary))

    async def emit_scan_complete(self, **kwargs) -> None:
        self.scan_completes.append(kwargs)


async def test_happy_path_emits_vuln_update_and_returns_count():
    ns = _RecordingNS()

    async def fast_scan(device_id, device_ip):
        return 7

    count, timed_out = await _scan_one_device_with_timeout(
        "dev-1", "10.0.0.5", ns=ns, timeout_s=10, scan_fn=fast_scan
    )

    assert count == 7
    assert timed_out is False
    assert ns.vuln_updates == [("dev-1", {"count": 7})]
    assert ns.scan_completes == []


async def test_zero_findings_does_not_emit_vuln_update():
    # The previous scan loop only emitted when count > 0; preserve that
    # contract — no vuln:updated for a clean scan, but still no timeout.
    ns = _RecordingNS()

    async def clean_scan(device_id, device_ip):
        return 0

    count, timed_out = await _scan_one_device_with_timeout(
        "dev-2", "10.0.0.6", ns=ns, timeout_s=10, scan_fn=clean_scan
    )

    assert count == 0
    assert timed_out is False
    assert ns.vuln_updates == []


async def test_timeout_branch_emits_scan_complete_with_reason():
    ns = _RecordingNS()

    async def hanging_scan(device_id, device_ip):
        # Sleep beyond the helper's timeout. The wait_for cancels us
        # cleanly when the timeout fires.
        await asyncio.sleep(60)
        return 999  # never reached

    # Use a small timeout so the test runs fast. Real production timeout
    # is 70 min; here 0.05s proves the branch is reachable and the right
    # side effects fire.
    count, timed_out = await _scan_one_device_with_timeout(
        "dev-3", "10.0.0.7", ns=ns, timeout_s=0.05, scan_fn=hanging_scan
    )

    assert count == 0
    assert timed_out is True
    assert ns.vuln_updates == []
    assert len(ns.scan_completes) == 1
    payload = ns.scan_completes[0]
    assert payload["device_id"] == "dev-3"
    assert payload["scan_type"] == "openvas"
    assert payload["device_count"] == 0
    assert "timed out" in payload["error"]


async def test_arbitrary_exception_is_swallowed_so_loop_continues():
    # The outer scan loop iterates all online devices; one bad scan
    # mustn't kill the rest. The helper logs and returns (0, False).
    ns = _RecordingNS()

    async def failing_scan(device_id, device_ip):
        raise RuntimeError("gvmd connection lost mid-stream")

    count, timed_out = await _scan_one_device_with_timeout(
        "dev-4", "10.0.0.8", ns=ns, timeout_s=10, scan_fn=failing_scan
    )

    assert count == 0
    assert timed_out is False
    # No emit on generic failure — we still log, but the per-device
    # state machine on the frontend has its 90-second TTL fallback
    # to clear stuck spinners (see the per-row scan flow added in
    # the v1.0.0 polish pass).
    assert ns.scan_completes == []
