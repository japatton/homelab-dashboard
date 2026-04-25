"""Tests for services.alarm_service — the alarm dedup + persistence core.

The service is the single funnel for every gateway-alarm write. If the
dedup logic regresses, the Security page will fill with duplicate rows
during IDS alert storms; if the socket-push counts regress, the sidebar
badge lags the list. Both are visible, annoying failures worth
regression tests.

Covers:
  - New insert path (count=1, fingerprint unique).
  - Repeat fire → same row, count++, dismissed flag cleared.
  - Summary group-by-severity totals + unacknowledged breakdown.
  - Acknowledge / dismiss / clear-dismissed state transitions.
  - Distinct sources with identical fingerprints don't collide.
"""

from __future__ import annotations

import pytest

from services.alarm_service import (
    AlarmInput,
    acknowledge,
    clear_dismissed,
    dismiss,
    get_summary,
    list_alarms,
    upsert_alarms,
)


pytestmark = pytest.mark.asyncio


def _input(**overrides) -> AlarmInput:
    """Factory — sensible defaults, override only what the test cares about."""
    base = dict(
        source="opnsense",
        fingerprint="192.168.1.1|1.1.1.1|ET TROJAN|2026-04-21T18:40",
        message="ET TROJAN activity",
        severity="high",
        source_label="OPNsense 24.7",
        category="Trojan Activity",
        signature="ET TROJAN",
        src_ip="192.168.1.1",
        dst_ip="1.1.1.1",
        raw={"protocol": "tcp"},
    )
    base.update(overrides)
    return AlarmInput(**base)


async def test_empty_input_is_noop(initialised_db):
    # upsert with an empty list should neither write nor raise.
    new, updated = await upsert_alarms([])
    assert (new, updated) == (0, 0)
    rows = await list_alarms()
    assert rows == []


async def test_first_fire_creates_row(initialised_db):
    new, updated = await upsert_alarms([_input()])
    assert (new, updated) == (1, 0)
    rows = await list_alarms()
    assert len(rows) == 1
    assert rows[0].count == 1
    assert rows[0].acknowledged is False
    assert rows[0].dismissed is False
    # id prefix — cheap sanity check on uuid assignment.
    assert rows[0].id.startswith("alrm-")


async def test_duplicate_fingerprint_merges(initialised_db):
    # Same source + fingerprint fires three times.
    await upsert_alarms([_input()])
    await upsert_alarms([_input()])
    new, updated = await upsert_alarms([_input()])
    assert (new, updated) == (0, 1)

    rows = await list_alarms()
    assert len(rows) == 1
    assert rows[0].count == 3


async def test_distinct_sources_do_not_collide(initialised_db):
    # Same fingerprint string, different source → two rows.
    fp = "same|fingerprint|2026-04-21T18:40"
    await upsert_alarms([_input(source="opnsense", fingerprint=fp)])
    await upsert_alarms([_input(source="firewalla", fingerprint=fp)])
    rows = await list_alarms()
    assert len(rows) == 2
    sources = sorted(r.source for r in rows)
    assert sources == ["firewalla", "opnsense"]


async def test_redisplay_after_dismiss_unsets_dismissed(initialised_db):
    # An alarm the user dismissed but that fires AGAIN should come back
    # — a truly resolved alarm stays dismissed; a recurring one deserves
    # attention. This is the "dismissed = 0 on merge" contract.
    await upsert_alarms([_input()])
    rows = await list_alarms()
    alarm_id = rows[0].id

    assert await dismiss(alarm_id) is True
    rows_after_dismiss = await list_alarms()
    assert rows_after_dismiss == []  # falls out of default feed
    # But a subsequent merge un-dismisses.
    await upsert_alarms([_input()])
    rows = await list_alarms()
    assert len(rows) == 1
    assert rows[0].dismissed is False
    assert rows[0].count == 2


async def test_summary_counts_by_severity(initialised_db):
    await upsert_alarms(
        [
            _input(fingerprint="a", severity="critical"),
            _input(fingerprint="b", severity="high"),
            _input(fingerprint="c", severity="high"),
            _input(fingerprint="d", severity="info"),
        ]
    )
    s = await get_summary()
    assert s.total == 4
    assert s.unacknowledged == 4
    assert s.critical == 1
    assert s.high == 2
    assert s.medium == 0
    assert s.low == 0
    assert s.info == 1


async def test_acknowledge_drops_from_unacknowledged(initialised_db):
    await upsert_alarms([_input()])
    rows = await list_alarms()
    ok = await acknowledge(rows[0].id)
    assert ok is True
    s = await get_summary()
    assert s.total == 1
    assert s.unacknowledged == 0


async def test_acknowledge_unknown_returns_false(initialised_db):
    # UPDATE ... WHERE id = '?' matches nothing → rowcount 0 → False.
    assert await acknowledge("alrm-does-not-exist") is False


async def test_summary_excludes_dismissed(initialised_db):
    await upsert_alarms(
        [
            _input(fingerprint="keep", severity="high"),
            _input(fingerprint="gone", severity="critical"),
        ]
    )
    rows = await list_alarms()
    gone = next(r for r in rows if r.fingerprint == "gone")
    await dismiss(gone.id)

    s = await get_summary()
    assert s.total == 1
    assert s.high == 1
    assert s.critical == 0


async def test_list_filters(initialised_db):
    await upsert_alarms(
        [
            _input(source="opnsense", fingerprint="a", severity="high"),
            _input(source="firewalla", fingerprint="b", severity="high"),
            _input(source="firewalla", fingerprint="c", severity="critical"),
        ]
    )
    # Source filter
    ops = await list_alarms(source="opnsense")
    assert len(ops) == 1
    fws = await list_alarms(source="firewalla")
    assert len(fws) == 2
    # Severity filter
    crit = await list_alarms(severity="critical")
    assert len(crit) == 1


async def test_list_include_dismissed(initialised_db):
    await upsert_alarms([_input()])
    rows = await list_alarms()
    await dismiss(rows[0].id)
    assert await list_alarms() == []
    assert len(await list_alarms(include_dismissed=True)) == 1


async def test_clear_dismissed_deletes_only_dismissed(initialised_db):
    await upsert_alarms(
        [
            _input(fingerprint="keep"),
            _input(fingerprint="kill"),
        ]
    )
    rows = await list_alarms()
    to_kill = next(r for r in rows if r.fingerprint == "kill")
    await dismiss(to_kill.id)

    deleted = await clear_dismissed()
    assert deleted == 1
    remaining = await list_alarms(include_dismissed=True)
    assert len(remaining) == 1
    assert remaining[0].fingerprint == "keep"


async def test_last_seen_refreshes_on_merge(initialised_db):
    # On merge the last_seen_at moves forward. Distinguishing first_seen
    # from last_seen is what lets the UI show "storm firing for 3h".
    await upsert_alarms([_input()])
    first_rows = await list_alarms()
    first_last_seen = first_rows[0].last_seen_at
    first_first_seen = first_rows[0].first_seen_at

    # A second fire: timestamp on the merge is now (), strictly >= first.
    await upsert_alarms([_input()])
    rows = await list_alarms()
    assert rows[0].last_seen_at >= first_last_seen
    # first_seen doesn't move.
    assert rows[0].first_seen_at == first_first_seen
