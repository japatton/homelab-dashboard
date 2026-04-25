"""Fire-and-forget task helper.

`asyncio.create_task` on its own is a footgun: the event loop only holds a
*weak* reference to the task, so if the caller drops the return value (which
fire-and-forget code does by definition) the task can be garbage-collected
mid-run. See https://docs.python.org/3/library/asyncio-task.html#asyncio.create_task
— the warning was added in Python 3.11.

This module keeps strong references until tasks complete, and logs any
unhandled exception so it shows up in the backend log instead of vanishing
into the `_exceptions_handler` void.

Usage:
    from services.background_tasks import spawn
    spawn(do_scan(scan_id), name="scan:%s" % scan_id)

The return value is still the Task, so callers that *do* want to await it
or cancel it can — the bookkeeping just makes it safe to ignore.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Coroutine, Set

log = logging.getLogger(__name__)

# Strong-ref set. Each task removes itself via add_done_callback so we
# don't leak memory for completed tasks.
_BACKGROUND_TASKS: Set[asyncio.Task] = set()


def _on_done(task: asyncio.Task) -> None:
    _BACKGROUND_TASKS.discard(task)
    if task.cancelled():
        return
    exc = task.exception()
    if exc is not None:
        # Use log.exception to get the traceback without re-raising — this
        # is fire-and-forget, there's nobody up the stack to catch it.
        log.error(
            "Background task %r failed: %s",
            task.get_name(),
            exc,
            exc_info=exc,
        )


def spawn(coro: Coroutine[Any, Any, Any], *, name: str | None = None) -> asyncio.Task:
    """Schedule *coro* on the running loop, keep a strong ref until done,
    and log any unhandled exception. Returns the Task.
    """
    task = asyncio.create_task(coro, name=name)
    _BACKGROUND_TASKS.add(task)
    task.add_done_callback(_on_done)
    return task


def active_count() -> int:
    """Number of in-flight background tasks — handy for /healthz."""
    return len(_BACKGROUND_TASKS)
