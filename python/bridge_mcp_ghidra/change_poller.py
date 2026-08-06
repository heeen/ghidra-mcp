"""Adaptive poller for ``/get_change_token``.

Catches GUI edits, undo/redo and ``run_ghidra_script`` — everything the
write-hook invalidation path is blind to — at program coarseness. Runs only
while at least one resource URI is known to some session; backs off when quiet
and **exits** when the known set empties (``kick()`` restarts it on the next
read/subscribe).
"""

from __future__ import annotations

import asyncio
import json
from urllib.parse import unquote

from . import dispatch
from . import state
from . import subscriptions
from .config import logger

_ACTIVE_INTERVAL = 1.5
_QUIET_INTERVAL = 10.0
_QUIET_AFTER_CYCLES = 4  # ~6s of no change before backing off

_poll_task: asyncio.Task | None = None
_last_tokens: dict[str, int] = {}
_quiet_cycles = 0


def kick() -> None:
    """Ensure the poller is running on the current event loop."""
    global _poll_task
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    if _poll_task is not None and not _poll_task.done():
        return

    async def _runner() -> None:
        try:
            await _poll_loop()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Change-token poller crashed")

    _poll_task = loop.create_task(_runner(), name="ghidra-change-token-poller")


def stop() -> None:
    """Cancel a running poller (used by tests)."""
    global _poll_task
    if _poll_task is not None and not _poll_task.done():
        _poll_task.cancel()
    _poll_task = None
    _last_tokens.clear()


async def _poll_loop() -> None:
    global _quiet_cycles
    while True:
        known = state.known_resource_uris()
        if not known:
            _last_tokens.clear()
            _quiet_cycles = 0
            # Exit rather than sleep forever: asyncio.run() in tests (and a
            # quiet process with no sessions) must not keep a zombie task.
            return

        snapshot = state.get_connection_snapshot()
        if snapshot.mode == "none":
            # No Ghidra yet — wait briefly; kick() will have us running once a
            # session exists, and we must not block the loop on connection retries.
            await asyncio.sleep(_ACTIVE_INTERVAL)
            continue

        programs = _programs_from_uris(known)
        any_change = False
        for program in programs:
            token = await _fetch_token(program)
            if token is None:
                continue
            previous = _last_tokens.get(program)
            _last_tokens[program] = token
            if previous is None or previous == token:
                continue
            any_change = True
            logger.debug(
                "Change token for %s moved %s → %s; invalidating known URIs",
                program, previous, token,
            )
            await _invalidate_program(program)

        if any_change:
            _quiet_cycles = 0
            interval = _ACTIVE_INTERVAL
        else:
            _quiet_cycles += 1
            interval = (
                _ACTIVE_INTERVAL
                if _quiet_cycles < _QUIET_AFTER_CYCLES
                else _QUIET_INTERVAL
            )
        await asyncio.sleep(interval)


async def _fetch_token(program: str) -> int | None:
    try:
        raw = await state.run_blocking_ghidra_call(
            lambda: dispatch.raise_on_failure(
                dispatch.dispatch_get("/get_change_token", params={"program": program})
            )
        )
        payload = json.loads(raw)
        if isinstance(payload, dict) and "modification_number" in payload:
            return int(payload["modification_number"])
    except Exception as e:
        logger.debug("get_change_token(%s) failed: %s", program, e)
    return None


async def _invalidate_program(program: str) -> None:
    from .invalidation import _known_uris_for_program  # local import: avoid cycle at load

    uris = _known_uris_for_program(program)
    # Cap: a coarse program-wide bump should not storm thousands of URIs.
    if len(uris) > 64:
        await subscriptions.emit_resource_list_changed()
        if "ghidra://programs" in uris:
            await subscriptions.emit_resource_updated("ghidra://programs")
        return
    for uri in sorted(uris):
        await subscriptions.emit_resource_updated(uri)
    await subscriptions.emit_resource_list_changed()


def _programs_from_uris(uris: set[str]) -> set[str]:
    """Extract program names from ``ghidra://function|program|search/{program}/...``."""
    programs: set[str] = set()
    for uri in uris:
        if not uri.startswith("ghidra://"):
            continue
        rest = uri[len("ghidra://") :]
        parts = rest.split("/")
        # authority is function|program|search; next segment is the program.
        if len(parts) >= 2 and parts[0] in ("function", "program", "search"):
            programs.add(unquote(parts[1]))
    return programs
