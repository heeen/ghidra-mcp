"""Coverage: every non-read-only tool has an invalidation tier."""

from __future__ import annotations

import asyncio
import json
import re
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "python"))

from bridge_mcp_ghidra import invalidation  # noqa: E402
from bridge_mcp_ghidra.invalidation import ENDPOINT_TIER, InvalidationTier  # noqa: E402

REPO = Path(__file__).resolve().parent.parent.parent
JAVA_ROOT = REPO / "src" / "main" / "java"


def _mcp_tool_blocks(text: str) -> list[str]:
    """Return the argument text of every ``@McpTool(...)`` annotation."""
    blocks: list[str] = []
    needle = "@McpTool("
    start = 0
    while True:
        idx = text.find(needle, start)
        if idx < 0:
            break
        i = idx + len(needle)
        depth = 1
        while i < len(text) and depth:
            ch = text[i]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            i += 1
        blocks.append(text[idx + len(needle) : i - 1])
        start = i
    return blocks


def _write_endpoints_from_java() -> set[str]:
    """Paths whose @McpTool access is WRITE or DESTRUCTIVE (not READ_ONLY)."""
    path_re = re.compile(r'path\s*=\s*"([^"]+)"')
    access_re = re.compile(r"access\s*=\s*ToolAccess\.(WRITE|DESTRUCTIVE|READ_ONLY|UNSPECIFIED)")
    found: set[str] = set()
    for path in JAVA_ROOT.rglob("*.java"):
        text = path.read_text(encoding="utf-8")
        for block in _mcp_tool_blocks(text):
            path_match = path_re.search(block)
            access_match = access_re.search(block)
            if not path_match or not access_match:
                continue
            if access_match.group(1) in ("WRITE", "DESTRUCTIVE"):
                found.add(path_match.group(1))
    return found


class TestInvalidationTier(unittest.TestCase):
    def test_every_write_endpoint_has_a_tier(self):
        writes = _write_endpoints_from_java()
        self.assertTrue(writes, "expected to find WRITE/DESTRUCTIVE @McpTool annotations")
        missing = sorted(writes - set(ENDPOINT_TIER))
        extra = sorted(set(ENDPOINT_TIER) - writes)
        self.assertEqual(
            missing,
            [],
            f"write endpoints missing an invalidation tier: {missing}",
        )
        # Extra entries are allowed only if they are stale — flag them so the
        # table does not accumulate ghosts, but do not fail on headless-only
        # aliases. Require extras to be empty for strictness.
        self.assertEqual(
            extra,
            [],
            f"invalidation tiers for unknown endpoints (removed?): {extra}",
        )

    def test_tiers_are_the_expected_values(self):
        self.assertEqual(
            set(ENDPOINT_TIER.values()),
            {
                InvalidationTier.NONE,
                InvalidationTier.LOCAL,
                InvalidationTier.CALLERS,
                InvalidationTier.TYPE,
                InvalidationTier.UNBOUNDED,
            },
        )

    def test_saving_does_not_invalidate(self):
        """A save is what happens after every write; invalidating on it would
        drop the very cache this feature exists to build."""
        for endpoint in ("/save_program", "/save_all_programs", "/checkin_program"):
            self.assertEqual(ENDPOINT_TIER[endpoint], InvalidationTier.NONE, endpoint)

    def test_none_tier_emits_nothing(self):
        emitted: list[tuple] = []

        async def fake_updated(uri, **kw):
            emitted.append(("updated", uri))
            return 1

        async def fake_list_changed(**kw):
            emitted.append(("list_changed", None))
            return 1

        with mock.patch.object(invalidation.subscriptions, "emit_resource_updated", fake_updated), \
             mock.patch.object(
                 invalidation.subscriptions, "emit_resource_list_changed", fake_list_changed
             ):
            asyncio.run(
                invalidation.after_successful_write(
                    {"endpoint": "/save_program", "read_only": False},
                    {"program": "ls"},
                    None,
                    "{}",
                )
            )
        self.assertEqual(emitted, [])

    def test_local_and_callers_cover_comment_and_rename(self):
        self.assertEqual(ENDPOINT_TIER["/set_comment"], InvalidationTier.LOCAL)
        self.assertEqual(ENDPOINT_TIER["/rename_variables"], InvalidationTier.LOCAL)
        self.assertEqual(ENDPOINT_TIER["/rename_function"], InvalidationTier.CALLERS)
        self.assertEqual(ENDPOINT_TIER["/set_function_prototype"], InvalidationTier.CALLERS)
        self.assertEqual(ENDPOINT_TIER["/create_struct"], InvalidationTier.TYPE)
        self.assertEqual(ENDPOINT_TIER["/disassemble_bytes"], InvalidationTier.UNBOUNDED)


class TestLocalTierEmitsBeforeReturning(unittest.TestCase):
    """The notification must be sent while the tool request is still open.

    streamable-HTTP closes a request's SSE stream as soon as its response goes
    out, and a `resources/updated` carrying that request's id afterwards is
    dropped with nothing but a debug log. So the emit has to happen inside the
    awaited hook, not in a task that outlives it.
    """

    def test_updated_is_emitted_by_the_time_the_hook_returns(self):
        emitted: list[str] = []

        async def fake_updated(uri, **kw):
            emitted.append(uri)
            return 1

        async def fake_get(endpoint, params=None):
            return json.dumps({"name": "FUN_1000", "address": "00001000"})

        async def run():
            with mock.patch.object(
                invalidation.subscriptions, "emit_resource_updated", fake_updated
            ), mock.patch.object(
                invalidation.state, "known_resource_uris",
                lambda: {"ghidra://function/ls/00001000"},
            ), mock.patch.object(
                invalidation.state, "run_blocking_ghidra_call",
                lambda func, *a, **kw: fake_get("", None),
            ):
                await invalidation.after_successful_write(
                    {"endpoint": "/set_comment", "read_only": False},
                    {"program": "ls", "address": "00001004"},
                    None,
                    "{}",
                )
                # No sleep, no task draining: it is already sent or it is broken.
                self.assertEqual(emitted, ["ghidra://function/ls/00001000"])

        asyncio.run(run())


if __name__ == "__main__":
    unittest.main()
