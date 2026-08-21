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

        async def fake_blocking(func, *a, **kw):
            # Resolve-target path; decompile_checkout_status has no checkout_id → no refresh.
            return json.dumps({"name": "FUN_1000", "address": "00001000"})

        async def run():
            with mock.patch.object(
                invalidation.subscriptions, "emit_resource_updated", fake_updated
            ), mock.patch.object(
                invalidation.state, "known_resource_uris",
                lambda: {"ghidra://function/ls/00001000"},
            ), mock.patch.object(
                invalidation.state, "run_blocking_ghidra_call",
                fake_blocking,
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


class TestBlastRadiusNotificationsByteIdentical(unittest.TestCase):
    """``_invalidate`` emit behaviour must match the pre-refactor path per tier."""

    def _capture(self, endpoint, kwargs, known, ghidra_replies):
        emitted: list[tuple] = []
        reply_iter = iter(ghidra_replies)

        async def fake_updated(uri, **kw):
            emitted.append(("updated", uri))
            return 1

        async def fake_list_changed(**kw):
            emitted.append(("list_changed", None))
            return 1

        async def fake_blocking(func, *a, **kw):
            try:
                return next(reply_iter)
            except StopIteration:
                return json.dumps({"error": "no checkout"})

        async def run():
            with mock.patch.object(
                invalidation.subscriptions, "emit_resource_updated", fake_updated
            ), mock.patch.object(
                invalidation.subscriptions, "emit_resource_list_changed", fake_list_changed
            ), mock.patch.object(
                invalidation.state, "known_resource_uris", lambda: known
            ), mock.patch.object(
                invalidation.state, "run_blocking_ghidra_call", fake_blocking
            ):
                await invalidation.after_successful_write(
                    {"endpoint": endpoint, "read_only": False},
                    kwargs,
                    None,
                    "{}",
                )
            return emitted

        return asyncio.run(run())

    def test_local_emits_only_interested_uri(self):
        emitted = self._capture(
            "/set_comment",
            {"program": "ls", "address": "00001004"},
            {"ghidra://function/ls/00001000"},
            [json.dumps({"address": "00001000"})],
        )
        self.assertEqual(emitted, [("updated", "ghidra://function/ls/00001000")])

    def test_local_emits_nothing_when_uri_not_of_interest(self):
        emitted = self._capture(
            "/set_comment",
            {"program": "ls", "address": "00001004"},
            {"ghidra://function/ls/99999999"},
            [json.dumps({"address": "00001000"})],
        )
        self.assertEqual(emitted, [])

    def test_callers_caps_notification_uris_at_64(self):
        callers = [
            {"name": f"C{i:03d}", "address": f"{i:08x}"}
            for i in range(100)
        ]
        known = {f"ghidra://function/ls/{i:08x}" for i in range(100)}
        known.add("ghidra://function/ls/0000aaaa")
        emitted = self._capture(
            "/rename_function",
            {"program": "ls", "old_name": "Target", "address": "0000aaaa"},
            known,
            [
                json.dumps({"address": "0000aaaa"}),
                json.dumps({"callers": callers, "total": 100}),
            ],
        )
        updated = [u for kind, u in emitted if kind == "updated"]
        # target + 64 callers = 65 interested URIs → collapse to list_changed.
        self.assertEqual(updated, [])
        self.assertIn(("list_changed", None), emitted)

    def test_unbounded_degrades_to_list_changed(self):
        emitted = self._capture(
            "/reanalyze",
            {"program": "ls"},
            {"ghidra://function/ls/00001000"},
            # decompile_checkout_status: no id → skip refresh (still notification-only)
            [json.dumps({"error": "no checkout"})],
        )
        self.assertEqual(emitted, [
            ("updated", "ghidra://function/ls/00001000"),
            ("list_changed", None),
        ])

    def test_none_still_silent(self):
        emitted = self._capture(
            "/save_program",
            {"program": "ls"},
            {"ghidra://function/ls/00001000"},
            [],
        )
        self.assertEqual(emitted, [])


class TestCheckoutRefreshFromBlastRadius(unittest.TestCase):
    """Checkout splice uses the uncapped address set — never notification caps."""

    def test_callers_refresh_requests_limit_zero_and_all_addresses(self):
        posted: list[dict] = []
        gets: list[dict] = []

        callers = [
            {"name": f"C{i:03d}", "address": f"{i:08x}"}
            for i in range(200)
        ]

        async def fake_blocking(func, *a, **kw):
            # Execute the callable so we can observe dispatch params.
            return func()

        def fake_get(endpoint, params=None):
            gets.append({"endpoint": endpoint, "params": dict(params or {})})
            if endpoint == "/get_function_by_address":
                return json.dumps({"address": "0000aaaa"})
            if endpoint == "/get_function_callers":
                return json.dumps({"callers": callers, "total": 200})
            if endpoint == "/decompile_checkout_status":
                return json.dumps({"checkout_id": "co_deadbeef", "phase": "complete"})
            return json.dumps({"error": "unexpected get " + endpoint})

        def fake_post(endpoint, data, retries=3, query_params=None):
            posted.append({
                "endpoint": endpoint,
                "data": dict(data),
                "query": dict(query_params or {}),
            })
            return json.dumps({"refreshed": 201, "busy": False})

        async def run():
            with mock.patch.object(
                invalidation.subscriptions, "emit_resource_updated",
                mock.AsyncMock(return_value=1),
            ), mock.patch.object(
                invalidation.subscriptions, "emit_resource_list_changed",
                mock.AsyncMock(return_value=1),
            ), mock.patch.object(
                invalidation.state, "known_resource_uris",
                lambda: set(),  # interest empty ⇒ zero notification URIs
            ), mock.patch.object(
                invalidation.state, "run_blocking_ghidra_call", fake_blocking
            ), mock.patch.object(
                invalidation.dispatch, "dispatch_get", fake_get
            ), mock.patch.object(
                invalidation.dispatch, "dispatch_post", fake_post
            ), mock.patch.object(
                invalidation.dispatch, "raise_on_failure", lambda text: text
            ):
                await invalidation.after_successful_write(
                    {"endpoint": "/rename_function", "read_only": False},
                    {"program": "ls", "old_name": "Target", "address": "0000aaaa"},
                    None,
                    "{}",
                )

        asyncio.run(run())

        caller_gets = [g for g in gets if g["endpoint"] == "/get_function_callers"]
        self.assertEqual(len(caller_gets), 1)
        # THE TRAP: notification path used limit=64; checkout must request uncapped.
        self.assertEqual(caller_gets[0]["params"].get("limit"), 0)

        self.assertEqual(len(posted), 1)
        self.assertEqual(posted[0]["endpoint"], "/decompile_checkout_refresh")
        addr_csv = posted[0]["data"]["addresses"]
        addrs = set(addr_csv.split(","))
        self.assertEqual(len(addrs), 201)  # target + 200 callers
        self.assertIn("0000aaaa", addrs)

    def test_interest_filter_does_not_shrink_checkout_addresses(self):
        """Unread URIs drop from notifications but must still refresh on disk."""
        posted: list[dict] = []

        async def fake_blocking(func, *a, **kw):
            return func()

        def fake_get(endpoint, params=None):
            if endpoint == "/get_function_by_address":
                return json.dumps({"address": "00001000"})
            if endpoint == "/decompile_checkout_status":
                return json.dumps({"checkout_id": "co_abc", "phase": "complete"})
            return json.dumps({})

        def fake_post(endpoint, data, retries=3, query_params=None):
            posted.append(dict(data))
            return json.dumps({"ok": True})

        async def run():
            with mock.patch.object(
                invalidation.subscriptions, "emit_resource_updated",
                mock.AsyncMock(return_value=1),
            ), mock.patch.object(
                invalidation.state, "known_resource_uris",
                lambda: set(),  # nothing of interest → no SSE
            ), mock.patch.object(
                invalidation.state, "run_blocking_ghidra_call", fake_blocking
            ), mock.patch.object(
                invalidation.dispatch, "dispatch_get", fake_get
            ), mock.patch.object(
                invalidation.dispatch, "dispatch_post", fake_post
            ), mock.patch.object(
                invalidation.dispatch, "raise_on_failure", lambda text: text
            ):
                blast = await invalidation.resolve_blast_radius(
                    "/set_comment",
                    InvalidationTier.LOCAL,
                    {"program": "ls", "address": "00001000"},
                )
                await invalidation._invalidate(blast, None)
                await invalidation._refresh_checkout(blast)
                return blast

        blast = asyncio.run(run())
        self.assertEqual(blast.addresses, frozenset({"00001000"}))
        self.assertEqual(len(posted), 1)
        self.assertIn("00001000", posted[0]["addresses"])

    def test_unbounded_marks_stale_instead_of_refreshing(self):
        posted: list[dict] = []

        async def fake_blocking(func, *a, **kw):
            return func()

        def fake_get(endpoint, params=None):
            if endpoint == "/decompile_checkout_status":
                return json.dumps({"checkout_id": "co_abc", "phase": "complete"})
            return json.dumps({})

        def fake_post(endpoint, data, retries=3, query_params=None):
            posted.append(dict(data))
            return json.dumps({"marked_stale": True})

        async def run():
            with mock.patch.object(
                invalidation.subscriptions, "emit_resource_updated",
                mock.AsyncMock(return_value=1),
            ), mock.patch.object(
                invalidation.subscriptions, "emit_resource_list_changed",
                mock.AsyncMock(return_value=1),
            ), mock.patch.object(
                invalidation.state, "known_resource_uris",
                lambda: {"ghidra://function/ls/1"},
            ), mock.patch.object(
                invalidation.state, "run_blocking_ghidra_call", fake_blocking
            ), mock.patch.object(
                invalidation.dispatch, "dispatch_get", fake_get
            ), mock.patch.object(
                invalidation.dispatch, "dispatch_post", fake_post
            ), mock.patch.object(
                invalidation.dispatch, "raise_on_failure", lambda text: text
            ):
                await invalidation.after_successful_write(
                    {"endpoint": "/reanalyze", "read_only": False},
                    {"program": "ls"},
                    None,
                    "{}",
                )

        asyncio.run(run())
        self.assertEqual(len(posted), 1)
        self.assertTrue(posted[0].get("mark_stale"))
        self.assertNotIn("addresses", posted[0])

    def test_structural_writes_mark_stale_rather_than_splice(self):
        """Creating or deleting a function changes the function SET, not its text.

        Measured: /create_function followed by a refresh reported skipped:1 and
        left the tree silently lacking the function while phase still said
        complete. Deleting is worse — an orphan block describes a function the
        program no longer has, and it is greppable. Both can also move compartment
        membership and band boundaries, so the partitioning is suspect too.
        """
        for endpoint in ("/create_function", "/delete_function"):
            with self.subTest(endpoint=endpoint):
                posted: list[dict] = []

                async def fake_blocking(func, *a, **kw):
                    return func()

                def fake_get(ep, params=None):
                    if ep == "/decompile_checkout_status":
                        return json.dumps({"checkout_id": "co_abc", "phase": "complete"})
                    return json.dumps({})

                def fake_post(ep, data, retries=3, query_params=None):
                    posted.append(dict(data))
                    return json.dumps({"marked_stale": True})

                async def run():
                    with mock.patch.object(
                        invalidation.subscriptions, "emit_resource_updated",
                        mock.AsyncMock(return_value=1),
                    ), mock.patch.object(
                        invalidation.subscriptions, "emit_resource_list_changed",
                        mock.AsyncMock(return_value=1),
                    ), mock.patch.object(
                        invalidation.state, "known_resource_uris",
                        lambda: {"ghidra://function/ls/1"},
                    ), mock.patch.object(
                        invalidation.state, "run_blocking_ghidra_call", fake_blocking
                    ), mock.patch.object(
                        invalidation.dispatch, "dispatch_get", fake_get
                    ), mock.patch.object(
                        invalidation.dispatch, "dispatch_post", fake_post
                    ), mock.patch.object(
                        invalidation.dispatch, "raise_on_failure", lambda text: text
                    ):
                        await invalidation.after_successful_write(
                            {"endpoint": endpoint, "read_only": False},
                            {"program": "ls", "address": "00001000"},
                            None,
                            "{}",
                        )

                asyncio.run(run())
                refreshes = [d for d in posted if "addresses" in d]
                stales = [d for d in posted if d.get("mark_stale")]
                self.assertEqual(
                    refreshes, [],
                    f"{endpoint} must not attempt a splice: {refreshes}")
                self.assertEqual(
                    len(stales), 1,
                    f"{endpoint} must mark the checkout stale, got {posted}")

    def test_no_checkout_skips_silently(self):
        posted: list[dict] = []

        async def fake_blocking(func, *a, **kw):
            return func()

        def fake_get(endpoint, params=None):
            if endpoint == "/get_function_by_address":
                return json.dumps({"address": "00001000"})
            if endpoint == "/decompile_checkout_status":
                return json.dumps({"error": "no checkout matches selector: ls"})
            return json.dumps({})

        def fake_post(endpoint, data, retries=3, query_params=None):
            posted.append(dict(data))
            return json.dumps({})

        async def run():
            with mock.patch.object(
                invalidation.subscriptions, "emit_resource_updated",
                mock.AsyncMock(return_value=1),
            ), mock.patch.object(
                invalidation.state, "known_resource_uris",
                lambda: {"ghidra://function/ls/00001000"},
            ), mock.patch.object(
                invalidation.state, "run_blocking_ghidra_call", fake_blocking
            ), mock.patch.object(
                invalidation.dispatch, "dispatch_get", fake_get
            ), mock.patch.object(
                invalidation.dispatch, "dispatch_post", fake_post
            ), mock.patch.object(
                invalidation.dispatch, "raise_on_failure", lambda text: text
            ):
                await invalidation.after_successful_write(
                    {"endpoint": "/set_comment", "read_only": False},
                    {"program": "ls", "address": "00001000"},
                    None,
                    "{}",
                )

        asyncio.run(run())
        self.assertEqual(posted, [])

    def test_refresh_failure_does_not_raise(self):
        async def fake_blocking(func, *a, **kw):
            return func()

        def fake_get(endpoint, params=None):
            if endpoint == "/get_function_by_address":
                return json.dumps({"address": "00001000"})
            if endpoint == "/decompile_checkout_status":
                return json.dumps({"checkout_id": "co_abc"})
            return json.dumps({})

        def fake_post(endpoint, data, retries=3, query_params=None):
            raise RuntimeError("boom")

        async def run():
            with mock.patch.object(
                invalidation.subscriptions, "emit_resource_updated",
                mock.AsyncMock(return_value=1),
            ), mock.patch.object(
                invalidation.state, "known_resource_uris",
                lambda: {"ghidra://function/ls/00001000"},
            ), mock.patch.object(
                invalidation.state, "run_blocking_ghidra_call", fake_blocking
            ), mock.patch.object(
                invalidation.dispatch, "dispatch_get", fake_get
            ), mock.patch.object(
                invalidation.dispatch, "dispatch_post", fake_post
            ), mock.patch.object(
                invalidation.dispatch, "raise_on_failure", lambda text: text
            ):
                # Must not propagate — same contract as _invalidate_guarded.
                await invalidation.after_successful_write(
                    {"endpoint": "/set_comment", "read_only": False},
                    {"program": "ls", "address": "00001000"},
                    None,
                    "{}",
                )

        asyncio.run(run())

    def test_checkout_refresh_is_none_tier(self):
        self.assertEqual(
            ENDPOINT_TIER["/decompile_checkout_refresh"], InvalidationTier.NONE
        )

    def test_resolve_blast_radius_local_callers_type_mapping(self):
        async def fake_blocking(func, *a, **kw):
            return func()

        def fake_get(endpoint, params=None):
            if endpoint == "/get_function_by_address":
                return json.dumps({"address": "00001000"})
            if endpoint == "/get_function_callers":
                return json.dumps({
                    "callers": [
                        {"name": "A", "address": "00002000"},
                        {"name": "B", "address": "00003000"},
                    ]
                })
            if endpoint == "/find_type_users":
                return json.dumps({
                    "functions": [
                        {"address": "00004000"},
                        {"address": "00005000"},
                    ]
                })
            return json.dumps({})

        async def run():
            with mock.patch.object(
                invalidation.state, "run_blocking_ghidra_call", fake_blocking
            ), mock.patch.object(
                invalidation.dispatch, "dispatch_get", fake_get
            ), mock.patch.object(
                invalidation.dispatch, "raise_on_failure", lambda text: text
            ):
                local = await invalidation.resolve_blast_radius(
                    "/set_comment", InvalidationTier.LOCAL,
                    {"program": "ls", "address": "00001000"},
                )
                callers = await invalidation.resolve_blast_radius(
                    "/rename_function", InvalidationTier.CALLERS,
                    {"program": "ls", "address": "00001000"},
                )
                typ = await invalidation.resolve_blast_radius(
                    "/create_struct", InvalidationTier.TYPE,
                    {"program": "ls", "name": "Foo"},
                )
                unbounded = await invalidation.resolve_blast_radius(
                    "/reanalyze", InvalidationTier.UNBOUNDED,
                    {"program": "ls"},
                )
                return local, callers, typ, unbounded

        local, callers, typ, unbounded = asyncio.run(run())
        self.assertEqual(local.addresses, frozenset({"00001000"}))
        self.assertEqual(
            callers.addresses, frozenset({"00001000", "00002000", "00003000"})
        )
        self.assertEqual(typ.addresses, frozenset({"00004000", "00005000"}))
        self.assertEqual(unbounded.addresses, frozenset())
        self.assertTrue(unbounded.degraded)


if __name__ == "__main__":
    unittest.main()
