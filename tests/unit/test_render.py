"""The Markdown rendering of a function bundle, and what it leaves out.

The interesting half is the omissions: a bundle repeats every local that the
decompiled C above it already declares, and on a real function that was 48 rows
of pure redundancy — the single largest waste in the payload.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "python"))

from bridge_mcp_ghidra.render import (  # noqa: E402
    _AUTO_NAMED,
    checkout_markdown,
    function_bundle_markdown,
)


class TestAutoNameDetection(unittest.TestCase):
    def test_ghidra_auto_names_are_recognised(self):
        for name in ("local_f0", "local_res10", "auStack_110", "uStack_120",
                     "uVar14", "pcVar5", "puVar1", "param_9",
                     "in_AL", "in_FS_OFFSET", "extraout_EAX", "unaff_EBX"):
            self.assertTrue(_AUTO_NAMED.match(name), name)

    def test_human_names_are_not(self):
        for name in ("bytesRead", "pFileHeader", "sBuffer", "__src", "result"):
            self.assertFalse(_AUTO_NAMED.match(name), name)


class TestVariableSection(unittest.TestCase):
    def _render(self, **bundle):
        base = {"name": "f", "address": "1000", "program": "ls",
                "decompiled_code": "void f(void) { return; }"}
        base.update(bundle)
        return function_bundle_markdown(base)

    def test_auto_named_locals_are_counted_not_listed(self):
        body = self._render(locals=[
            {"name": "local_f0", "type": "long", "storage": "Stack[-0xf0]:8",
             "in_decompiled_code": True},
            {"name": "uVar7", "type": "ulong", "storage": "RCX:8",
             "in_decompiled_code": True},
        ])
        self.assertNotIn("local_f0", body)
        self.assertNotIn("uVar7", body)
        self.assertIn("2 auto-named locals omitted", body)

    def test_a_renamed_local_survives_with_its_storage(self):
        """Once it is not called local_f0 any more, the offset lives nowhere else."""
        body = self._render(locals=[
            {"name": "bytesRead", "type": "int", "storage": "Stack[-0x20]:4",
             "in_decompiled_code": True},
        ])
        self.assertIn("`bytesRead` : int @ Stack[-0x20]:4", body)
        self.assertNotIn("omitted", body)

    def test_a_local_the_decompiler_dropped_survives(self):
        body = self._render(locals=[
            {"name": "local_20", "type": "int", "storage": "Stack[-0x20]:4",
             "in_decompiled_code": False},
        ])
        self.assertIn("local_20", body)
        self.assertIn("not in decompiled code", body)

    def test_parameters_always_survive_because_storage_is_the_convention(self):
        body = self._render(parameters=[
            {"name": "param_9", "type": "char *", "storage": "RDI:8"},
        ])
        # param_9 is auto-named, but unlike a local its name does NOT say RDI.
        self.assertIn("`param_9` : char * @ RDI:8", body)

    def test_no_section_at_all_when_there_are_no_variables(self):
        self.assertNotIn("Parameters and notable locals", self._render())


class TestBundleShape(unittest.TestCase):
    def test_unresolved_return_type_is_above_the_fold(self):
        body = function_bundle_markdown({
            "name": "f", "address": "1000", "return_type": "undefined",
            "return_type_resolved": False,
            "decompiled_code": "void f(void) {}",
        })
        self.assertLess(body.index("⚠ return type"), body.index("## Decompiled"))

    def test_truncation_is_stated_not_silent(self):
        body = function_bundle_markdown({
            "name": "f", "address": "1000",
            "decompiled_code": "void f(void) {}",
            "truncation": {"callers": True, "xrefs": False},
        })
        self.assertIn("Truncated sections: callers", body)
        self.assertNotIn("xrefs", body)


class TestCheckoutMarkdown(unittest.TestCase):
    def test_single_status_golden_shape(self):
        body = checkout_markdown({
            "checkout_id": "co_7de33ad7",
            "program_name": "synaWudfBioUsb.dll",
            "program": "synaWudfBioUsb.dll",
            "live_modification_number": 3,
            "root": "/tmp/ghidra-mcp-checkout/synaWudfBioUsb.dll-7de33ad7",
            "root_present": True,
            "root_recreated": 0,
            "phase": "complete",
            "functions_total": 3230,
            "functions_done": 3230,
            "functions_failed": 0,
            "bytes_written": 5886248,
            "eta_seconds": 0,
            "last_error": None,
            "status_revision": 311,
            "resource_uri": "ghidra://checkout/co_7de33ad7",
            "config": {
                "enabled_strategies": [],
                "band_size": 20,
                "max_file_bytes": 32768,
                "exclusions": [],
                "include_only": [],
                "throttle_percent": 10,
                "decompile_timeout_seconds": 30,
                "analysis_wait_seconds": 600,
            },
            "status_state": "clean",
            "swept_at_modification_number": 3,
        })
        self.assertTrue(body.startswith("# Checkout co_7de33ad7 — synaWudfBioUsb.dll"))
        self.assertIn("complete · 3230/3230", body)
        self.assertIn("## Status", body)
        self.assertIn("freshness: fresh (mod 3)", body)
        self.assertIn("## Configuration", body)
        self.assertIn("band size: 20", body)
        self.assertIn("max file bytes: 32768", body)
        self.assertIn("## How to read this checkout", body)
        self.assertIn(
            "Glob /tmp/ghidra-mcp-checkout/synaWudfBioUsb.dll-7de33ad7/modules/*/*.c",
            body,
        )
        self.assertIn("uri: ghidra://function/<program>/<address>", body)
        self.assertLess(body.index("## Status"), body.index("## Configuration"))
        self.assertLess(body.index("## Configuration"), body.index("## How to read"))

    def test_freshness_follows_the_tree_not_the_sweep(self):
        """A spliced tree at the live modification number is fresh, and says it was spliced;
        the sweep's own number lagging behind does not make it stale."""
        from bridge_mcp_ghidra.render import _checkout_freshness
        self.assertEqual(
            _checkout_freshness({"swept_at_modification_number": 3,
                                 "reconciled_at_modification_number": 5,
                                 "live_modification_number": 5, "spliced_since_sweep": 2}),
            "fresh (mod 5), 2 blocks spliced since sweep")
        self.assertEqual(
            _checkout_freshness({"reconciled_at_modification_number": 5,
                                 "live_modification_number": 6}),
            "behind (tree at 5, live 6)")
        self.assertEqual(
            _checkout_freshness({"reconciled_at_modification_number": 5,
                                 "live_modification_number": 6, "pending_dirty": 3}),
            "catching up (3 pending)")
        self.assertEqual(
            _checkout_freshness({"phase": "stale", "last_error": "edits were discarded"}),
            "stale (edits were discarded)")

    def test_list_shape_renders_compact_table(self):
        body = checkout_markdown({
            "checkouts": [
                {
                    "checkout_id": "co_aaa",
                    "program_name": "ls",
                    "phase": "idle",
                    "functions_done": 0,
                    "functions_total": 100,
                    "root": "/tmp/a",
                },
                {
                    "checkout_id": "co_bbb",
                    "program_name": "driver.dll",
                    "phase": "complete",
                    "functions_done": 50,
                    "functions_total": 50,
                    "root": "/tmp/b",
                },
            ],
            "adoptable_on_disk": [
                {
                    "checkout_id": "co_orphan",
                    "program_name": "old.bin",
                    "status_state": "dirty",
                    "files_on_disk": 12,
                    "root": "/tmp/orphan",
                },
            ],
            "checkout_count": 2,
            "adoptable_count": 1,
        })
        self.assertTrue(body.startswith("# Checkouts"))
        self.assertIn("| co_aaa | ls | idle | 0/100 |", body)
        self.assertIn("| co_bbb | driver.dll | complete | 50/50 |", body)
        self.assertIn("## Adoptable on disk", body)
        self.assertIn("co_orphan", body)

    def test_missing_every_optional_key_never_raises(self):
        body = checkout_markdown({"checkout_id": "co_empty"})
        self.assertIn("# Checkout co_empty", body)
        self.assertIn("## Status", body)
        self.assertIn("## Configuration", body)
        self.assertIn("## How to read this checkout", body)
        # Empty dict / non-dict must also survive.
        self.assertIn("Checkouts", checkout_markdown({"checkouts": []}))
        self.assertIn("Unexpected", checkout_markdown("not-a-dict"))


if __name__ == "__main__":
    unittest.main()
