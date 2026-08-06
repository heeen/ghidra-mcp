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


if __name__ == "__main__":
    unittest.main()
