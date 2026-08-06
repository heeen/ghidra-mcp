"""Coverage: every non-read-only tool has an invalidation tier."""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "python"))

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

    def test_tiers_are_the_four_expected_values(self):
        self.assertEqual(
            set(ENDPOINT_TIER.values()),
            {
                InvalidationTier.LOCAL,
                InvalidationTier.CALLERS,
                InvalidationTier.TYPE,
                InvalidationTier.UNBOUNDED,
            },
        )

    def test_local_and_callers_cover_comment_and_rename(self):
        self.assertEqual(ENDPOINT_TIER["/set_comment"], InvalidationTier.LOCAL)
        self.assertEqual(ENDPOINT_TIER["/rename_variables"], InvalidationTier.LOCAL)
        self.assertEqual(ENDPOINT_TIER["/rename_function"], InvalidationTier.CALLERS)
        self.assertEqual(ENDPOINT_TIER["/set_function_prototype"], InvalidationTier.CALLERS)
        self.assertEqual(ENDPOINT_TIER["/create_struct"], InvalidationTier.TYPE)
        self.assertEqual(ENDPOINT_TIER["/disassemble_bytes"], InvalidationTier.UNBOUNDED)


if __name__ == "__main__":
    unittest.main()
