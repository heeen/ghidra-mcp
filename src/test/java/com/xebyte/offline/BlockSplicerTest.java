package com.xebyte.offline;

import com.xebyte.core.checkout.BlockSplicer;
import com.xebyte.core.checkout.CheckoutTreeNarrower;
import com.xebyte.core.checkout.SweepJob;
import org.junit.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Offline tests for checkout block splicing — locate, fingerprint-skip, fail
 * closed on missing blocks, and ignore {@code // fn:} inside string literals.
 */
public class BlockSplicerTest {

    private static final String THREE_BLOCKS = ""
            + "// fn: Foo @ 00100000 size=16\n"
            + "// part: c05 address-band conf=0.50 evidence_backed=false\n"
            + "// fp:aaaaaaaaaaaa\n"
            + "// dts:2026-01-01T00:00:00Z\n"
            + "// mod:1\n"
            + "// uri: ghidra://function/x/00100000\n"
            + "// see: modules/c05/README.md\n"
            + "void Foo(void) {\n"
            + "  puts(\"// fn: not a header\");\n"
            + "}\n"
            + "\n"
            + "// fn: Bar @ 00100100 size=16\n"
            + "// part: c05 address-band conf=0.50 evidence_backed=false\n"
            + "// fp:bbbbbbbbbbbb\n"
            + "// dts:2026-01-01T00:00:00Z\n"
            + "// mod:1\n"
            + "// uri: ghidra://function/x/00100100\n"
            + "// see: modules/c05/README.md\n"
            + "void Bar(void) {}\n"
            + "\n"
            + "// fn: Baz @ 00100200 size=16\n"
            + "// part: c05 address-band conf=0.50 evidence_backed=false\n"
            + "// fp:cccccccccccc\n"
            + "// dts:2026-01-01T00:00:00Z\n"
            + "// mod:1\n"
            + "// uri: ghidra://function/x/00100200\n"
            + "// see: modules/c05/README.md\n"
            + "void Baz(void) {}\n"
            + "\n";

    @Test
    public void findBlock_firstLastAndSingle() {
        String first = BlockSplicer.findBlock(THREE_BLOCKS, "00100000");
        assertNotNull(first);
        assertTrue(first.startsWith("// fn: Foo @ 00100000"));
        assertTrue("string literal must stay inside Foo's block",
                first.contains("puts(\"// fn: not a header\")"));

        String last = BlockSplicer.findBlock(THREE_BLOCKS, "00100200");
        assertNotNull(last);
        assertTrue(last.startsWith("// fn: Baz @ 00100200"));

        String alone = ""
                + "// fn: Only @ deadbeef size=4\n"
                + "// part: c00 address-band conf=0.10 evidence_backed=false\n"
                + "// fp:123456789abc\n"
                + "// dts:2026-01-01T00:00:00Z\n"
                + "// mod:1\n"
                + "// uri: ghidra://function/x/deadbeef\n"
                + "// see: modules/c00/README.md\n"
                + "void Only(void) {}\n";
        String found = BlockSplicer.findBlock(alone, "deadbeef");
        assertNotNull(found);
        assertEquals(1, CheckoutTreeNarrower.splitFunctionChunks(alone).size());
        assertTrue(found.contains("void Only"));
    }

    @Test
    public void stringLiteralContainingFnMarkerDoesNotCreateBlock() {
        // Three real headers — the puts line must not split Foo.
        List<String> chunks = CheckoutTreeNarrower.splitFunctionChunks(THREE_BLOCKS);
        assertEquals(3, chunks.size());
        assertEquals("00100000", CheckoutTreeNarrower.addressFromChunk(chunks.get(0)));
        assertTrue(chunks.get(0).contains("puts(\"// fn: not a header\")"));
        assertNull(BlockSplicer.findBlock(THREE_BLOCKS, "not_an_address"));
    }

    @Test
    public void fpUnchangedSkipsRewrite() {
        String oldBar = BlockSplicer.findBlock(THREE_BLOCKS, "00100100");
        assertNotNull(oldBar);
        // Same fingerprint in a "new" block — write must be skipped.
        Map<String, String> reps = new LinkedHashMap<>();
        reps.put("00100100", oldBar);
        BlockSplicer.SpliceResult result = BlockSplicer.spliceFile(THREE_BLOCKS, reps);
        assertFalse(result.rewritten());
        assertEquals(THREE_BLOCKS, result.newBody());
        assertEquals(List.of("00100100"), result.unchanged());
        assertTrue(result.refreshed().isEmpty());
    }

    @Test
    public void unlocatableBlockFailsWithoutTouchingFile() {
        String replacement = rebuildBlock("Ghost", "00ffffff", "dddddddddddd", "void Ghost(void) {}\n");
        Map<String, String> reps = Map.of("00ffffff", replacement);
        BlockSplicer.SpliceResult result = BlockSplicer.spliceFile(THREE_BLOCKS, reps);
        assertFalse(result.rewritten());
        assertEquals(THREE_BLOCKS, result.newBody());
        assertEquals(List.of("00ffffff"), result.failed());
        assertTrue(result.refreshed().isEmpty());
    }

    @Test
    public void spliceReplacesOnlyTargetBlock() {
        String newBar = rebuildBlock("BarRenamed", "00100100", "eeeeeeeeeeee",
                "void BarRenamed(void) { return; }\n");
        BlockSplicer.SpliceResult result = BlockSplicer.spliceFile(
                THREE_BLOCKS, Map.of("00100100", newBar));
        assertTrue(result.rewritten());
        assertEquals(List.of("00100100"), result.refreshed());
        assertTrue(result.newBody().contains("// fn: Foo @ 00100000"));
        assertTrue(result.newBody().contains("// fn: BarRenamed @ 00100100"));
        assertTrue(result.newBody().contains("// fn: Baz @ 00100200"));
        assertFalse(result.newBody().contains("// fn: Bar @ 00100100"));
        assertEquals("BarRenamed", result.nameUpdates().get("00100100"));
    }

    @Test
    public void updateIndexNamesRewritesNameColumnOnly() {
        String index = SweepJob.byAddressHeader()
                + SweepJob.formatByAddressRow("00100000", "Foo", "c05", "modules/c05/c05.c", false)
                + SweepJob.formatByAddressRow("00100100", "Bar", "c05", "modules/c05/c05.c", false);
        String updated = BlockSplicer.updateIndexNames(
                index, Map.of("00100100", "BarRenamed"));
        assertTrue(updated.contains("00100100\tBarRenamed\tc05\t"));
        assertTrue(updated.contains("00100000\tFoo\tc05\t"));
        assertFalse(updated.contains("00100100\tBar\t"));
    }

    private static String rebuildBlock(String name, String addr, String fp, String body) {
        return SweepJob.renderFunctionHeader(
                name, addr, 16L, "c05", "address-band", 0.50, false, fp,
                java.time.Instant.parse("2026-01-01T00:00:00Z"), 1L, "x")
                + body;
    }
}
