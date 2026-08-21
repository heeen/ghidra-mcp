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
 * closed on missing blocks, header-only neighbourhood patches, and ignore
 * {@code // fn:} inside string literals.
 */
public class BlockSplicerTest {

    private static final String THREE_BLOCKS = ""
            + "// fn: Foo @ 00100000 size=16\n"
            + "// calls: Bar\n"
            + "// callers: (none — entry)\n"
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
            + "// calls: (none)\n"
            + "// callers: Foo\n"
            + "// part: c05 address-band conf=0.50 evidence_backed=false\n"
            + "// fp:bbbbbbbbbbbb\n"
            + "// dts:2026-01-01T00:00:00Z\n"
            + "// mod:1\n"
            + "// uri: ghidra://function/x/00100100\n"
            + "// see: modules/c05/README.md\n"
            + "void Bar(void) {}\n"
            + "\n"
            + "// fn: Baz @ 00100200 size=16\n"
            + "// calls: (none)\n"
            + "// callers: (none — entry)\n"
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

        String alone = rebuildBlock("Only", "deadbeef", "123456789abc",
                List.of(), List.of(), "void Only(void) {}\n");
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
        String replacement = rebuildBlock("Ghost", "00ffffff", "dddddddddddd",
                List.of(), List.of(), "void Ghost(void) {}\n");
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
                List.of(), List.of("Foo"), "void BarRenamed(void) { return; }\n");
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
                + SweepJob.formatByAddressRow(
                        "00100000", "Foo", "c05", "modules/c05/00100000.c", false)
                + SweepJob.formatByAddressRow(
                        "00100100", "Bar", "c05", "modules/c05/00100000.c", false);
        String updated = BlockSplicer.updateIndexNames(
                index, Map.of("00100100", "BarRenamed"));
        assertTrue(updated.contains("00100100\tBarRenamed\tc05\t"));
        assertTrue(updated.contains("00100000\tFoo\tc05\t"));
        assertFalse(updated.contains("00100100\tBar\t"));
    }

    @Test
    public void updateCallgraphNamesRewritesNameColumnsAfterRename() {
        String cg = ""
                + "caller\tcallee\tcaller_name\tcallee_name\n"
                + "00100000\t00100100\tFoo\tBar\n"
                + "00100200\t00100100\tBaz\tBar\n";
        String updated = BlockSplicer.updateCallgraphNames(
                cg, Map.of("00100100", "BarRenamed"));
        assertTrue(updated.contains("00100000\t00100100\tFoo\tBarRenamed\n"));
        assertTrue(updated.contains("00100200\t00100100\tBaz\tBarRenamed\n"));
        assertFalse(updated.contains("\tBar\n"));
    }

    @Test
    public void headerOnlyPatchChangesOnlyNeighbourhoodLines() {
        String bar = BlockSplicer.findBlock(THREE_BLOCKS, "00100100");
        assertNotNull(bar);
        String bodyBefore = BlockSplicer.bodyAfterLeadingComments(bar);
        String patched = BlockSplicer.patchNeighbourhoodLines(
                bar, "(none)", "FooRenamed");
        assertTrue(patched.contains("// callers: FooRenamed\n"));
        assertTrue(patched.contains("// calls: (none)\n"));
        assertEquals(bodyBefore, BlockSplicer.bodyAfterLeadingComments(patched));
        assertTrue(patched.contains("void Bar(void) {}"));
        // fp/uri/see untouched
        assertTrue(patched.contains("// fp:bbbbbbbbbbbb\n"));
        assertTrue(patched.contains("// uri: ghidra://function/x/00100100\n"));
    }

    @Test
    public void headerOnlyPatchInsertsLinesIntoLegacySevenLineHeader() {
        String legacy = ""
                + "// fn: Legacy @ 00100300 size=4\n"
                + "// part: c00 address-band conf=0.10 evidence_backed=false\n"
                + "// fp:123456789abc\n"
                + "// dts:2026-01-01T00:00:00Z\n"
                + "// mod:1\n"
                + "// uri: ghidra://function/x/00100300\n"
                + "// see: modules/c00/README.md\n"
                + "void Legacy(void) { return; }\n";
        String bodyBefore = BlockSplicer.bodyAfterLeadingComments(legacy);
        String patched = BlockSplicer.patchNeighbourhoodLines(
                legacy, "Helper", "(none — entry)");
        assertTrue(patched.contains("// calls: Helper\n"));
        assertTrue(patched.contains("// callers: (none — entry)\n"));
        assertEquals(bodyBefore, BlockSplicer.bodyAfterLeadingComments(patched));
    }

    @Test
    public void spliceFindsBlockWhenCompartmentHasManyFiles() {
        // Regression for Read-budget split: index points at the sibling file,
        // and spliceFile must still locate the block inside that file alone.
        String fileA = rebuildBlock("Foo", "00100000", "aaaaaaaaaaaa",
                List.of("Bar"), List.of(), "void Foo(void) {}\n")
                + "\n"
                + rebuildBlock("Bar", "00100100", "bbbbbbbbbbbb",
                List.of(), List.of("Foo"), "void Bar(void) {}\n")
                + "\n";
        String fileB = rebuildBlock("Baz", "00100200", "cccccccccccc",
                List.of(), List.of(), "void Baz(void) {}\n")
                + "\n"
                + rebuildBlock("Qux", "00100300", "dddddddddddd",
                List.of(), List.of(), "void Qux(void) {}\n")
                + "\n";

        String index = SweepJob.byAddressHeader()
                + SweepJob.formatByAddressRow(
                        "00100000", "Foo", "c05", "modules/c05/00100000.c", false)
                + SweepJob.formatByAddressRow(
                        "00100100", "Bar", "c05", "modules/c05/00100000.c", false)
                + SweepJob.formatByAddressRow(
                        "00100200", "Baz", "c05", "modules/c05/00100200.c", false)
                + SweepJob.formatByAddressRow(
                        "00100300", "Qux", "c05", "modules/c05/00100200.c", false);

        // Lookup as BlockSplicer.refresh does: index → file body → findBlock.
        assertTrue(index.contains("00100200\tBaz\tc05\tmodules/c05/00100200.c\t"));
        assertNull("Baz must not be found in the sibling budget file",
                BlockSplicer.findBlock(fileA, "00100200"));
        String found = BlockSplicer.findBlock(fileB, "00100200");
        assertNotNull(found);
        assertTrue(found.startsWith("// fn: Baz @ 00100200"));

        String newBaz = rebuildBlock("BazRenamed", "00100200", "eeeeeeeeeeee",
                List.of(), List.of(), "void BazRenamed(void) { return; }\n");
        BlockSplicer.SpliceResult result = BlockSplicer.spliceFile(
                fileB, Map.of("00100200", newBaz));
        assertTrue(result.rewritten());
        assertTrue(result.newBody().contains("// fn: BazRenamed @ 00100200"));
        assertTrue(result.newBody().contains("// fn: Qux @ 00100300"));
        assertFalse(result.newBody().contains("// fn: Baz @ 00100200"));
        // Sibling file untouched by construction (splice is per-file).
        assertTrue(fileA.contains("// fn: Foo @ 00100000"));
        assertTrue(fileA.contains("// fn: Bar @ 00100100"));
    }

    private static String rebuildBlock(
            String name, String addr, String fp,
            List<String> calls, List<String> callers, String body) {
        return SweepJob.renderFunctionHeader(
                name, addr, 16L, "c05", "address-band", 0.50, false, fp,
                java.time.Instant.parse("2026-01-01T00:00:00Z"), 1L, "x",
                calls, callers)
                + body;
    }
}
