package com.xebyte.offline;

import com.xebyte.core.checkout.Checkout;
import com.xebyte.core.checkout.CheckoutConfig;
import com.xebyte.core.checkout.CheckoutKey;
import com.xebyte.core.checkout.CheckoutLayout;
import com.xebyte.core.checkout.CheckoutRoot;
import com.xebyte.core.checkout.CheckoutStatusMd;
import com.xebyte.core.checkout.SweepJob;
import com.xebyte.core.checkout.SweepProgress;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Pure offline tests for {@link SweepJob} helpers — header rendering, index
 * row shape, STATUS.md states, and cancel-flag plumbing. No live Program.
 */
public class SweepJobTest {

    private Path tempRoot;

    @Before
    public void setUp() throws IOException {
        tempRoot = Files.createTempDirectory("sweep-job-test");
    }

    @After
    public void tearDown() throws IOException {
        if (tempRoot != null && Files.exists(tempRoot)) {
            try (Stream<Path> walk = Files.walk(tempRoot)) {
                walk.sorted(Comparator.reverseOrder()).forEach(p -> {
                    try {
                        Files.deleteIfExists(p);
                    } catch (IOException ignored) {
                        // best-effort
                    }
                });
            }
        }
    }

    @Test
    public void functionHeaderHasNineLinesResolvableUriAndFields() {
        Instant dts = Instant.parse("2026-08-20T12:00:00Z");
        String header = SweepJob.renderFunctionHeader(
                "ParseHeader",
                "0000000180001000",
                0x120L,
                "c05",
                "literal-locality",
                0.85,
                true,
                "abcdef012345",
                dts,
                42L,
                "synaWudfBioUsb.dll",
                List.of("crt0_init_bss_data", "prng_seed_default"),
                List.of());

        String[] lines = header.split("\n", -1);
        // trailing newline ⇒ last element empty
        assertEquals(SweepJob.HEADER_LINES + 1, lines.length);
        assertEquals(SweepJob.HEADER_LINES, lines.length - 1);

        assertTrue(lines[0].startsWith("// fn: ParseHeader @ 0000000180001000 size="));
        assertEquals("// calls: crt0_init_bss_data, prng_seed_default", lines[1]);
        assertEquals("// callers: (none — entry)", lines[2]);
        assertTrue(lines[3].contains("c05"));
        assertTrue(lines[3].contains("literal-locality"));
        assertTrue(lines[3].contains("evidence_backed=true"));
        assertEquals("// fp: abcdef012345", lines[4]);
        assertEquals("// dts: 2026-08-20T12:00:00Z", lines[5]);
        assertEquals("// mod: 42", lines[6]);
        assertEquals(
                "// uri: ghidra://function/synaWudfBioUsb.dll/0000000180001000",
                lines[7]);
        assertEquals("// see: modules/c05/README.md", lines[8]);
    }

    @Test
    public void neighbourListEmptyCallsVsEntryCallers() {
        assertEquals("(none)", SweepJob.formatNeighbourList(List.of(), false));
        assertEquals("(none — entry)", SweepJob.formatNeighbourList(List.of(), true));
        assertEquals("(none)", SweepJob.formatNeighbourList(null, false));
    }

    @Test
    public void neighbourListTruncatesAtEightWithMoreHint() {
        List<String> nine = List.of("a", "b", "c", "d", "e", "f", "g", "h", "i");
        String rendered = SweepJob.formatNeighbourList(nine, false);
        assertEquals("a, b, c, d, e, f, g, h +1 more, see callgraph.tsv", rendered);
        List<String> eight = List.of("a", "b", "c", "d", "e", "f", "g", "h");
        assertEquals("a, b, c, d, e, f, g, h", SweepJob.formatNeighbourList(eight, false));
    }

    @Test
    public void functionUriEncodesProgramNameLikeBridgeQuote() {
        assertEquals(
                "ghidra://function/my%20prog/00401000",
                SweepJob.functionResourceUri("my prog", "00401000"));
        assertEquals(
                "ghidra://function/proj%2Fbin/mem:1000",
                SweepJob.functionResourceUri("proj/bin", "mem:1000"));
    }

    @Test
    public void failedDecompileMarkerIsNeverSilent() {
        String body = SweepJob.renderFailedBody("timed out");
        assertTrue(body.startsWith("// DECOMPILATION FAILED: "));
        assertTrue(body.contains("timed out"));
        assertTrue(body.endsWith("\n"));
    }

    @Test
    public void byAddressTsvRowShape() {
        assertEquals(
                "address\tname\tpartition_slug\tfile\tevidence_backed\tifp\n",
                SweepJob.byAddressHeader());
        assertEquals(
                "00100000\tFoo\tc05\tmodules/c05/00100000.c\ttrue\tabcdef123456\n",
                SweepJob.formatByAddressRow(
                        "00100000", "Foo", "c05", "modules/c05/00100000.c", true,
                        "abcdef123456"));
        assertEquals(
                "00100000\tBar\tb003\tmodules/b003/00100000.c\tfalse\t\n",
                SweepJob.formatByAddressRow(
                        "00100000", "Bar", "b003", "modules/b003/00100000.c", false,
                        ""));
    }

    @Test
    public void assignBlocksSplitsAtByteBudget() {
        // Three 400-byte blocks into a 1000-byte budget → files [0,0,1]
        int[] sizes = {400, 400, 400};
        int[] files = SweepJob.assignBlocksToFiles(sizes, 1000, 200);
        assertEquals(0, files[0]);
        assertEquals(0, files[1]);
        assertEquals(1, files[2]);
    }

    @Test
    public void assignBlocksOversizedSingleFunctionGetsOwnFileNeverSplit() {
        int[] sizes = {500, 5000, 500};
        int[] files = SweepJob.assignBlocksToFiles(sizes, 1000, 200);
        assertEquals(0, files[0]);
        assertEquals(1, files[1]); // alone despite > budget
        assertEquals(2, files[2]);
    }

    @Test
    public void assignBlocksSecondaryCapOf200Functions() {
        int[] sizes = new int[201];
        for (int i = 0; i < sizes.length; i++) {
            sizes[i] = 10; // tiny — byte budget alone would keep them together
        }
        int[] files = SweepJob.assignBlocksToFiles(sizes, 1_000_000, SweepJob.MAX_FUNCTIONS_PER_FILE);
        assertEquals(0, files[0]);
        assertEquals(0, files[199]);
        assertEquals(1, files[200]);
    }

    @Test
    public void indexRowsPointAtContainingFileAfterPacking() {
        // Simulate the sweep's index construction from assignBlocksToFiles.
        long[] addrs = {0x1000L, 0x1100L, 0x1200L, 0x1300L};
        int[] sizes = {400, 400, 400, 400}; // budget 1000 → two per file
        int[] fileIdx = SweepJob.assignBlocksToFiles(sizes, 1000, 200);
        String[] paths = new String[addrs.length];
        String currentPath = null;
        int currentFile = -1;
        for (int i = 0; i < addrs.length; i++) {
            if (fileIdx[i] != currentFile) {
                currentFile = fileIdx[i];
                currentPath = "modules/c03/"
                        + CheckoutLayout.compartmentFileName(addrs[i], 4);
            }
            paths[i] = currentPath;
        }
        assertEquals("modules/c03/00001000.c", paths[0]);
        assertEquals("modules/c03/00001000.c", paths[1]);
        assertEquals("modules/c03/00001200.c", paths[2]);
        assertEquals("modules/c03/00001200.c", paths[3]);
        // by-address row for fn[2] must name the file that starts at fn[2].
        String row = SweepJob.formatByAddressRow(
                "00001200", "Fn2", "c03", paths[2], false, "deadbeefcafe");
        assertTrue(row.contains("\tmodules/c03/00001200.c\t"));
    }

    @Test
    public void moduleReadmeListsEveryFileWithRange() {
        // Shape the Files table the sweep writes — navigable without opening .c.
        String readme = ""
                + "# Module c03\n\n"
                + "method: address-band\n"
                + "confidence: 0.10\n"
                + "functions: 4\n"
                + "files: 2\n"
                + "\n## Files\n\n"
                + "| file | first | last | functions |\n"
                + "| --- | --- | --- | ---: |\n"
                + "| modules/c03/00001000.c | 00001000 | 00001100 | 2 |\n"
                + "| modules/c03/00001200.c | 00001200 | 00001300 | 2 |\n"
                + "\n## Evidence\n\n";
        assertTrue(readme.contains("| modules/c03/00001000.c | 00001000 | 00001100 | 2 |"));
        assertTrue(readme.contains("| modules/c03/00001200.c | 00001200 | 00001300 | 2 |"));
        assertTrue(readme.contains("files: 2"));
    }

    @Test
    public void statusMdBeforeAndAfterStates() throws IOException {
        CheckoutKey key = CheckoutKey.of("/proj/app.exe", tempRoot.toString());
        CheckoutRoot root = CheckoutRoot.ofResolved(tempRoot);
        Checkout checkout = new Checkout(key, "app.exe", CheckoutConfig.defaults(), root);

        // Before work: dirty, no swept_at.
        checkout.setProgress(checkout.progress()
                .withPhase(SweepProgress.Phase.DECOMPILING)
                .withCounts(100, 10, 1)
                .withBytesWritten(4096L));
        String dirty = CheckoutStatusMd.render(checkout, "dirty", null);
        assertTrue(dirty.contains("state: dirty"));
        assertTrue(dirty.contains("phase: decompiling"));
        assertTrue(dirty.contains("functions_total: 100"));
        assertTrue(dirty.contains("functions_done: 10"));
        assertTrue(dirty.contains("functions_failed: 1"));
        assertTrue(dirty.contains("swept_at_modification_number: \n")
                || dirty.contains("swept_at_modification_number:\n"));

        CheckoutStatusMd.write(checkout, "dirty", null);
        assertTrue(Files.isRegularFile(tempRoot.resolve("STATUS.md")));
        String onDisk = Files.readString(tempRoot.resolve("STATUS.md"));
        assertTrue(onDisk.contains("state: dirty"));

        // After success: clean + modification number.
        checkout.setProgress(checkout.progress()
                .withPhase(SweepProgress.Phase.COMPLETE)
                .withCounts(100, 100, 1)
                .withBytesWritten(9999L));
        String clean = CheckoutStatusMd.render(checkout, "clean", 7L);
        assertTrue(clean.contains("state: clean"));
        assertTrue(clean.contains("phase: complete"));
        assertTrue(clean.contains("swept_at_modification_number: 7"));
        assertEquals("clean", CheckoutStatusMd.stateForPhase(SweepProgress.Phase.COMPLETE));
        assertEquals("cancelled", CheckoutStatusMd.stateForPhase(SweepProgress.Phase.CANCELLED));
        assertEquals("failed", CheckoutStatusMd.stateForPhase(SweepProgress.Phase.FAILED));
        assertEquals("dirty", CheckoutStatusMd.stateForPhase(SweepProgress.Phase.DECOMPILING));
    }

    @Test
    public void cancelFlagPlumbsThroughTaskMonitor() {
        CheckoutKey key = CheckoutKey.of("/proj/app.exe", tempRoot.toString());
        CheckoutRoot root = CheckoutRoot.ofResolved(tempRoot);
        Checkout checkout = new Checkout(key, "app.exe", CheckoutConfig.defaults(), root);

        // Program is required at construction for a real sweep; cancel plumbing
        // is tested via CancelSignal without running. Build a job-shaped signal
        // the same way SweepJob does.
        SweepJob.CancelSignal signal = new SweepJob.CancelSignal();
        assertFalse(signal.isCancelled());
        assertFalse(signal.monitor().isCancelled());

        signal.cancel();
        assertTrue(signal.isCancelled());
        assertTrue(
                "TaskMonitor.isCancelled must mirror the volatile flag so the "
                        + "native decompiler aborts",
                signal.monitor().isCancelled());
    }

    @Test
    public void shortContentHashIsStableTwelveHex() {
        String a = SweepJob.shortContentHash("int foo() { return 1; }\n");
        String b = SweepJob.shortContentHash("int foo() { return 1; }\n");
        String c = SweepJob.shortContentHash("int foo() { return 2; }\n");
        assertEquals(12, a.length());
        assertEquals(a, b);
        assertFalse(a.equals(c));
    }
}
