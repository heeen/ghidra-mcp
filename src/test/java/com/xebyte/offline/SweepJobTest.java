package com.xebyte.offline;

import com.xebyte.core.checkout.Checkout;
import com.xebyte.core.checkout.CheckoutConfig;
import com.xebyte.core.checkout.CheckoutKey;
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
    public void functionHeaderHasSevenLinesResolvableUriAndFields() {
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
                "synaWudfBioUsb.dll");

        String[] lines = header.split("\n", -1);
        // trailing newline ⇒ last element empty
        assertEquals(8, lines.length);
        assertEquals(7, lines.length - 1);

        assertTrue(lines[0].startsWith("// fn: ParseHeader @ 0000000180001000 size="));
        assertTrue(lines[1].contains("c05"));
        assertTrue(lines[1].contains("literal-locality"));
        assertTrue(lines[1].contains("evidence_backed=true"));
        assertEquals("// fp: abcdef012345", lines[2]);
        assertEquals("// dts: 2026-08-20T12:00:00Z", lines[3]);
        assertEquals("// mod: 42", lines[4]);
        assertEquals(
                "// uri: ghidra://function/synaWudfBioUsb.dll/0000000180001000",
                lines[5]);
        assertEquals("// see: modules/c05/README.md", lines[6]);
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
                "address\tname\tpartition_slug\tfile\tevidence_backed\n",
                SweepJob.byAddressHeader());
        assertEquals(
                "00100000\tFoo\tc05\tmodules/c05/c05.c\ttrue\n",
                SweepJob.formatByAddressRow(
                        "00100000", "Foo", "c05", "modules/c05/c05.c", true));
        assertEquals(
                "00100000\tBar\tb003\tmodules/b003/b003.c\tfalse\n",
                SweepJob.formatByAddressRow(
                        "00100000", "Bar", "b003", "modules/b003/b003.c", false));
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
