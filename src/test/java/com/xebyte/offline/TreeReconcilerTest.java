package com.xebyte.offline;

import com.xebyte.core.checkout.BlockSplicer;
import com.xebyte.core.checkout.Checkout;
import com.xebyte.core.checkout.CheckoutConfig;
import com.xebyte.core.checkout.CheckoutKey;
import com.xebyte.core.checkout.CheckoutLayout;
import com.xebyte.core.checkout.CheckoutRoot;
import com.xebyte.core.checkout.CheckoutTreeNarrower;
import com.xebyte.core.checkout.ModuleOverrides;
import com.xebyte.core.checkout.SweepJob;
import com.xebyte.core.checkout.SweepProgress;
import com.xebyte.core.checkout.TreeReconciler;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.program.model.util.StringPropertyMap;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Offline tests for the three reconcile primitives, file split/delete, pin vs
 * containment placement, empty-ifp re-check, and zero-decompile full pass.
 */
public class TreeReconcilerTest {

    private Path tempRoot;
    private Checkout checkout;

    @Before
    public void setUp() throws IOException {
        tempRoot = Files.createTempDirectory("tree-reconciler-test");
        CheckoutKey key = CheckoutKey.of("/proj/app.exe", tempRoot.toString());
        CheckoutRoot root = CheckoutRoot.ofResolved(tempRoot);
        checkout = new Checkout(key, "app.exe", CheckoutConfig.defaults(), root);
        checkout.setProgress(SweepProgress.idle().withPhase(SweepProgress.Phase.COMPLETE));
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

    // -------------------------------------------------------------------------
    // planWork / ifp — the cheap full-reconcile gate
    // -------------------------------------------------------------------------

    @Test
    public void planWork_classifiesReplaceInsertRemove() {
        Map<String, CheckoutTreeNarrower.IndexEntry> index = new LinkedHashMap<>();
        index.put("00100000", entry("00100000", "Foo", "c05", "modules/c05/00100000.c", "aaa"));
        index.put("00100100", entry("00100100", "Bar", "c05", "modules/c05/00100000.c", "bbb"));

        Map<String, Function> prog = new LinkedHashMap<>();
        prog.put("00100000", mock(Function.class)); // surviving → replace
        prog.put("00100200", mock(Function.class)); // new → insert
        // 00100100 absent → remove

        TreeReconciler.WorkPlan plan = TreeReconciler.planWork(index, prog, null);
        assertEquals(Set.of("00100000"), plan.replace());
        assertEquals(Set.of("00100200"), plan.insert());
        assertEquals(Set.of("00100100"), plan.remove());
    }

    @Test
    public void emptyIfpForcesRecheck() {
        assertTrue(TreeReconciler.needsRedecompile("", "abcdefabcdef"));
        assertTrue(TreeReconciler.needsRedecompile(null, "abcdefabcdef"));
        assertTrue(TreeReconciler.needsRedecompile("   ", "abcdefabcdef"));
        assertTrue(TreeReconciler.needsRedecompile("oldoldoldold", "newnewnewnew"));
        assertFalse(TreeReconciler.needsRedecompile("samefpsamefp", "samefpsamefp"));
    }

    @Test
    public void fullReconcileUnchangedTreeNeedsZeroDecompiles() {
        // The gate the full pass uses: matching non-empty ifp → skip.
        Map<String, CheckoutTreeNarrower.IndexEntry> index = new LinkedHashMap<>();
        index.put("00100000", entry("00100000", "Foo", "c05", "modules/c05/00100000.c", "aaa111aaa111"));
        index.put("00100100", entry("00100100", "Bar", "c05", "modules/c05/00100000.c", "bbb222bbb222"));

        int needing = 0;
        Map<String, String> live = Map.of(
                "00100000", "aaa111aaa111",
                "00100100", "bbb222bbb222");
        for (String hex : index.keySet()) {
            if (TreeReconciler.needsRedecompile(index.get(hex).ifp(), live.get(hex))) {
                needing++;
            }
        }
        assertEquals("unchanged ifps must produce zero decompiles", 0, needing);

        // Empty ifp on a surviving address still counts as needing work.
        index.put("00100000", entry("00100000", "Foo", "c05", "modules/c05/00100000.c", ""));
        assertTrue(TreeReconciler.needsRedecompile(
                index.get("00100000").ifp(), live.get("00100000")));
    }

    // -------------------------------------------------------------------------
    // Placement
    // -------------------------------------------------------------------------

    @Test
    public void insertWithoutPinRecordsContainmentAndNotEvidenceBacked() {
        Map<String, CheckoutTreeNarrower.IndexEntry> index = new LinkedHashMap<>();
        index.put("00100000", entry("00100000", "Foo", "c05", "modules/c05/00100000.c", "a"));
        index.put("00100200", entry("00100200", "Baz", "c05", "modules/c05/00100000.c", "c"));
        index.put("00200000", entry("00200000", "Other", "b001", "modules/b001/00200000.c", "d"));

        TreeReconciler.Placement p =
                TreeReconciler.placeByContainment("00100100", index);
        assertEquals("c05", p.slug());
        assertEquals(TreeReconciler.METHOD_CONTAINMENT, p.method());
        assertFalse(p.evidenceBacked());
    }

    @Test
    public void insertRespectsPin() {
        Program program = mock(Program.class);
        PropertyMapManager propMgr = mock(PropertyMapManager.class);
        StringPropertyMap map = mock(StringPropertyMap.class);
        when(program.getUsrPropertyManager()).thenReturn(propMgr);
        when(propMgr.getStringPropertyMap(ModuleOverrides.MAP_NAME)).thenReturn(map);

        Address entry = mock(Address.class);
        when(entry.toString(false)).thenReturn("00100150");
        when(map.hasProperty(entry)).thenReturn(true);
        when(map.getString(entry)).thenReturn("driver_usb");

        Function func = mock(Function.class);
        when(func.getEntryPoint()).thenReturn(entry);

        Map<String, CheckoutTreeNarrower.IndexEntry> index = new LinkedHashMap<>();
        index.put("00100000", entry("00100000", "Foo", "c05", "modules/c05/00100000.c", "a"));

        TreeReconciler.Placement p = TreeReconciler.place(func, program, index);
        assertEquals("driver_usb", p.slug());
        assertEquals(ModuleOverrides.METHOD, p.method());
        assertTrue(p.evidenceBacked());
    }

    // -------------------------------------------------------------------------
    // Pure block insert / remove / split
    // -------------------------------------------------------------------------

    @Test
    public void insertBlockGoesInAddressOrder() {
        String body = twoBlocks("00100000", "Foo", "00100200", "Baz");
        String mid = rebuildBlock("Bar", "00100100", "cccccccccccc", "void Bar(void) {}\n");
        String out = TreeReconciler.insertBlockInAddressOrder(body, mid);
        List<String> chunks = CheckoutTreeNarrower.splitFunctionChunks(out);
        assertEquals(3, chunks.size());
        assertEquals("00100000", CheckoutTreeNarrower.addressFromChunk(chunks.get(0)));
        assertEquals("00100100", CheckoutTreeNarrower.addressFromChunk(chunks.get(1)));
        assertEquals("00100200", CheckoutTreeNarrower.addressFromChunk(chunks.get(2)));
    }

    @Test
    public void removeThatEmptiesFileYieldsBlank() {
        String alone = rebuildBlock("Only", "00100000", "aaaaaaaaaaaa", "void Only(void) {}\n");
        String out = TreeReconciler.removeBlockFromFile(alone, "00100000");
        assertTrue(out.isBlank());
    }

    @Test
    public void insertIntoFullFileSplitsAndBothHalvesKeepCorrectNames() throws IOException {
        // Two large blocks already at the budget edge; inserting a third forces a split.
        // Use a tiny maxFileBytes via the pure splitter (bypasses config floor).
        String a = paddedBlock("Aaa", "00100000", 1200);
        String b = paddedBlock("Bbb", "00100100", 1200);
        String c = paddedBlock("Ccc", "00100080", 1200); // inserts between a and b
        String body = TreeReconciler.insertBlockInAddressOrder(
                TreeReconciler.insertBlockInAddressOrder(a + "\n", b), c);

        List<String> halves = TreeReconciler.splitFileBody(body, 2500, 200);
        assertTrue("expected a split into 2+ files, got " + halves.size(), halves.size() >= 2);

        String path0 = TreeReconciler.filePathForBody("c05", halves.get(0), 4);
        String path1 = TreeReconciler.filePathForBody("c05", halves.get(1), 4);
        assertEquals("modules/c05/00100000.c", path0);
        // Second half named for its first address — not a copy of the original name.
        assertTrue(path1.startsWith("modules/c05/"));
        assertTrue(path1.endsWith(".c"));
        assertFalse(path0.equals(path1));

        // Index rows would track each address to its half.
        Map<String, String> addrToFile = new LinkedHashMap<>();
        for (String half : halves) {
            String path = TreeReconciler.filePathForBody("c05", half, 4);
            for (String chunk : CheckoutTreeNarrower.splitFunctionChunks(half)) {
                addrToFile.put(
                        com.xebyte.core.checkout.CheckoutAddresses.normalize(
                                CheckoutTreeNarrower.addressFromChunk(chunk)),
                        path);
            }
        }
        assertEquals(path0, addrToFile.get("00100000"));
        assertEquals(3, addrToFile.size());
        // The middle insert lands in whichever half covers it; both halves named correctly.
        assertTrue(addrToFile.containsKey("00100080"));
        assertTrue(addrToFile.containsKey("00100100"));
    }

    @Test
    public void removeThatEmptiesFileDeletesItOnDisk() throws IOException {
        String relative = "modules/c05/00100000.c";
        String body = rebuildBlock("Only", "00100000", "aaaaaaaaaaaa", "void Only(void) {}\n");
        checkout.root().writeFile(Path.of(relative), body);
        checkout.root().writeFile(
                Path.of(CheckoutLayout.byAddressTsv()),
                SweepJob.byAddressHeader()
                        + SweepJob.formatByAddressRow(
                                "00100000", "Only", "c05", relative, false, "aaa"));

        Map<String, CheckoutTreeNarrower.IndexEntry> working = new LinkedHashMap<>();
        working.put("00100000", entry("00100000", "Only", "c05", relative, "aaa"));

        String filtered = TreeReconciler.removeBlockFromFile(body, "00100000");
        assertTrue(filtered.isBlank());
        Files.deleteIfExists(tempRoot.resolve(relative));
        working.remove("00100000");
        CheckoutTreeNarrower.rebuildIndexes(checkout, List.copyOf(working.values()), Set.of("c05"));

        assertFalse(Files.exists(tempRoot.resolve(relative)));
        assertFalse(Files.exists(tempRoot.resolve("modules/c05")));
        List<CheckoutTreeNarrower.IndexEntry> rows = CheckoutTreeNarrower.readIndex(
                tempRoot.resolve(CheckoutLayout.byAddressTsv()));
        assertTrue(rows.isEmpty());
    }

    /**
     * The reconciler used to write its own short README, so the first edit that touched a
     * compartment dropped method, confidence and evidence (peripheral_pages among them) and
     * stamped it "narrowed by /decompile_checkout_configure".
     */
    @Test
    public void aReconcileKeepsTheSweepsGroupingAndRecountsTheFiles() throws IOException {
        String readme = com.xebyte.core.checkout.ModuleReadme.render("m03",
                new com.xebyte.core.checkout.ModuleReadme.Grouping("mmio-page", 0.84,
                        new LinkedHashMap<>(Map.of("peripheral_pages", "0x40003000,0x40020000")), null),
                1, List.of(new com.xebyte.core.checkout.ModuleReadme.FileRow(
                        "modules/m03/00100000.c", "00100000", "00100000", 1)));
        checkout.root().writeFile(Path.of(CheckoutLayout.moduleReadme("m03")), readme);

        CheckoutTreeNarrower.rebuildIndexes(checkout, List.of(
                entry("00100000", "spi_init", "m03", "modules/m03/00100000.c", "a"),
                entry("00100100", "spi_send", "m03", "modules/m03/00100000.c", "b")), Set.of("m03"));

        String after = Files.readString(tempRoot.resolve(CheckoutLayout.moduleReadme("m03")));
        assertTrue(after, after.contains("method: mmio-page\nconfidence: 0.84\nfunctions: 2\n"));
        assertTrue(after, after.contains("- peripheral_pages: 0x40003000,0x40020000"));
        assertTrue(after, after.contains("| modules/m03/00100000.c | 00100000 | 00100100 | 2 |"));
        assertFalse(after, after.contains("narrowed"));
        assertEquals("a second rewrite changes nothing",
                after, rewriteAgain());
    }

    private String rewriteAgain() throws IOException {
        CheckoutTreeNarrower.rebuildIndexes(checkout, List.of(
                entry("00100000", "spi_init", "m03", "modules/m03/00100000.c", "a"),
                entry("00100100", "spi_send", "m03", "modules/m03/00100000.c", "b")), Set.of("m03"));
        return Files.readString(tempRoot.resolve(CheckoutLayout.moduleReadme("m03")));
    }

    @Test
    public void replacePrimitiveSwapsBlockInPlace() {
        String body = twoBlocks("00100000", "Foo", "00100100", "Bar");
        String newBar = rebuildBlock(
                "BarRenamed", "00100100", "dddddddddddd", "void BarRenamed(void) {}\n");
        BlockSplicer.SpliceResult splice =
                BlockSplicer.spliceFile(body, Map.of("00100100", newBar));
        assertTrue(splice.rewritten());
        assertEquals(List.of("00100100"), splice.refreshed());
        assertTrue(splice.newBody().contains("// fn: BarRenamed @ 00100100"));
        assertTrue(splice.newBody().contains("// fn: Foo @ 00100000"));
    }

    @Test
    public void statusMdTracksSplicedSinceSweep() {
        checkout.setProgress(checkout.progress().withSplicedSinceSweep(3));
        String rendered = com.xebyte.core.checkout.CheckoutStatusMd.render(checkout, "spliced");
        assertTrue(rendered.contains("spliced_since_sweep: 3"));
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static CheckoutTreeNarrower.IndexEntry entry(
            String addr, String name, String slug, String file, String ifp) {
        return new CheckoutTreeNarrower.IndexEntry(addr, name, slug, file, false, ifp);
    }

    private static String twoBlocks(String a1, String n1, String a2, String n2) {
        return rebuildBlock(n1, a1, "aaaaaaaaaaaa", "void " + n1 + "(void) {}\n")
                + "\n"
                + rebuildBlock(n2, a2, "bbbbbbbbbbbb", "void " + n2 + "(void) {}\n")
                + "\n";
    }

    /**
     * A caller the decompiler resolved through a literal pool has no reference to the
     * callee, so only its text says it uses the name: the old name must be found in the
     * body, and a header line or a longer identifier must not count.
     */
    @Test
    public void blocksMentioningFindsBodiesThatStillPrintAName() throws IOException {
        String file = rebuildBlock("Caller", "00100000", "aaaaaaaaaaaa",
                        "void Caller(void) {\n  ws2812_set_pixel(1,2);\n}\n")
                + "\n" + rebuildBlock("Other", "00100100", "bbbbbbbbbbbb",
                        "void Other(void) {\n  ws2812_set_pixel_fast(1);\n}\n")
                + "\n" + rebuildBlock("ws2812_set_pixel", "00100200", "cccccccccccc",
                        "void x(void) {}\n");
        checkout.root().writeFile(Path.of("modules/c05/00100000.c"), file);

        assertEquals(Set.of("00100000"),
                TreeReconciler.blocksMentioning(checkout, List.of("ws2812_set_pixel")));
        assertEquals(Set.of(), TreeReconciler.blocksMentioning(checkout, List.of()));
    }

    private static String rebuildBlock(String name, String addr, String fp, String body) {
        return TestBlocks.block(name, addr, fp, body);
    }

    /** Oversized body so byte-budget splits fire under a small maxFileBytes. */
    private static String paddedBlock(String name, String addr, int bodyPad) {
        StringBuilder pad = new StringBuilder(bodyPad);
        for (int i = 0; i < bodyPad; i++) {
            pad.append('x');
        }
        return rebuildBlock(name, addr, SweepJob.shortContentHash(pad.toString()),
                "void " + name + "(void) { /* " + pad + " */ }\n");
    }
}
