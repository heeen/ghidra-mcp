package com.xebyte.core.checkout;

import com.xebyte.core.FunctionFacts;
import com.xebyte.core.ServiceUtils;
import com.xebyte.core.partition.PartitionContext;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Pattern;

/**
 * Reconcile the on-disk checkout tree with the live program.
 *
 * <p>Events are hints about where to look; this class is the thing that acts.
 * Ghidra can suppress, coalesce, or replace change events — so splicing driven
 * purely by events silently goes wrong. Three primitives are closed under every
 * change the program can make, which is what lets {@code mark_stale} die:
 *
 * <ul>
 *   <li>{@code replace} — in tree and in program → re-decompile, swap block
 *   <li>{@code insert} — in program, not in tree → place, insert in address
 *       order, split the file if over budget
 *   <li>{@code remove} — in tree, not in program → delete block; delete the
 *       file if it empties
 * </ul>
 *
 * <p>Never routes through {@code ThreadingStrategy} (same EDT/global-lock rule
 * as {@link SweepJob}). One pooled {@link DecompInterface} for the whole pass.
 *
 * @since 7.2.0
 */
public final class TreeReconciler {

    /** Placement method when the pin map did not claim the function. */
    public static final String METHOD_CONTAINMENT = "containment";

    private TreeReconciler() {
    }

    // -------------------------------------------------------------------------
    // Public entry points
    // -------------------------------------------------------------------------

    /** Full reconcile: address-set diff + ifp compare; decompile only mismatches. */
    public static ReconcileResult reconcile(Checkout checkout, Program program)
            throws IOException {
        return reconcile(checkout, program, null);
    }

    /**
     * Targeted reconcile over {@code addresses}. {@code null} addresses means
     * full (index-driven). An empty set is a no-op that still reports counts.
     */
    public static ReconcileResult reconcile(
            Checkout checkout, Program program, Set<String> addresses) throws IOException {
        Objects.requireNonNull(checkout, "checkout");
        Objects.requireNonNull(program, "program");
        long started = System.currentTimeMillis();
        // What the tree will reflect when this pass ends; edits arriving meanwhile queue
        // another pass, so claiming a later number would overstate it.
        long reconcilingAt = program.getModificationNumber();

        Path indexPath = checkout.root().path().resolve(CheckoutLayout.byAddressTsv());
        List<CheckoutTreeNarrower.IndexEntry> indexRows = Files.isRegularFile(indexPath)
                ? CheckoutTreeNarrower.readIndex(indexPath)
                : List.of();
        Map<String, CheckoutTreeNarrower.IndexEntry> indexByHex = new LinkedHashMap<>();
        for (CheckoutTreeNarrower.IndexEntry row : indexRows) {
            indexByHex.put(CheckoutTreeNarrower.normalizeHex(row.addressHex()), row);
        }

        PartitionContext ctx = new PartitionContext(program);
        ExclusionEvaluator evaluator = ExclusionEvaluator.of(program, checkout.config());

        Map<String, Function> programByHex = new LinkedHashMap<>();
        for (Function f : ctx.functions()) {
            programByHex.put(
                    CheckoutTreeNarrower.normalizeHex(f.getEntryPoint().toString(false)), f);
        }

        WorkPlan plan = planWork(indexByHex, programByHex, addresses);

        Accumulators acc = new Accumulators();
        checkout.setProgress(checkout.progress().withLastError(null));
        CheckoutStatusMd.write(checkout, "dirty");

        DecompInterface decomp = null;
        int decompileCalls = 0;
        try {
            Map<String, CheckoutTreeNarrower.IndexEntry> working =
                    new LinkedHashMap<>(indexByHex);

            // Pre-filter full-reconcile replaces by ifp so an unchanged tree
            // creates no DecompInterface and reports decompile_calls=0.
            Set<String> replaceNow = new LinkedHashSet<>();
            if (addresses == null) {
                for (String hex : plan.replace) {
                    CheckoutTreeNarrower.IndexEntry row = working.get(hex);
                    Function func = programByHex.get(hex);
                    if (row == null || func == null) {
                        acc.failed.add(hex);
                        acc.failedReasons.add("replace_missing");
                        continue;
                    }
                    String liveIfp = InputFingerprint.of(func);
                    if (!needsRedecompile(row.ifp(), liveIfp)) {
                        acc.unchanged.add(hex);
                    } else {
                        replaceNow.add(hex);
                    }
                }
            } else {
                replaceNow.addAll(plan.replace);
            }

            boolean needsDecomp = !replaceNow.isEmpty() || !plan.insert.isEmpty();
            if (needsDecomp) {
                decomp = ServiceUtils.createConfiguredDecompiler(program, FunctionFacts::configureDecompiler);
            }
            long mod = program.getModificationNumber();
            int timeout = checkout.config().decompileTimeoutSeconds();
            int pointerSize = Math.max(1, program.getDefaultPointerSize());
            int maxFileBytes = checkout.config().maxFileBytes();

            Set<String> touchedSlugs = new LinkedHashSet<>();
            Set<String> seedForNeighbours = new LinkedHashSet<>();
            Map<String, List<AddressIndex.Row>> addressRows = new LinkedHashMap<>();

            // Removes first — frees file budget before inserts land in the same file.
            for (String hex : plan.remove) {
                CheckoutTreeNarrower.IndexEntry row = working.get(hex);
                if (row == null) {
                    continue;
                }
                RemoveOutcome out = removeFromTree(
                        checkout, working, hex, row, pointerSize);
                acc.removed.add(hex);
                acc.filesWritten += out.filesWritten;
                acc.filesDeleted += out.filesDeleted;
                touchedSlugs.add(row.slug());
                seedForNeighbours.add(hex);
            }

            for (String hex : replaceNow) {
                CheckoutTreeNarrower.IndexEntry row = working.get(hex);
                Function func = programByHex.get(hex);
                if (row == null || func == null) {
                    acc.failed.add(hex);
                    acc.failedReasons.add("replace_missing");
                    continue;
                }
                BlockSplicer.PartitionMeta part = partitionMetaForReplace(checkout, row);
                FunctionBlock.Built built = BlockSplicer.decompileBlock(
                        decomp, func, part, mod, timeout, program.getName());
                decompileCalls++;
                addressRows.put(hex, built.addresses());
                ReplaceOutcome out = replaceInTree(checkout, working, hex, row, func, built.text());
                if (out.skipped()) {
                    acc.unchanged.add(hex);
                } else if (out.ok()) {
                    acc.replaced.add(hex);
                    acc.filesWritten += out.filesWritten();
                    touchedSlugs.add(row.slug());
                    seedForNeighbours.add(hex);
                } else {
                    acc.failed.add(hex);
                    acc.failedReasons.add(out.reason());
                }
            }

            for (String hex : plan.insert) {
                Function func = programByHex.get(hex);
                if (func == null) {
                    acc.failed.add(hex);
                    acc.failedReasons.add("function_not_found");
                    continue;
                }
                Placement placement = place(func, program, working);
                if (!evaluator.isInScope(func, placement.slug())) {
                    // Out of scope under current exclusions — tree must not claim it.
                    continue;
                }
                BlockSplicer.PartitionMeta part = new BlockSplicer.PartitionMeta(
                        placement.slug(), placement.method(), placement.confidence(),
                        placement.evidenceBacked());
                FunctionBlock.Built built = BlockSplicer.decompileBlock(
                        decomp, func, part, mod, timeout, program.getName());
                decompileCalls++;
                InsertOutcome out = insertIntoTree(
                        checkout, working, func, built.text(), placement,
                        pointerSize, maxFileBytes);
                if (out.ok) {
                    addressRows.put(hex, built.addresses());
                    acc.inserted.add(hex);
                    acc.filesWritten += out.filesWritten;
                    acc.filesSplit += out.filesSplit;
                    touchedSlugs.add(placement.slug());
                    seedForNeighbours.add(hex);
                } else {
                    acc.failed.add(hex);
                    acc.failedReasons.add(out.reason);
                }
            }

            // Neighbours of every structural change need header-only calls/callers.
            acc.filesWritten += patchNeighbourHeaders(
                    checkout, program, ctx, working, seedForNeighbours, acc);

            if (!touchedSlugs.isEmpty() || !acc.replaced.isEmpty()
                    || !acc.inserted.isEmpty() || !acc.removed.isEmpty()) {
                List<CheckoutTreeNarrower.IndexEntry> finalRows =
                        new ArrayList<>(working.values());
                CheckoutTreeNarrower.rebuildIndexes(checkout, finalRows, touchedSlugs);
                AddressIndex.update(checkout, addressRows);
                checkout.root().writeFile(
                        Path.of(CheckoutLayout.callgraphTsv()),
                        SweepJob.renderCallgraphTsv(ctx));
            }
        } finally {
            if (decomp != null) {
                try {
                    decomp.dispose();
                } catch (Exception ignored) {
                    // must not mask reconcile outcome
                }
            }
        }

        int structural = acc.inserted.size() + acc.removed.size();
        int rewritten = acc.replaced.size() + structural;
        SweepProgress before = checkout.progress();
        SweepProgress after = before
                .withLastError(before.phase() == SweepProgress.Phase.STALE ? before.lastError() : null)
                .reconciledAt(reconcilingAt, rewritten, structural);
        if (addresses == null && checkout.recoverOnReattach()) {
            // The full pass after a stale close re-diffed every block against the program
            // as it reopened: the divergence that made it stale is gone.
            checkout.setRecoverOnReattach(false);
            after = after
                    .withPhase(after.sweptAtModification() != null
                            ? SweepProgress.Phase.COMPLETE : SweepProgress.Phase.IDLE)
                    .withLastError(null);
        }
        checkout.setProgress(after);
        CheckoutStatusMd.write(checkout, CheckoutStatusMd.settledState(checkout.progress()));

        return ReconcileResult.of(
                acc.replaced, acc.inserted, acc.removed, acc.headerPatched, acc.unchanged,
                acc.failed, acc.failedReasons,
                acc.filesWritten, acc.filesSplit, acc.filesDeleted,
                decompileCalls, System.currentTimeMillis() - started,
                checkout.progress().splicedSinceSweep());
    }

    /**
     * Entry addresses of blocks whose decompiled body (not the header) uses one of
     * {@code names} as a whole identifier. A rename's old name is printed wherever the
     * decompiler resolved the symbol, including calls it worked out through a register or
     * a literal pool, where the program records no reference to look up.
     */
    public static Set<String> blocksMentioning(Checkout checkout, Collection<String> names)
            throws IOException {
        Set<String> found = new LinkedHashSet<>();
        if (names == null || names.isEmpty()) {
            return found;
        }
        Pattern any = Pattern.compile("(?<![A-Za-z0-9_])(?:"
                + names.stream().map(Pattern::quote).collect(java.util.stream.Collectors.joining("|"))
                + ")(?![A-Za-z0-9_])");
        Path modules = checkout.root().path().resolve("modules");
        if (!Files.isDirectory(modules)) {
            return found;
        }
        try (java.util.stream.Stream<Path> files = Files.walk(modules)) {
            for (Path file : (Iterable<Path>) files.filter(p -> p.toString().endsWith(".c"))::iterator) {
                for (String chunk : CheckoutTreeNarrower.splitFunctionChunks(
                        Files.readString(file, StandardCharsets.UTF_8))) {
                    String hex = CheckoutTreeNarrower.addressFromChunk(chunk);
                    if (hex != null && bodyMatches(chunk, any)) {
                        found.add(CheckoutTreeNarrower.normalizeHex(hex));
                    }
                }
            }
        }
        return found;
    }

    private static boolean bodyMatches(String chunk, Pattern names) {
        return names.matcher(BlockSplicer.bodyAfterLeadingComments(chunk)).find();
    }

    // -------------------------------------------------------------------------
    // Pure planning / placement (offline-tested)
    // -------------------------------------------------------------------------

    /**
     * Classify addresses into replace / insert / remove.
     *
     * <p>Full mode ({@code addresses == null}): set-diff plus ifp. Empty ifp is
     * UNKNOWN — never "unchanged" — so a 5-column pre-Stage-A tree is re-checked.
     * Targeted mode: every requested address is classified by presence alone;
     * ifp skip happens later at replace time only for full mode.
     */
    public static WorkPlan planWork(
            Map<String, CheckoutTreeNarrower.IndexEntry> indexByHex,
            Map<String, Function> programByHex,
            Set<String> addresses) {

        Set<String> replace = new LinkedHashSet<>();
        Set<String> insert = new LinkedHashSet<>();
        Set<String> remove = new LinkedHashSet<>();

        if (addresses == null) {
            Set<String> tree = indexByHex.keySet();
            Set<String> prog = programByHex.keySet();
            for (String hex : prog) {
                if (!tree.contains(hex)) {
                    insert.add(hex);
                } else {
                    replace.add(hex); // ifp filter applied at execute time
                }
            }
            for (String hex : tree) {
                if (!prog.contains(hex)) {
                    remove.add(hex);
                }
            }
        } else {
            for (String raw : addresses) {
                if (raw == null || raw.isBlank()) {
                    continue;
                }
                String hex = CheckoutTreeNarrower.normalizeHex(raw);
                boolean inTree = indexByHex.containsKey(hex);
                boolean inProg = programByHex.containsKey(hex);
                if (inTree && inProg) {
                    replace.add(hex);
                } else if (inProg) {
                    insert.add(hex);
                } else if (inTree) {
                    remove.add(hex);
                }
                // else: neither — ignore (hint about a non-function address)
            }
        }
        return new WorkPlan(replace, insert, remove);
    }

    /**
     * Whether a surviving address needs a decompile under full reconcile.
     * Empty/blank ifp ⇒ yes (unknown). Mismatch ⇒ yes. Match ⇒ no.
     */
    public static boolean needsRedecompile(String storedIfp, String liveIfp) {
        if (storedIfp == null || storedIfp.isBlank()) {
            return true;
        }
        return !storedIfp.equals(liveIfp);
    }

    /**
     * Pin first (same {@link ModuleOverrides#slugFor} the sweep consults), else
     * containment: the compartment whose address span covers the entry.
     */
    public static Placement place(
            Function func,
            Program program,
            Map<String, CheckoutTreeNarrower.IndexEntry> indexByHex) {
        Address entry = func.getEntryPoint();
        Optional<String> pinned = ModuleOverrides.slugFor(program, entry);
        if (pinned.isPresent()) {
            // Inherit confidence from an existing member of that slug when present;
            // a brand-new slug still records pinned/1.0 — the pin IS the evidence.
            double conf = 1.0;
            for (CheckoutTreeNarrower.IndexEntry row : indexByHex.values()) {
                if (pinned.get().equals(row.slug())) {
                    conf = 1.0;
                    break;
                }
            }
            return new Placement(pinned.get(), ModuleOverrides.METHOD, conf, true);
        }
        return placeByContainment(entry.toString(false), indexByHex);
    }

    /**
     * Compartment whose [min,max] entry span covers {@code addressHex}; on a
     * tie, the tightest span. Outside every span → nearest by distance.
     * Method {@link #METHOD_CONTAINMENT}, {@code evidence_backed=false}.
     */
    public static Placement placeByContainment(
            String addressHex, Map<String, CheckoutTreeNarrower.IndexEntry> indexByHex) {
        String want = CheckoutTreeNarrower.normalizeHex(addressHex);
        long addr = parseHexLong(want);

        Map<String, long[]> spans = new LinkedHashMap<>();
        Map<String, Integer> counts = new LinkedHashMap<>();
        for (CheckoutTreeNarrower.IndexEntry row : indexByHex.values()) {
            long a = parseHexLong(CheckoutTreeNarrower.normalizeHex(row.addressHex()));
            long[] span = spans.get(row.slug());
            if (span == null) {
                spans.put(row.slug(), new long[]{a, a});
                counts.put(row.slug(), 1);
            } else {
                span[0] = Math.min(span[0], a);
                span[1] = Math.max(span[1], a);
                counts.merge(row.slug(), 1, Integer::sum);
            }
        }

        String bestCover = null;
        long bestCoverWidth = Long.MAX_VALUE;
        for (Map.Entry<String, long[]> e : spans.entrySet()) {
            long min = e.getValue()[0];
            long max = e.getValue()[1];
            if (addr >= min && addr <= max) {
                long width = max - min;
                if (bestCover == null || width < bestCoverWidth) {
                    bestCover = e.getKey();
                    bestCoverWidth = width;
                }
            }
        }
        if (bestCover != null) {
            return new Placement(bestCover, METHOD_CONTAINMENT, 0.1, false);
        }

        String nearest = null;
        long bestDist = Long.MAX_VALUE;
        for (Map.Entry<String, long[]> e : spans.entrySet()) {
            long min = e.getValue()[0];
            long max = e.getValue()[1];
            long dist = addr < min ? min - addr : addr - max;
            if (dist < bestDist) {
                bestDist = dist;
                nearest = e.getKey();
            }
        }
        if (nearest != null) {
            return new Placement(nearest, METHOD_CONTAINMENT, 0.1, false);
        }
        // Empty tree — mint a band-shaped slug so insert still has a home.
        return new Placement("b000", METHOD_CONTAINMENT, 0.1, false);
    }

    /**
     * Insert {@code newBlock} into {@code fileBody} in address order.
     * Pure — offline tests pin the ordering.
     */
    public static String insertBlockInAddressOrder(String fileBody, String newBlock) {
        String want = CheckoutTreeNarrower.addressFromChunk(newBlock);
        if (want == null) {
            return (fileBody == null ? "" : fileBody) + ensureBlockSeparator(newBlock);
        }
        String wantNorm = CheckoutTreeNarrower.normalizeHex(want);
        List<String> chunks = CheckoutTreeNarrower.splitFunctionChunks(
                fileBody == null ? "" : fileBody);
        List<String> out = new ArrayList<>();
        boolean inserted = false;
        for (String chunk : chunks) {
            String addr = CheckoutTreeNarrower.addressFromChunk(chunk);
            if (!inserted && addr != null
                    && CheckoutTreeNarrower.normalizeHex(addr).compareTo(wantNorm) > 0) {
                out.add(trimTrailingExtraBlanks(newBlock));
                inserted = true;
            }
            out.add(chunk);
        }
        if (!inserted) {
            out.add(trimTrailingExtraBlanks(newBlock));
        }
        return joinChunks(out);
    }

    /**
     * Remove the block at {@code addressHex}. Returns empty string when the
     * file empties (caller deletes).
     */
    public static String removeBlockFromFile(String fileBody, String addressHex) {
        return CheckoutTreeNarrower.rewritePartitionFile(
                fileBody, Set.of(CheckoutTreeNarrower.normalizeHex(addressHex)));
    }

    /**
     * Split an over-budget file body into N file bodies under the same rules
     * as {@link SweepJob#assignBlocksToFiles}. Returns one body per file; the
     * caller names each after its first address.
     */
    public static List<String> splitFileBody(
            String fileBody, int maxFileBytes, int maxFunctionsPerFile) {
        List<String> chunks = CheckoutTreeNarrower.splitFunctionChunks(
                fileBody == null ? "" : fileBody);
        if (chunks.isEmpty()) {
            return List.of();
        }
        int[] sizes = new int[chunks.size()];
        for (int i = 0; i < chunks.size(); i++) {
            sizes[i] = SweepJob.encodedBlockBytes(chunks.get(i));
        }
        int[] assign = SweepJob.assignBlocksToFiles(
                sizes, maxFileBytes, maxFunctionsPerFile);
        int maxIdx = 0;
        for (int a : assign) {
            maxIdx = Math.max(maxIdx, a);
        }
        List<List<String>> buckets = new ArrayList<>(maxIdx + 1);
        for (int i = 0; i <= maxIdx; i++) {
            buckets.add(new ArrayList<>());
        }
        for (int i = 0; i < chunks.size(); i++) {
            buckets.get(assign[i]).add(chunks.get(i));
        }
        List<String> bodies = new ArrayList<>();
        for (List<String> bucket : buckets) {
            if (!bucket.isEmpty()) {
                bodies.add(joinChunks(bucket));
            }
        }
        return bodies;
    }

    /**
     * After a split, the relative path for file half {@code body} under
     * {@code slug}. Named for the first function's entry — same rule as the sweep.
     */
    public static String filePathForBody(String slug, String body, int pointerSize) {
        String addr = CheckoutTreeNarrower.addressFromChunk(
                CheckoutTreeNarrower.splitFunctionChunks(body).get(0));
        long offset = parseHexLong(CheckoutTreeNarrower.normalizeHex(addr));
        return CheckoutLayout.moduleFunctionFile(
                slug, CheckoutLayout.compartmentFileName(offset, pointerSize));
    }

    // -------------------------------------------------------------------------
    // Disk mutation helpers
    // -------------------------------------------------------------------------

    private static ReplaceOutcome replaceInTree(
            Checkout checkout,
            Map<String, CheckoutTreeNarrower.IndexEntry> working,
            String hex,
            CheckoutTreeNarrower.IndexEntry row,
            Function func,
            String newBlock) throws IOException {
        Path abs = checkout.root().path().resolve(row.file());
        if (!Files.isRegularFile(abs)) {
            return ReplaceOutcome.fail("file_missing:" + row.file());
        }
        String original = Files.readString(abs, StandardCharsets.UTF_8);
        Map<String, String> reps = Map.of(hex, newBlock);
        BlockSplicer.SpliceResult splice = BlockSplicer.spliceFile(original, reps);
        if (!splice.failed().isEmpty()) {
            return ReplaceOutcome.fail("block_not_found");
        }
        if (!splice.rewritten()) {
            // fp match — still refresh ifp so a future full pass stays cheap.
            working.put(hex, row.withIfp(InputFingerprint.of(func))
                    .withName(func.getName()));
            return ReplaceOutcome.skippedUnchanged();
        }
        checkout.root().writeFile(Path.of(row.file()), splice.newBody());
        String name = func.getName();
        working.put(hex, row.withIfp(InputFingerprint.of(func)).withName(name));
        return ReplaceOutcome.rewritten(1);
    }

    private static RemoveOutcome removeFromTree(
            Checkout checkout,
            Map<String, CheckoutTreeNarrower.IndexEntry> working,
            String hex,
            CheckoutTreeNarrower.IndexEntry row,
            int pointerSize) throws IOException {
        Path abs = checkout.root().path().resolve(row.file());
        int filesWritten = 0;
        int filesDeleted = 0;
        if (Files.isRegularFile(abs)) {
            String original = Files.readString(abs, StandardCharsets.UTF_8);
            String filtered = removeBlockFromFile(original, hex);
            if (filtered.isBlank()) {
                Files.deleteIfExists(abs);
                filesDeleted++;
            } else {
                // First address of the file may have changed — rename to match.
                String newPath = maybeRenameFileAfterFirstChanged(
                        checkout, row.slug(), row.file(), filtered, pointerSize);
                if (!newPath.equals(row.file())) {
                    for (Map.Entry<String, CheckoutTreeNarrower.IndexEntry> e :
                            new ArrayList<>(working.entrySet())) {
                        if (row.file().equals(e.getValue().file())
                                && !hex.equals(e.getKey())) {
                            working.put(e.getKey(), e.getValue().withFile(newPath));
                        }
                    }
                    Files.deleteIfExists(abs);
                }
                checkout.root().writeFile(Path.of(newPath), filtered);
                filesWritten++;
            }
        }
        working.remove(hex);
        return new RemoveOutcome(filesWritten, filesDeleted);
    }

    private static InsertOutcome insertIntoTree(
            Checkout checkout,
            Map<String, CheckoutTreeNarrower.IndexEntry> working,
            Function func,
            String newBlock,
            Placement placement,
            int pointerSize,
            int maxFileBytes) throws IOException {
        String hex = CheckoutTreeNarrower.normalizeHex(
                func.getEntryPoint().toString(false));
        String targetFile = chooseTargetFile(working, placement.slug(), hex, pointerSize);

        Path abs = checkout.root().path().resolve(targetFile);
        String original = Files.isRegularFile(abs)
                ? Files.readString(abs, StandardCharsets.UTF_8)
                : "";
        String withInsert = insertBlockInAddressOrder(original, newBlock);

        int filesWritten = 0;
        int filesSplit = 0;
        List<String> bodies = splitFileBody(
                withInsert, maxFileBytes, SweepJob.MAX_FUNCTIONS_PER_FILE);
        if (bodies.isEmpty()) {
            return InsertOutcome.fail("empty_after_insert");
        }

        // Delete the original target only when the first half got a new name,
        // or when we produced multiple halves (split).
        Set<String> writtenPaths = new LinkedHashSet<>();
        boolean split = bodies.size() > 1;
        if (split) {
            filesSplit++;
        }

        // Clear old file-path rows for every address that was in the target file.
        Set<String> affectedHex = new LinkedHashSet<>();
        affectedHex.add(hex);
        for (Map.Entry<String, CheckoutTreeNarrower.IndexEntry> e : working.entrySet()) {
            if (targetFile.equals(e.getValue().file())) {
                affectedHex.add(e.getKey());
            }
        }

        for (String body : bodies) {
            String path = filePathForBody(placement.slug(), body, pointerSize);
            checkout.root().writeFile(Path.of(path), body);
            writtenPaths.add(path);
            filesWritten++;
            for (String chunk : CheckoutTreeNarrower.splitFunctionChunks(body)) {
                String addr = CheckoutTreeNarrower.addressFromChunk(chunk);
                if (addr == null) {
                    continue;
                }
                String aHex = CheckoutTreeNarrower.normalizeHex(addr);
                String name = BlockSplicer.nameFromBlock(chunk);
                if (name == null) {
                    name = aHex;
                }
                boolean evidence = placement.evidenceBacked();
                String ifp = "";
                if (aHex.equals(hex)) {
                    ifp = InputFingerprint.of(func);
                    name = func.getName();
                    evidence = placement.evidenceBacked();
                } else {
                    CheckoutTreeNarrower.IndexEntry prior = working.get(aHex);
                    if (prior != null) {
                        ifp = prior.ifp() != null ? prior.ifp() : "";
                        evidence = prior.evidenceBacked();
                        name = prior.name();
                    }
                }
                working.put(aHex, new CheckoutTreeNarrower.IndexEntry(
                        addr, name, placement.slug(), path, evidence, ifp));
            }
        }

        if (!writtenPaths.contains(targetFile) && Files.isRegularFile(abs)) {
            Files.deleteIfExists(abs);
        }
        return InsertOutcome.ok(filesWritten, filesSplit);
    }

    /**
     * Prefer the file that already holds the address-predecessor (or successor)
     * inside {@code slug}; otherwise mint a new address-named file.
     */
    static String chooseTargetFile(
            Map<String, CheckoutTreeNarrower.IndexEntry> working,
            String slug,
            String newHex,
            int pointerSize) {
        TreeMap<String, String> addrToFile = new TreeMap<>();
        for (CheckoutTreeNarrower.IndexEntry row : working.values()) {
            if (slug.equals(row.slug())) {
                addrToFile.put(
                        CheckoutTreeNarrower.normalizeHex(row.addressHex()), row.file());
            }
        }
        if (addrToFile.isEmpty()) {
            long offset = parseHexLong(newHex);
            return CheckoutLayout.moduleFunctionFile(
                    slug, CheckoutLayout.compartmentFileName(offset, pointerSize));
        }
        String floor = addrToFile.floorKey(newHex);
        if (floor != null) {
            return addrToFile.get(floor);
        }
        return addrToFile.firstEntry().getValue();
    }

    private static String maybeRenameFileAfterFirstChanged(
            Checkout checkout, String slug, String oldRelative, String body, int pointerSize)
            throws IOException {
        String expected = filePathForBody(slug, body, pointerSize);
        if (expected.equals(oldRelative)) {
            return oldRelative;
        }
        return expected;
    }

    private static BlockSplicer.PartitionMeta partitionMetaForReplace(
            Checkout checkout, CheckoutTreeNarrower.IndexEntry row) throws IOException {
        Path abs = checkout.root().path().resolve(row.file());
        if (Files.isRegularFile(abs)) {
            String body = Files.readString(abs, StandardCharsets.UTF_8);
            String block = BlockSplicer.findBlock(body, row.addressHex());
            BlockSplicer.PartitionMeta meta = BlockSplicer.partitionMetaFromBlock(block);
            if (meta != null) {
                return meta;
            }
        }
        return new BlockSplicer.PartitionMeta(
                row.slug(), "address-band", 0.0, row.evidenceBacked());
    }

    private static int patchNeighbourHeaders(
            Checkout checkout,
            Program program,
            PartitionContext ctx,
            Map<String, CheckoutTreeNarrower.IndexEntry> working,
            Set<String> seeds,
            Accumulators acc) throws IOException {
        if (seeds.isEmpty()) {
            return 0;
        }
        Set<String> neighbours = BlockSplicer.neighbourAddresses(ctx, program, seeds);
        neighbours.removeAll(seeds);
        // Also drop addresses no longer in the tree.
        neighbours.removeIf(h -> !working.containsKey(h));

        Map<String, List<String>> byFile = new LinkedHashMap<>();
        for (String hex : neighbours) {
            CheckoutTreeNarrower.IndexEntry row = working.get(hex);
            if (row == null) {
                continue;
            }
            byFile.computeIfAbsent(row.file(), f -> new ArrayList<>()).add(hex);
        }

        int filesWritten = 0;
        for (Map.Entry<String, List<String>> fileEntry : byFile.entrySet()) {
            String relative = fileEntry.getKey();
            Path abs = checkout.root().path().resolve(relative);
            if (!Files.isRegularFile(abs)) {
                continue;
            }
            String body = Files.readString(abs, StandardCharsets.UTF_8);
            boolean any = false;
            for (String hex : fileEntry.getValue()) {
                String oldBlock = BlockSplicer.findBlock(body, hex);
                if (oldBlock == null) {
                    continue;
                }
                Function func = resolveFunction(program, hex);
                if (func == null) {
                    continue;
                }
                String[] now = FunctionBlock.neighbourValues(func);
                String callsVal = now[0];
                String callersVal = now[1];
                String[] existing = BlockSplicer.neighbourhoodValuesFromBlock(oldBlock);
                if (Objects.equals(callsVal, existing[0])
                        && Objects.equals(callersVal, existing[1])) {
                    continue;
                }
                String newBlock = BlockSplicer.patchNeighbourhoodLines(
                        oldBlock, callsVal, callersVal);
                String replaced = BlockSplicer.replaceBlock(body, hex, newBlock);
                if (replaced == null) {
                    continue;
                }
                body = replaced;
                any = true;
                acc.headerPatched.add(hex);
            }
            if (any) {
                checkout.root().writeFile(Path.of(relative), body);
                filesWritten++;
            }
        }
        return filesWritten;
    }

    private static Function resolveFunction(Program program, String hex) {
        var addr = ServiceUtils.parseAddress(program, hex);
        if (addr == null) {
            return null;
        }
        Function at = program.getFunctionManager().getFunctionAt(addr);
        if (at != null) {
            return at;
        }
        return program.getFunctionManager().getFunctionContaining(addr);
    }

    private static String joinChunks(List<String> chunks) {
        StringBuilder sb = new StringBuilder();
        for (String chunk : chunks) {
            sb.append(chunk);
            if (!chunk.endsWith("\n")) {
                sb.append('\n');
            }
            if (!chunk.endsWith("\n\n")) {
                sb.append('\n');
            }
        }
        return sb.toString();
    }

    private static String ensureBlockSeparator(String block) {
        String t = trimTrailingExtraBlanks(block);
        if (!t.endsWith("\n")) {
            t = t + "\n";
        }
        return t + "\n";
    }

    private static String trimTrailingExtraBlanks(String s) {
        if (s == null) {
            return "";
        }
        while (s.endsWith("\n\n")) {
            s = s.substring(0, s.length() - 1);
        }
        return s;
    }

    private static long parseHexLong(String hex) {
        if (hex == null || hex.isBlank()) {
            return 0L;
        }
        try {
            return Long.parseUnsignedLong(hex, 16);
        } catch (NumberFormatException e) {
            return 0L;
        }
    }

    // -------------------------------------------------------------------------
    // Result types
    // -------------------------------------------------------------------------

    public record WorkPlan(Set<String> replace, Set<String> insert, Set<String> remove) {
        public WorkPlan {
            replace = Set.copyOf(replace);
            insert = Set.copyOf(insert);
            remove = Set.copyOf(remove);
        }
    }

    public record Placement(
            String slug, String method, double confidence, boolean evidenceBacked) {}

    public record ReconcileResult(
            List<String> replaced,
            List<String> inserted,
            List<String> removed,
            List<String> headerPatched,
            List<String> unchanged,
            List<String> failed,
            List<String> failedReasons,
            int filesWritten,
            int filesSplit,
            int filesDeleted,
            int decompileCalls,
            long elapsedMs,
            int splicedSinceSweep) {

        public static ReconcileResult of(
                List<String> replaced,
                List<String> inserted,
                List<String> removed,
                List<String> headerPatched,
                List<String> unchanged,
                List<String> failed,
                List<String> failedReasons,
                int filesWritten,
                int filesSplit,
                int filesDeleted,
                int decompileCalls,
                long elapsedMs,
                int splicedSinceSweep) {
            return new ReconcileResult(
                    List.copyOf(replaced),
                    List.copyOf(inserted),
                    List.copyOf(removed),
                    List.copyOf(headerPatched),
                    List.copyOf(unchanged),
                    List.copyOf(failed),
                    List.copyOf(failedReasons),
                    filesWritten, filesSplit, filesDeleted,
                    decompileCalls, elapsedMs, splicedSinceSweep);
        }

        public Map<String, Object> toMap(String checkoutId, boolean busy, String phase) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("checkout_id", checkoutId);
            out.put("busy", busy);
            if (phase != null) {
                out.put("phase", phase);
            }
            out.put("replaced", replaced.size());
            out.put("inserted", inserted.size());
            out.put("removed", removed.size());
            out.put("header_patched", headerPatched.size());
            out.put("unchanged", unchanged.size());
            out.put("failed", failed.size());
            out.put("files_written", filesWritten);
            out.put("files_split", filesSplit);
            out.put("files_deleted", filesDeleted);
            out.put("decompile_calls", decompileCalls);
            out.put("elapsed_ms", elapsedMs);
            out.put("spliced_since_sweep", splicedSinceSweep);
            if (!failed.isEmpty()) {
                List<Map<String, String>> rows = new ArrayList<>();
                for (int i = 0; i < failed.size(); i++) {
                    Map<String, String> row = new LinkedHashMap<>();
                    row.put("address", failed.get(i));
                    row.put("reason",
                            i < failedReasons.size() ? failedReasons.get(i) : "failed");
                    rows.add(row);
                }
                out.put("failed_detail", rows);
            }
            return out;
        }
    }

    private static final class Accumulators {
        final List<String> replaced = new ArrayList<>();
        final List<String> inserted = new ArrayList<>();
        final List<String> removed = new ArrayList<>();
        final List<String> headerPatched = new ArrayList<>();
        final List<String> unchanged = new ArrayList<>();
        final List<String> failed = new ArrayList<>();
        final List<String> failedReasons = new ArrayList<>();
        int filesWritten;
        int filesSplit;
        int filesDeleted;
    }

    private record RemoveOutcome(int filesWritten, int filesDeleted) {}

    private record ReplaceOutcome(boolean ok, boolean skipped, int filesWritten, String reason) {
        static ReplaceOutcome rewritten(int files) {
            return new ReplaceOutcome(true, false, files, null);
        }

        static ReplaceOutcome skippedUnchanged() {
            return new ReplaceOutcome(true, true, 0, null);
        }

        static ReplaceOutcome fail(String reason) {
            return new ReplaceOutcome(false, false, 0, reason);
        }
    }

    private record InsertOutcome(boolean ok, int filesWritten, int filesSplit, String reason) {
        static InsertOutcome ok(int written, int split) {
            return new InsertOutcome(true, written, split, null);
        }

        static InsertOutcome fail(String reason) {
            return new InsertOutcome(false, 0, 0, reason);
        }
    }
}
