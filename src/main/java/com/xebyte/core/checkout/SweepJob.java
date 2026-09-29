package com.xebyte.core.checkout;

import com.xebyte.core.ServiceUtils;
import com.xebyte.core.WriteTx;
import com.xebyte.core.partition.Partition;
import com.xebyte.core.partition.PartitionCascade;
import com.xebyte.core.partition.PartitionContext;
import com.xebyte.core.partition.Partitioner;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Background sweep that materialises a partitioned decompilation tree.
 *
 * <p><b>Threading:</b> runs on {@link CheckoutRegistry}'s single daemon thread.
 * Never route through {@code ThreadingStrategy} — under Swing that freezes the
 * GUI for the whole sweep; under Direct it takes the global read lock and
 * serialises every other HTTP request. Same escape hatch
 * {@link com.xebyte.core.PartitionService} documents.
 *
 * <p><b>Decompiler:</b> one pooled {@link DecompInterface} for the entire sweep.
 * Measured: fresh interface per function = 238 ms ({@code openProgram} alone
 * 218 ms); already-open = 5.7–10 ms (~23×). {@code ParallelDecompiler} with 10
 * threads is 1.01× — ProgramDB-lock-bound — do not add threads.
 *
 * @since 7.2.0
 */
public final class SweepJob implements Runnable {

    /** Interactive yield quantum — release ProgramDB lock regularly. */
    public static final int SLICE_MS = 250;

    /** Re-check auto-analysis this often; {@code /reanalyze} can fire mid-sweep. */
    private static final int ANALYSIS_POLL_EVERY = 64;

    /**
     * Secondary per-file cap: a compartment of tiny stubs must not produce one
     * enormous-count file even when each stub is well under the byte budget.
     */
    public static final int MAX_FUNCTIONS_PER_FILE = 200;

    private static final String FAILED_MARKER_PREFIX = "// DECOMPILATION FAILED: ";

    private final Checkout checkout;
    private final Program program;

    private final CancelSignal cancel = new CancelSignal();
    private volatile DecompInterface decomp;
    private volatile String cancelReason;

    public SweepJob(Checkout checkout, Program program) {
        this.checkout = Objects.requireNonNull(checkout, "checkout");
        this.program = Objects.requireNonNull(program, "program");
    }

    public String checkoutId() {
        return checkout.id();
    }

    /**
     * Three cancel levers: the volatile flag (checked between functions), the
     * {@link TaskMonitor} whose {@code isCancelled()} returns it (so the C++
     * decompiler sees it), and {@link DecompInterface#stopProcess()} so stop
     * does not wait out {@code decompileTimeoutSeconds} on the in-flight call.
     */
    public void requestCancel(String reason) {
        cancelReason = reason != null ? reason : "cancelled";
        cancel.cancel();
        DecompInterface d = decomp;
        if (d != null) {
            try {
                d.stopProcess();
            } catch (Exception ignored) {
                // Best-effort — the flag still stops the outer loop.
            }
        }
    }

    /** Exposed for offline cancel plumbing tests. */
    TaskMonitor monitor() {
        return cancel.monitor();
    }

    @Override
    public void run() {
        // Queued jobs cancelled before they ever ran — honour without touching the program.
        if (cancel.isCancelled()) {
            finishTerminal(SweepProgress.Phase.CANCELLED,
                    cancelReason != null ? cancelReason : "cancelled before start",
                    null);
            return;
        }

        // Pin so the DB cannot close under us; still poll isClosed between
        // functions in case the user asked to close despite the consumer.
        // release(this) in finally — DomainObject has no removeConsumer.
        program.addConsumer(this);
        DecompInterface localDecomp = null;
        long sweptMod = program.getModificationNumber();
        try {
            publish(checkout.progress()
                    .withPhase(SweepProgress.Phase.QUEUED)
                    .withStartedEpochMs(System.currentTimeMillis())
                    .withRootRecreated(checkout.root().rootRecreated())
                    .withLastError(null), "dirty", null);

            if (!waitForAnalysisIfNeeded()) {
                return;
            }
            if (cancel.isCancelled() || !ensureProgramOpen()) {
                return;
            }

            publish(checkout.progress().withPhase(SweepProgress.Phase.PARTITIONING),
                    "dirty", null);

            CheckoutConfig cfg = checkout.config();
            if (cfg.disassembleMissing()) {
                DisassemblyPassResult disasm = disassembleMissingAtEntries(
                        program, cancel, cfg.throttlePercent(), SweepJob::disassembleAtEntry);
                publish(checkout.progress()
                        .withDisassemblyCounts(
                                disasm.disassembledOnDemand(), disasm.disassemblyFailed())
                        .withBodyReflowCounts(
                                disasm.bodiesRecomputed(), disasm.bodyRecomputeFailed()),
                        "dirty", null);
                if (cancel.isCancelled() || !ensureProgramOpen()) {
                    return;
                }
            }

            List<Partitioner> chain = PartitionCascade.buildChain(
                    cfg.bandSize(), cfg.enabledStrategies());
            if (chain.isEmpty()) {
                // Fall back to bands only — a mis-typed strategies list must not
                // leave the tree empty with no explanation.
                chain = PartitionCascade.buildChain(cfg.bandSize(), List.of("address-band"));
            }

            PartitionContext ctx = new PartitionContext(program);
            // Pins first — a claimed function is marked assigned so the cascade
            // (including the terminal address-band) never reclassifies it.
            List<Partition> pinned = ModuleOverrides.claimPinned(ctx);
            PartitionCascade.Result cascade = new PartitionCascade(chain).run(ctx);
            List<Partition> partitions = new ArrayList<>(pinned.size() + cascade.partitions().size());
            partitions.addAll(pinned);
            partitions.addAll(cascade.partitions());
            partitions.sort(Comparator.comparing(p -> p.members().get(0).getEntryPoint()));

            // Partition → PARTITION exclusions (need slugs) → TAG/RANGE + includeOnly
            // → decompile. One evaluator so /decompile_checkout_configure cannot disagree.
            ExclusionEvaluator evaluator = ExclusionEvaluator.of(program, cfg);
            ExclusionEvaluator.FilterResult filtered =
                    evaluator.filterPartitions(partitions, ctx.size());
            partitions = new ArrayList<>(filtered.partitions());
            ExclusionEvaluator.ScopeStats scope = filtered.stats();

            int total = scope.functionsInScope();
            publish(checkout.progress()
                    .withPhase(SweepProgress.Phase.DECOMPILING)
                    .withCounts(total, 0, 0)
                    .withBytesWritten(0L)
                    .withScope(scope.eligibleFunctions(), scope.functionsInScope(),
                            scope.removedByRule()),
                    "dirty", null);

            wipePriorTree();

            localDecomp = ServiceUtils.createConfiguredDecompiler(program, opts -> {
                // Same tune as FunctionBundleService: EOL comments under // so
                // Grep finds plate-adjacent notes. Not the shared default — that
                // feeds completeness scoring and fun-doc's comment stripper.
                opts.setEOLCommentIncluded(true);
                opts.setCommentStyle(DecompileOptions.CommentStyleEnum.CPPStyle);
            });
            decomp = localDecomp;

            SweepAccum accum = new SweepAccum();
            List<IndexRow> indexRows = new ArrayList<>(total);
            long sliceStartNs = System.nanoTime();
            int functionsSinceAnalysisCheck = 0;

            for (Partition part : partitions) {
                if (cancel.isCancelled() || !ensureProgramOpen()) {
                    return;
                }

                publish(checkout.progress()
                        .withPhase(SweepProgress.Phase.DECOMPILING)
                        .withCurrentPartition(part.slug())
                        .withCounts(total, accum.done, accum.failed)
                        .withBytesWritten(accum.bytes)
                        .withRootRecreated(checkout.root().rootRecreated())
                        .withEtaSeconds(etaSeconds(accum.done, total,
                                checkout.progress().startedEpochMs())),
                        "dirty", null);

                List<Function> members = new ArrayList<>(part.members());
                members.sort(Comparator.comparing(Function::getEntryPoint));

                // Compartment → N Read-budget files. Bytes (not function count)
                // decide the split: median C is ~386 B but max is 23 KB, so a
                // fixed count of 20 swings between ~8 KB and ~460 KB.
                int pointerSize = Math.max(1, program.getDefaultPointerSize());
                int maxFileBytes = cfg.maxFileBytes();
                StringBuilder fileBody = new StringBuilder();
                int fileBytes = 0;
                int fileFnCount = 0;
                String relativeFile = null;
                String fileFirstHex = null;
                String fileLastHex = null;
                List<EmittedFile> emitted = new ArrayList<>();

                for (Function func : members) {
                    if (cancel.isCancelled()) {
                        flushOpenFileBestEffort(relativeFile, fileBody, fileFirstHex, fileLastHex,
                                fileFnCount, emitted);
                        finishTerminal(SweepProgress.Phase.CANCELLED,
                                cancelReason != null ? cancelReason : "cancelled",
                                null);
                        return;
                    }
                    if (!ensureProgramOpen()) {
                        flushOpenFileBestEffort(relativeFile, fileBody, fileFirstHex, fileLastHex,
                                fileFnCount, emitted);
                        return;
                    }

                    if (functionsSinceAnalysisCheck >= ANALYSIS_POLL_EVERY) {
                        functionsSinceAnalysisCheck = 0;
                        if (!waitForAnalysisIfNeeded()) {
                            flushOpenFileBestEffort(relativeFile, fileBody, fileFirstHex,
                                    fileLastHex, fileFnCount, emitted);
                            return;
                        }
                    }

                    boolean evidenceBacked = isEvidenceBacked(part, func, ctx);
                    FunctionEmit emit = decompileOne(func, part, evidenceBacked, sweptMod, ctx);
                    int addition = encodedBlockBytes(emit.text());

                    // Close BEFORE adding so the budget is a hard Read ceiling;
                    // an empty file always accepts the next block (oversized
                    // single function → its own file, never split).
                    if (fileFnCount > 0
                            && (fileBytes + addition > maxFileBytes
                                || fileFnCount >= MAX_FUNCTIONS_PER_FILE)) {
                        flushOpenFile(relativeFile, fileBody, fileFirstHex, fileLastHex,
                                fileFnCount, emitted);
                        fileBody.setLength(0);
                        fileBytes = 0;
                        fileFnCount = 0;
                        relativeFile = null;
                        fileFirstHex = null;
                        fileLastHex = null;
                    }

                    if (relativeFile == null) {
                        relativeFile = CheckoutLayout.moduleFunctionFile(
                                part.slug(),
                                CheckoutLayout.compartmentFileName(
                                        func.getEntryPoint().getOffset(), pointerSize));
                    }

                    appendBlock(fileBody, emit.text());
                    fileBytes += addition;
                    fileFnCount++;

                    String addrHex = func.getEntryPoint().toString(false);
                    if (fileFirstHex == null) {
                        fileFirstHex = addrHex;
                    }
                    fileLastHex = addrHex;

                    indexRows.add(new IndexRow(
                            addrHex,
                            func.getName(),
                            part.slug(),
                            relativeFile,
                            evidenceBacked,
                            InputFingerprint.of(func)));

                    accum.done++;
                    if (emit.failed()) {
                        accum.failed++;
                    }
                    accum.bytes += emit.text().getBytes(StandardCharsets.UTF_8).length;
                    functionsSinceAnalysisCheck++;

                    sliceStartNs = maybeThrottle(sliceStartNs, cfg.throttlePercent());
                }

                flushOpenFile(relativeFile, fileBody, fileFirstHex, fileLastHex,
                        fileFnCount, emitted);
                writeModuleReadme(part, members.size(), emitted);
                publish(checkout.progress()
                        .withCounts(total, accum.done, accum.failed)
                        .withBytesWritten(accum.bytes)
                        .withCurrentPartition(part.slug())
                        .withRootRecreated(checkout.root().rootRecreated())
                        .withEtaSeconds(etaSeconds(accum.done, total,
                                checkout.progress().startedEpochMs())),
                        "dirty", null);
            }

            writeIndexes(indexRows, ctx, cascade, partitions, total, scope);
            writeTopReadme(total, partitions.size());
            writeAgentsMd(partitions);

            if (cancel.isCancelled()) {
                finishTerminal(SweepProgress.Phase.CANCELLED,
                        cancelReason != null ? cancelReason : "cancelled",
                        null);
                return;
            }

            sweptMod = program.getModificationNumber();
            finishTerminal(SweepProgress.Phase.COMPLETE, null, sweptMod);
        } catch (Exception e) {
            finishTerminal(SweepProgress.Phase.FAILED,
                    e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName(),
                    null);
        } finally {
            // Belt: no path may leave the sweep without a terminal phase. Several
            // early returns exit on cancel (the outer partition-loop check
            // short-circuits before ensureProgramOpen, and waitForAnalysisIfNeeded
            // ends with `return !cancel.isCancelled()`), and each one left STATUS.md
            // saying "dirty" — which reads as "a sweep died", not "someone stopped
            // it". Found by tests/integration/test_checkout.py, intermittently:
            // cancelling BETWEEN partitions took the bare-return path.
            SweepProgress.Phase reached = checkout.progress().phase();
            if (reached != SweepProgress.Phase.COMPLETE
                    && reached != SweepProgress.Phase.CANCELLED
                    && reached != SweepProgress.Phase.FAILED) {
                finishTerminal(
                        cancel.isCancelled()
                                ? SweepProgress.Phase.CANCELLED
                                : SweepProgress.Phase.FAILED,
                        cancel.isCancelled()
                                ? (cancelReason != null ? cancelReason : "cancelled")
                                : "sweep ended without reaching a terminal state",
                        null);
            }
            decomp = null;
            if (localDecomp != null) {
                try {
                    localDecomp.dispose();
                } catch (Exception ignored) {
                    // dispose must not mask the sweep outcome
                }
            }
            try {
                program.release(this);
            } catch (Exception ignored) {
                // program may already be closed
            }
            CheckoutRegistry.getInstance().clearActiveJob(checkout.id(), this);
        }
    }

    // -------------------------------------------------------------------------
    // Pure helpers (offline-tested)
    // -------------------------------------------------------------------------

    /**
     * Nine-line header. {@code uri} uses the same lowercase-hex
     * {@link ServiceUtils#addressToJson} emits so it resolves as an MCP resource.
     * {@code calls}/{@code callers} are always present (fixed shape for parsers);
     * empty callers note an entry/unreferenced function.
     */
    public static final int HEADER_LINES = 9;

    /** Cap names printed in the header; hubs dump the rest to callgraph.tsv. */
    public static final int NEIGHBOURHOOD_NAME_CAP = 8;

    public static String renderFunctionHeader(
            String functionName,
            String addressHex,
            long sizeBytes,
            String partitionSlug,
            String method,
            double confidence,
            boolean evidenceBacked,
            String fingerprint,
            Instant dts,
            long modificationNumber,
            String programName,
            List<String> calls,
            List<String> callers) {
        String uri = functionResourceUri(programName, addressHex);
        return ""
                + "// fn: " + functionName + " @ " + addressHex + " size=" + sizeBytes + "\n"
                + "// calls: " + formatNeighbourList(calls, false) + "\n"
                + "// callers: " + formatNeighbourList(callers, true) + "\n"
                + "// part: " + partitionSlug + " " + method
                + " conf=" + String.format(Locale.ROOT, "%.2f", confidence)
                + " evidence_backed=" + evidenceBacked + "\n"
                + "// fp: " + fingerprint + "\n"
                + "// dts: " + dts + "\n"
                + "// mod: " + modificationNumber + "\n"
                + "// uri: " + uri + "\n"
                + "// see: modules/" + partitionSlug + "/README.md\n";
    }

    /**
     * Names comma-separated; empty → {@code (none)} (or {@code (none — entry)}
     * for callers of an unreferenced function); hubs truncate at
     * {@link #NEIGHBOURHOOD_NAME_CAP}.
     */
    public static String formatNeighbourList(List<String> names, boolean entryWhenEmpty) {
        if (names == null || names.isEmpty()) {
            return entryWhenEmpty ? "(none — entry)" : "(none)";
        }
        if (names.size() <= NEIGHBOURHOOD_NAME_CAP) {
            return String.join(", ", names);
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < NEIGHBOURHOOD_NAME_CAP; i++) {
            if (i > 0) {
                sb.append(", ");
            }
            sb.append(names.get(i));
        }
        int more = names.size() - NEIGHBOURHOOD_NAME_CAP;
        sb.append(" +").append(more).append(" more, see callgraph.tsv");
        return sb.toString();
    }

    /**
     * Callee/caller names for one function, address-ordered via the context's
     * index (functions() is already address-sorted).
     */
    public static Neighbourhood neighbourhoodFor(Function func, PartitionContext ctx) {
        if (func == null || ctx == null) {
            return Neighbourhood.EMPTY;
        }
        Integer idx = ctx.indexOf(func.getEntryPoint());
        if (idx == null) {
            return Neighbourhood.EMPTY;
        }
        PartitionContext.CallGraph cg = ctx.callGraph();
        return new Neighbourhood(
                namesInAddressOrder(ctx, cg.callees().get(idx)),
                namesInAddressOrder(ctx, cg.callers().get(idx)));
    }

    static List<String> namesInAddressOrder(PartitionContext ctx, Set<Integer> indices) {
        if (indices == null || indices.isEmpty()) {
            return List.of();
        }
        List<Integer> sorted = new ArrayList<>(indices);
        sorted.sort(Integer::compareTo);
        List<Function> fns = ctx.functions();
        List<String> names = new ArrayList<>(sorted.size());
        for (int i : sorted) {
            if (i >= 0 && i < fns.size()) {
                names.add(fns.get(i).getName());
            }
        }
        return names;
    }

    /** Call neighbourhood rendered into the block header. */
    public record Neighbourhood(List<String> calls, List<String> callers) {
        public static final Neighbourhood EMPTY = new Neighbourhood(List.of(), List.of());

        public Neighbourhood {
            calls = calls == null ? List.of() : List.copyOf(calls);
            callers = callers == null ? List.of() : List.copyOf(callers);
        }
    }

    public static String renderFailedBody(String reason) {
        String safe = reason == null || reason.isBlank() ? "unknown" : reason.trim();
        return FAILED_MARKER_PREFIX + safe + "\n";
    }

    public static String functionResourceUri(String programName, String addressHex) {
        return "ghidra://function/"
                + encodeUriSegment(programName)
                + "/"
                + addressHex;
    }

    /**
     * Columns: address, name, partition_slug, file, evidence_backed, ifp.
     * {@code ifp} is the DB-cheap input fingerprint — not in the block header,
     * because the header is agent-read on every Read and must stay 9 lines.
     */
    public static String formatByAddressRow(
            String addressHex,
            String name,
            String partitionSlug,
            String file,
            boolean evidenceBacked,
            String ifp) {
        return addressHex + "\t" + name + "\t" + partitionSlug + "\t"
                + file + "\t" + evidenceBacked + "\t"
                + (ifp != null ? ifp : "") + "\n";
    }

    public static String byAddressHeader() {
        return "address\tname\tpartition_slug\tfile\tevidence_backed\tifp\n";
    }

    public static String shortContentHash(String content) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(content.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest, 0, 6); // 12 hex chars
        } catch (NoSuchAlgorithmException e) {
            return "000000000000";
        }
    }

    /**
     * Assign each block to a file index under a byte budget + function-count
     * cap. Pure so offline tests pin the split without a Program.
     *
     * <p>Close <em>before</em> adding when the next block would exceed the
     * budget or the open file already holds {@code maxFunctionsPerFile}
     * members. An oversized first block still opens a file alone — the block
     * is atomic for {@link BlockSplicer}.
     *
     * @param blockBytes           UTF-8 size of each encoded block (header+body
     *                             + the blank-line separator the writer adds)
     * @param maxFileBytes         Read budget (already clamped by config)
     * @param maxFunctionsPerFile  secondary cap (typically {@link #MAX_FUNCTIONS_PER_FILE})
     * @return parallel array of 0-based file indices, one per block
     */
    public static int[] assignBlocksToFiles(
            int[] blockBytes, int maxFileBytes, int maxFunctionsPerFile) {
        if (blockBytes == null || blockBytes.length == 0) {
            return new int[0];
        }
        int budget = Math.max(1, maxFileBytes);
        int fnCap = Math.max(1, maxFunctionsPerFile);
        int[] out = new int[blockBytes.length];
        int fileIdx = 0;
        int fileBytes = 0;
        int fileCount = 0;
        for (int i = 0; i < blockBytes.length; i++) {
            int addition = Math.max(0, blockBytes[i]);
            if (fileCount > 0
                    && (fileBytes + addition > budget || fileCount >= fnCap)) {
                fileIdx++;
                fileBytes = 0;
                fileCount = 0;
            }
            out[i] = fileIdx;
            fileBytes += addition;
            fileCount++;
        }
        return out;
    }

    /**
     * Bytes the sweep will write for one function block: body UTF-8, a trailing
     * newline if missing, then the blank-line separator between functions.
     */
    public static int encodedBlockBytes(String blockText) {
        if (blockText == null) {
            return 1; // just the separator newline
        }
        int n = blockText.getBytes(StandardCharsets.UTF_8).length;
        if (!blockText.endsWith("\n")) {
            n += 1;
        }
        return n + 1; // blank-line separator
    }

    /**
     * Percent-encode a URI path segment the way the bridge's
     * {@code quote(s, safe='')} does — every byte outside unreserved is escaped.
     */
    public static String encodeUriSegment(String raw) {
        if (raw == null || raw.isEmpty()) {
            return raw == null ? "" : raw;
        }
        StringBuilder out = new StringBuilder(raw.length() + 8);
        byte[] bytes = raw.getBytes(StandardCharsets.UTF_8);
        for (byte b : bytes) {
            int c = b & 0xff;
            if (isUnreserved(c)) {
                out.append((char) c);
            } else {
                out.append('%');
                out.append(Character.toUpperCase(Character.forDigit((c >> 4) & 0xf, 16)));
                out.append(Character.toUpperCase(Character.forDigit(c & 0xf, 16)));
            }
        }
        return out.toString();
    }

    private static boolean isUnreserved(int c) {
        return (c >= 'A' && c <= 'Z')
                || (c >= 'a' && c <= 'z')
                || (c >= '0' && c <= '9')
                || c == '-' || c == '.' || c == '_' || c == '~';
    }

    // -------------------------------------------------------------------------
    // Sweep internals
    // -------------------------------------------------------------------------

    private FunctionEmit decompileOne(
            Function func, Partition part, boolean evidenceBacked, long modNumber,
            PartitionContext ctx) {
        String addrHex = func.getEntryPoint().toString(false);
        long size = functionSize(func);
        String body;
        boolean failed;
        String failReason = null;

        try {
            DecompileResults results = decomp.decompileFunction(
                    func, checkout.config().decompileTimeoutSeconds(), cancel.monitor());
            if (results != null && results.decompileCompleted()
                    && results.getDecompiledFunction() != null
                    && results.getDecompiledFunction().getC() != null) {
                body = results.getDecompiledFunction().getC();
                failed = false;
            } else {
                failReason = results != null && results.getErrorMessage() != null
                        && !results.getErrorMessage().isBlank()
                        ? results.getErrorMessage().trim()
                        : "decompile did not complete";
                body = renderFailedBody(failReason);
                failed = true;
            }
        } catch (Exception e) {
            failReason = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            body = renderFailedBody(failReason);
            failed = true;
        }

        // Fingerprint the emitted body (code or FAILED marker), not the header —
        // so a header-only change does not look like a decompile drift.
        String fp = shortContentHash(body);
        Neighbourhood nb = neighbourhoodFor(func, ctx);
        String header = renderFunctionHeader(
                func.getName(),
                addrHex,
                size,
                part.slug(),
                part.method(),
                part.confidence(),
                evidenceBacked,
                fp,
                Instant.now(),
                modNumber,
                program.getName(),
                nb.calls(),
                nb.callers());
        return new FunctionEmit(header + body, failed);
    }

    private static long functionSize(Function func) {
        try {
            return func.getBody().getNumAddresses();
        } catch (Exception e) {
            return 0L;
        }
    }

    /**
     * Whether this member carried the partition's own signal, vs being swept in
     * by address containment (literal-locality interiors, qualified-name span
     * closure). Address bands never have structural evidence.
     */
    static boolean isEvidenceBacked(Partition part, Function func, PartitionContext ctx) {
        String method = part.method();
        // A pin IS the evidence — a human/agent stated the compartment.
        if (ModuleOverrides.METHOD.equals(method)) {
            return true;
        }
        if ("address-band".equals(method)) {
            return false;
        }
        Integer idx = ctx.indexOf(func.getEntryPoint());
        if (idx == null) {
            return false;
        }
        if ("literal-locality".equals(method)) {
            return ctx.literals().medianStringAddress()[idx] >= 0;
        }
        if ("qualified-name".equals(method)) {
            Object className = part.evidence().get("class_name");
            if (className == null) {
                return false;
            }
            String needle = className.toString();
            for (String s : ctx.literals().rawStrings().get(idx)) {
                if (s != null && s.contains(needle)) {
                    return true;
                }
            }
            return false;
        }
        // mmio-page (and any future signal-exact strategy): membership IS the evidence.
        return true;
    }

    private boolean waitForAnalysisIfNeeded() {
        AutoAnalysisManager mgr;
        try {
            mgr = AutoAnalysisManager.getAnalysisManager(program);
        } catch (Exception e) {
            return true; // no manager — nothing to wait for
        }
        if (mgr == null || !mgr.isAnalyzing()) {
            return true;
        }

        publish(checkout.progress().withPhase(SweepProgress.Phase.WAITING_FOR_ANALYSIS),
                "dirty", null);

        long deadline = System.nanoTime()
                + checkout.config().analysisWaitSeconds() * 1_000_000_000L;
        while (mgr.isAnalyzing()) {
            if (cancel.isCancelled()) {
                finishTerminal(SweepProgress.Phase.CANCELLED,
                        cancelReason != null ? cancelReason : "cancelled",
                        null);
                return false;
            }
            if (!ensureProgramOpen()) {
                return false;
            }
            if (System.nanoTime() > deadline) {
                // Cap reached — proceed anyway; a stuck analyzer must not block forever.
                break;
            }
            try {
                Thread.sleep(200L);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                requestCancel("interrupted");
                finishTerminal(SweepProgress.Phase.CANCELLED, "interrupted", null);
                return false;
            }
        }
        return !cancel.isCancelled();
    }

    private boolean ensureProgramOpen() {
        if (program.isClosed()) {
            requestCancel("program_closed");
            finishTerminal(SweepProgress.Phase.CANCELLED, "program_closed", null);
            return false;
        }
        return true;
    }

    private long maybeThrottle(long sliceStartNs, int throttlePercent) {
        return maybeThrottleSlice(sliceStartNs, throttlePercent, cancel);
    }

    /**
     * PE {@code .pdata} creates function entries without disassembly; partition
     * eligibility requires an instruction at the entry. Entry-only disassembly —
     * no auto-analysis, no new functions elsewhere.
     *
     * <p>Disassembly alone leaves the PE-loader body at one byte
     * ({@code body_start == body_end}). Every partitioner reads strings/scalars
     * out of the body, so that 1-byte body yields only address-band fallbacks.
     * After each successful entry disassembly we reflow the body via
     * {@link CreateFunctionCmd#getFunctionBody} + {@link Function#setBody} —
     * never {@code CreateFunctionCmd(..., recreate=true)}, which would discard
     * curated names/comments/signatures.
     */
    public static DisassemblyPassResult disassembleMissingAtEntries(
            Program program,
            CancelSignal cancel,
            int throttlePercent,
            EntryDisassembler disassembler) {
        return disassembleMissingAtEntries(
                program, cancel, throttlePercent, disassembler, SweepJob::defaultBodyComputer);
    }

    /**
     * Same as {@link #disassembleMissingAtEntries(Program, CancelSignal, int, EntryDisassembler)}
     * with an injectable body computer for offline tests.
     */
    public static DisassemblyPassResult disassembleMissingAtEntries(
            Program program,
            CancelSignal cancel,
            int throttlePercent,
            EntryDisassembler disassembler,
            BodyComputer bodyComputer) {
        int succeeded = 0;
        int failed = 0;
        int bodiesRecomputed = 0;
        int bodyRecomputeFailed = 0;
        long sliceStartNs = System.nanoTime();
        Listing listing = program.getListing();
        FunctionIterator it = program.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            if (cancel.isCancelled()) {
                break;
            }
            Function f = it.next();
            if (f.isExternal() || f.isThunk()) {
                continue;
            }
            Address entry = f.getEntryPoint();
            if (listing.getInstructionAt(entry) != null) {
                continue;
            }
            if (disassembler.disassemble(program, entry)) {
                succeeded++;
                BodyReflowOutcome bodyOutcome = recomputeBodyIfDegenerate(
                        program, f, cancel.monitor(), bodyComputer);
                if (bodyOutcome == BodyReflowOutcome.RECOMPUTED) {
                    bodiesRecomputed++;
                } else if (bodyOutcome == BodyReflowOutcome.FAILED) {
                    bodyRecomputeFailed++;
                }
            } else {
                failed++;
            }
            sliceStartNs = maybeThrottleSlice(sliceStartNs, throttlePercent, cancel);
        }
        return new DisassemblyPassResult(
                succeeded, failed, bodiesRecomputed, bodyRecomputeFailed);
    }

    /** Disassemble one known entry; package-visible for offline injection tests. */
    @FunctionalInterface
    public interface EntryDisassembler {
        boolean disassemble(Program program, Address entry);
    }

    /**
     * Computes a candidate body by following flow — creates nothing.
     * Injectable so offline tests do not need a live listing.
     */
    @FunctionalInterface
    public interface BodyComputer {
        AddressSetView compute(Program program, Address entry, TaskMonitor monitor);
    }

    public enum BodyReflowOutcome {
        SKIPPED,
        RECOMPUTED,
        FAILED
    }

    public record DisassemblyPassResult(
            int disassembledOnDemand,
            int disassemblyFailed,
            int bodiesRecomputed,
            int bodyRecomputeFailed) {
    }

    private static AddressSetView defaultBodyComputer(
            Program program, Address entry, TaskMonitor monitor) {
        return CreateFunctionCmd.getFunctionBody(monitor, program, entry);
    }

    /**
     * Reflow a PE-loader stub body after disassembly. Never shrinks a real body;
     * never recreates the function. Overlap with a neighbour is counted, not thrown.
     */
    public static BodyReflowOutcome recomputeBodyIfDegenerate(
            Program program,
            Function function,
            TaskMonitor monitor,
            BodyComputer bodyComputer) {
        AddressSetView current = function.getBody();
        // PE .pdata stubs are one address (start == end). A real body is larger —
        // leave it alone; curated extents must not be "fixed".
        if (current == null || current.getNumAddresses() > 1) {
            return BodyReflowOutcome.SKIPPED;
        }
        Address entry = function.getEntryPoint();
        AddressSetView body;
        try {
            body = bodyComputer.compute(program, entry, monitor);
        } catch (Exception e) {
            return BodyReflowOutcome.FAILED;
        }
        if (body == null || body.getNumAddresses() <= current.getNumAddresses()) {
            return BodyReflowOutcome.SKIPPED;
        }
        WriteTx tx = WriteTx.begin(program, "Checkout recompute function body");
        try {
            function.setBody(body);
            tx.end(true);
            return BodyReflowOutcome.RECOMPUTED;
        } catch (OverlappingFunctionException e) {
            // One bad neighbour must not abort the sweep — count and continue.
            tx.end(false);
            return BodyReflowOutcome.FAILED;
        } catch (Exception e) {
            tx.end(false);
            return BodyReflowOutcome.FAILED;
        }
    }

    private static boolean disassembleAtEntry(Program program, Address entry) {
        Listing listing = program.getListing();
        if (listing.getInstructionAt(entry) != null) {
            return true;
        }
        WriteTx tx = WriteTx.begin(program, "Checkout disassemble entry");
        try {
            AddressSet addrSet = new AddressSet(entry, entry);
            DisassembleCommand cmd = new DisassembleCommand(addrSet, null, true);
            // Follow flow from the entry only — do not pull in auto-analysis or
            // rename anything beyond what disassembly requires.
            cmd.setSeedContext(null);
            cmd.setInitialContext(null);
            cmd.enableCodeAnalysis(false);
            if (!cmd.applyTo(program, TaskMonitor.DUMMY)) {
                tx.end(false);
                return false;
            }
            tx.end(true);
            return listing.getInstructionAt(entry) != null;
        } catch (Exception e) {
            tx.end(false);
            return false;
        }
    }

    private static long maybeThrottleSlice(
            long sliceStartNs, int throttlePercent, CancelSignal cancel) {
        if (throttlePercent <= 0) {
            return sliceStartNs;
        }
        long heldMs = (System.nanoTime() - sliceStartNs) / 1_000_000L;
        if (heldMs < SLICE_MS) {
            return sliceStartNs;
        }
        long sleepMs = Math.max(1L, (long) SLICE_MS * throttlePercent / (100 - throttlePercent));
        try {
            Thread.sleep(sleepMs);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            cancel.cancel();
        }
        return System.nanoTime();
    }

    private void wipePriorTree() throws IOException {
        // Repartitioning moves compartment paths; leaving stale modules would
        // make Grep lie. Indexes are rebuilt from scratch too.
        deleteIfExists(checkout.root().path().resolve("modules"));
        deleteIfExists(checkout.root().path().resolve("index"));
        Path callgraph = checkout.root().path().resolve(CheckoutLayout.callgraphTsv());
        Files.deleteIfExists(callgraph);
        Path readme = checkout.root().path().resolve(CheckoutLayout.readmeMd());
        Files.deleteIfExists(readme);
    }

    private static void deleteIfExists(Path dir) throws IOException {
        if (!Files.exists(dir)) {
            return;
        }
        Files.walkFileTree(dir, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs)
                    throws IOException {
                Files.deleteIfExists(file);
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult postVisitDirectory(Path d, IOException exc) throws IOException {
                if (exc != null) {
                    throw exc;
                }
                Files.deleteIfExists(d);
                return FileVisitResult.CONTINUE;
            }
        });
    }

    private static void appendBlock(StringBuilder fileBody, String text) {
        if (text == null) {
            text = "";
        }
        fileBody.append(text);
        if (!text.endsWith("\n")) {
            fileBody.append('\n');
        }
        fileBody.append('\n');
    }

    private void flushOpenFile(
            String relativeFile,
            StringBuilder body,
            String firstHex,
            String lastHex,
            int fnCount,
            List<EmittedFile> emitted) throws IOException {
        if (relativeFile == null || body == null || body.isEmpty() || fnCount <= 0) {
            return;
        }
        checkout.root().writeFile(Path.of(relativeFile), body.toString());
        emitted.add(new EmittedFile(relativeFile, firstHex, lastHex, fnCount));
    }

    private void flushOpenFileBestEffort(
            String relativeFile,
            StringBuilder body,
            String firstHex,
            String lastHex,
            int fnCount,
            List<EmittedFile> emitted) {
        try {
            flushOpenFile(relativeFile, body, firstHex, lastHex, fnCount, emitted);
        } catch (IOException ignored) {
            // Cancel/close path — best effort so Grep still sees what finished.
        }
    }

    private void writeModuleReadme(Partition part, int memberCount, List<EmittedFile> files)
            throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("# Module ").append(part.slug()).append("\n\n");
        sb.append("method: ").append(part.method()).append('\n');
        sb.append("confidence: ")
                .append(String.format(Locale.ROOT, "%.2f", part.confidence())).append('\n');
        sb.append("functions: ").append(memberCount).append('\n');
        sb.append("files: ").append(files.size()).append('\n');
        // What the grouping asserts, in the reader's terms. Without this an
        // address-band compartment reads as a defect rather than as the expected
        // outcome for code that carries no signal.
        sb.append('\n').append(CheckoutGuidance.interpretation(part.method(), part.confidence()))
                .append('\n');
        sb.append("\n## Files\n\n");
        sb.append("| file | first | last | functions |\n");
        sb.append("| --- | --- | --- | ---: |\n");
        for (EmittedFile f : files) {
            sb.append("| ").append(f.relativePath())
                    .append(" | ").append(f.firstAddressHex())
                    .append(" | ").append(f.lastAddressHex())
                    .append(" | ").append(f.functionCount())
                    .append(" |\n");
        }
        sb.append("\n## Evidence\n\n");
        for (Map.Entry<String, Object> e : part.evidence().entrySet()) {
            sb.append("- ").append(e.getKey()).append(": ").append(e.getValue()).append('\n');
        }
        checkout.root().writeFile(Path.of(CheckoutLayout.moduleReadme(part.slug())), sb.toString());
    }

    private void writeIndexes(
            List<IndexRow> rows,
            PartitionContext ctx,
            PartitionCascade.Result cascade,
            List<Partition> partitions,
            int total,
            ExclusionEvaluator.ScopeStats scope) throws IOException {

        StringBuilder byAddr = new StringBuilder(byAddressHeader());
        rows.sort(Comparator.comparing(IndexRow::addressHex));
        for (IndexRow row : rows) {
            byAddr.append(formatByAddressRow(
                    row.addressHex(), row.name(), row.slug(), row.file(),
                    row.evidenceBacked(), row.ifp()));
        }
        checkout.root().writeFile(Path.of(CheckoutLayout.byAddressTsv()), byAddr.toString());

        checkout.root().writeFile(
                Path.of(CheckoutLayout.callgraphTsv()),
                renderCallgraphTsv(ctx));

        checkout.root().writeFile(
                Path.of(CheckoutLayout.modulesIndexMd()),
                renderModulesIndex(ctx, cascade, partitions, total, scope, rows));
    }

    /** Full callgraph TSV from a live context — shared by sweep and reconcile. */
    public static String renderCallgraphTsv(PartitionContext ctx) {
        StringBuilder sb = new StringBuilder("caller\tcallee\tcaller_name\tcallee_name\n");
        PartitionContext.CallGraph cg = ctx.callGraph();
        List<Function> fns = ctx.functions();
        for (int i = 0; i < fns.size(); i++) {
            Set<Integer> callees = cg.callees().get(i);
            if (callees == null || callees.isEmpty()) {
                continue;
            }
            String callerAddr = fns.get(i).getEntryPoint().toString(false);
            String callerName = fns.get(i).getName();
            List<Integer> sorted = new ArrayList<>(callees);
            sorted.sort(Integer::compareTo);
            for (int j : sorted) {
                sb.append(callerAddr).append('\t')
                        .append(fns.get(j).getEntryPoint().toString(false)).append('\t')
                        .append(callerName).append('\t')
                        .append(fns.get(j).getName()).append('\n');
            }
        }
        return sb.toString();
    }

    private String renderModulesIndex(
            PartitionContext ctx,
            PartitionCascade.Result cascade,
            List<Partition> partitions,
            int total,
            ExclusionEvaluator.ScopeStats scope,
            List<IndexRow> rows) {
        PartitionContext.LiteralIndex li = ctx.literals();
        int withStrings = li.functionsWithStrings();
        int eligible = scope.eligibleFunctions();
        int inScope = scope.functionsInScope();
        double pct = eligible == 0 ? 0.0 : (100.0 * withStrings / eligible);

        Map<String, Integer> filesPerSlug = countDistinctFilesPerSlug(rows);

        StringBuilder sb = new StringBuilder();
        sb.append("# Modules\n\n");
        sb.append("eligible_functions: ").append(eligible).append('\n');
        sb.append("functions_in_scope: ").append(inScope).append('\n');
        sb.append("assigned_functions: ").append(cascade.assignedFunctions()).append('\n');
        sb.append("partitions: ").append(partitions.size()).append('\n');
        sb.append("functions_in_tree: ").append(total).append('\n');
        if (!scope.removedByRule().isEmpty()) {
            sb.append('\n');
            sb.append("## Exclusions removed\n\n");
            for (Map.Entry<String, Integer> e : scope.removedByRule().entrySet()) {
                sb.append("- ").append(e.getKey()).append(": removed ")
                        .append(e.getValue()).append('\n');
            }
        }
        sb.append('\n');

        sb.append("## Coverage\n\n");
        sb.append(String.format(Locale.ROOT,
                "%d of %d eligible functions (%.1f%%) carry a referenced-string signal; "
                        + "the rest inherit their compartment by address containment.\n\n",
                withStrings, eligible, pct));
        // The caveat has to be about THIS binary. An earlier version restated one
        // specimen's numbers (1299/3230 = 40%) verbatim into every tree, which on a
        // 25k-function ELF whose real figure is 9.9% was simply a false claim — in
        // the one file whose whole purpose is to be honest about coverage.
        sb.append("Compartments are structural, not semantic: they are coherent but "
                + "unscored (no ground-truth comparison exists yet). A slug names no "
                + "meaning — read each compartment's README.md for the rule and evidence "
                + "that formed it, and treat a low evidence-backed count as a boundary "
                + "around a poorly-evidenced interior rather than a claim about its "
                + "contents.\n\n");

        sb.append("## Strategy log\n\n");
        for (Map.Entry<String, Object> e : cascade.strategyLog().entrySet()) {
            sb.append("### ").append(e.getKey()).append("\n\n");
            Object val = e.getValue();
            if (val instanceof Map<?, ?> m) {
                for (Map.Entry<?, ?> field : m.entrySet()) {
                    sb.append("- ").append(field.getKey()).append(": ")
                            .append(field.getValue()).append('\n');
                }
            } else {
                sb.append(val).append('\n');
            }
            sb.append('\n');
        }

        sb.append("## Compartments\n\n");
        sb.append("| slug | method | functions | files | confidence |\n");
        sb.append("| --- | --- | ---: | ---: | ---: |\n");
        for (Partition p : partitions) {
            sb.append("| ").append(p.slug())
                    .append(" | ").append(p.method())
                    .append(" | ").append(p.size())
                    .append(" | ").append(filesPerSlug.getOrDefault(p.slug(), 0))
                    .append(" | ").append(String.format(Locale.ROOT, "%.2f", p.confidence()))
                    .append(" |\n");
        }
        return sb.toString();
    }

    /** Distinct {@code .c} paths per compartment — what the Files column reports. */
    static Map<String, Integer> countDistinctFilesPerSlug(List<IndexRow> rows) {
        Map<String, Set<String>> sets = new java.util.LinkedHashMap<>();
        for (IndexRow row : rows) {
            sets.computeIfAbsent(row.slug(), s -> new java.util.LinkedHashSet<>())
                    .add(row.file());
        }
        Map<String, Integer> out = new java.util.LinkedHashMap<>();
        for (Map.Entry<String, Set<String>> e : sets.entrySet()) {
            out.put(e.getKey(), e.getValue().size());
        }
        return out;
    }

    private void writeTopReadme(int total, int partitionCount) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("# Decompilation checkout: ").append(checkout.programName()).append("\n\n");
        sb.append("checkout_id: ").append(checkout.id()).append('\n');
        sb.append("domain_path: ").append(checkout.domainPath()).append('\n');
        sb.append("functions: ").append(total).append('\n');
        sb.append("partitions: ").append(partitionCount).append('\n');
        sb.append("\n## How to read\n\n");
        sb.append("- `AGENTS.md` — **start here**: what this tree is, whether it is current, "
                + "and how to search it\n");
        sb.append("- `modules/index.md` — strategy log (including not-applicable reasons) "
                + "and compartment table\n");
                sb.append("- `modules/<slug>/*.c` — Read-budget files inside each compartment "
                + "(named by first-function address); each function has a 9-line header "
                + "with calls/callers and a resolvable `ghidra://function/...` uri\n");
        sb.append("- `index/by-address.tsv` — complete address → file map "
                + "(failed decompiles still appear); `ifp` column is a "
                + "DB-cheap input fingerprint for reconcile without re-decompiling\n");
        sb.append("- `STATUS.md` — trustworthiness without talking to Ghidra\n");
        checkout.root().writeFile(Path.of(CheckoutLayout.readmeMd()), sb.toString());
    }

    /**
     * The reading contract. Two of its caveats are conditional on this binary, so
     * a tree that cannot hit them does not carry the warning as noise.
     */
    private void writeAgentsMd(List<Partition> partitions) throws IOException {
        boolean hasPeripherals = partitions.stream()
                .anyMatch(p -> "mmio-page".equals(p.method()));
        checkout.root().writeFile(
                Path.of(CheckoutLayout.agentsMd()),
                CheckoutGuidance.agentsMd(
                        checkout.programName(),
                        checkout.id(),
                        checkout.root().path().toString(),
                        isStripped(),
                        hasPeripherals));
    }

    /**
     * True when almost every name is Ghidra's own, which makes name-based Grep
     * useless: measured, `ls` carries 12 real names across 25,231 functions.
     */
    private boolean isStripped() {
        int auto = 0;
        int total = 0;
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.isExternal() || f.isThunk()) {
                continue;
            }
            total++;
            String n = f.getName();
            if (n.startsWith("FUN_") || n.startsWith("SUB_")) {
                auto++;
            }
        }
        return total > 0 && auto / (double) total >= 0.9;
    }

    private void publish(SweepProgress progress, String state, Long sweptAt) {
        // decompile_checkout_run(action=stop) may have already stamped CANCELLED; never let a mid-sweep
        // DECOMPILING publish clobber that — the agent is polling for cancel.
        if (cancel.isCancelled()) {
            SweepProgress.Phase p = progress.phase();
            if (p != SweepProgress.Phase.CANCELLED
                    && p != SweepProgress.Phase.FAILED
                    && p != SweepProgress.Phase.COMPLETE) {
                progress = progress
                        .withPhase(SweepProgress.Phase.CANCELLED)
                        .withLastError(cancelReason != null ? cancelReason : "cancelled");
                state = "cancelled";
            }
        }
        checkout.setProgress(progress);
        try {
            CheckoutStatusMd.write(checkout, state, sweptAt);
        } catch (IOException e) {
            // Progress is still in memory for /decompile_checkout_status; disk is best-effort
            // mid-sweep (root may be recreating).
        }
    }

    private void finishTerminal(SweepProgress.Phase phase, String error, Long sweptAt) {
        if (cancel.isCancelled() && phase == SweepProgress.Phase.COMPLETE) {
            phase = SweepProgress.Phase.CANCELLED;
            error = cancelReason != null ? cancelReason : "cancelled";
            sweptAt = null;
        }
        SweepProgress.Phase current = checkout.progress().phase();
        // Don't clobber an already-published cancel with a later failure from finally.
        if (current == SweepProgress.Phase.CANCELLED
                && phase != SweepProgress.Phase.CANCELLED) {
            return;
        }
        SweepProgress next = checkout.progress()
                .withPhase(phase)
                .withLastError(error)
                .withCurrentPartition(null)
                .withEtaSeconds(null)
                .withRootRecreated(checkout.root().rootRecreated());
        // A fresh sweep is the new ground truth — splice drift starts at zero.
        if (phase == SweepProgress.Phase.COMPLETE) {
            next = next.withSplicedSinceSweep(0);
        }
        String state = CheckoutStatusMd.stateForPhase(phase);
        publish(next, state, sweptAt);
    }

    private static Long etaSeconds(int done, int total, long startedEpochMs) {
        if (done <= 0 || total <= done || startedEpochMs <= 0) {
            return null;
        }
        long elapsed = System.currentTimeMillis() - startedEpochMs;
        if (elapsed <= 0) {
            return null;
        }
        double perFn = elapsed / (double) done;
        return Math.max(0L, Math.round(perFn * (total - done) / 1000.0));
    }

    // -------------------------------------------------------------------------
    // Nested types
    // -------------------------------------------------------------------------

    /**
     * Cancel flag + TaskMonitor whose {@code isCancelled()} returns the same
     * flag, so the native decompiler aborts without waiting out the timeout.
     */
    public static final class CancelSignal {
        private final SweepMonitor monitor = new SweepMonitor();

        public void cancel() {
            monitor.cancel();
        }

        public boolean isCancelled() {
            return monitor.isCancelled();
        }

        public TaskMonitor monitor() {
            return monitor;
        }
    }

    private static final class SweepMonitor extends TaskMonitorAdapter {
        SweepMonitor() {
            super(true);
        }
    }

    private record FunctionEmit(String text, boolean failed) {}

    private record IndexRow(
            String addressHex,
            String name,
            String slug,
            String file,
            boolean evidenceBacked,
            String ifp) {}

    /** One Read-budget {@code .c} flushed during a compartment sweep. */
    private record EmittedFile(
            String relativePath,
            String firstAddressHex,
            String lastAddressHex,
            int functionCount) {}

    private static final class SweepAccum {
        int done;
        int failed;
        long bytes;
    }
}
