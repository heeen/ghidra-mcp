package com.xebyte.core.checkout;

import com.xebyte.core.ServiceUtils;
import com.xebyte.core.partition.Partition;
import com.xebyte.core.partition.PartitionCascade;
import com.xebyte.core.partition.PartitionContext;
import com.xebyte.core.partition.Partitioner;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.program.model.listing.Function;
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

    public boolean isCancelRequested() {
        return cancel.isCancelled();
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
            List<Partitioner> chain = PartitionCascade.buildChain(
                    cfg.bandSize(), cfg.enabledStrategies());
            if (chain.isEmpty()) {
                // Fall back to bands only — a mis-typed strategies list must not
                // leave the tree empty with no explanation.
                chain = PartitionCascade.buildChain(cfg.bandSize(), List.of("address-band"));
            }

            PartitionContext ctx = new PartitionContext(program);
            PartitionCascade.Result cascade = new PartitionCascade(chain).run(ctx);
            List<Partition> partitions = new ArrayList<>(cascade.partitions());
            partitions.sort(Comparator.comparing(p -> p.members().get(0).getEntryPoint()));

            int total = 0;
            for (Partition p : partitions) {
                total += p.size();
            }
            publish(checkout.progress()
                    .withPhase(SweepProgress.Phase.DECOMPILING)
                    .withCounts(total, 0, 0)
                    .withBytesWritten(0L), "dirty", null);

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

                String relativeFile = CheckoutLayout.moduleFunctionFile(
                        part.slug(), part.slug() + ".c");
                StringBuilder fileBody = new StringBuilder();

                for (Function func : members) {
                    if (cancel.isCancelled()) {
                        writePartialPartition(relativeFile, fileBody);
                        finishTerminal(SweepProgress.Phase.CANCELLED,
                                cancelReason != null ? cancelReason : "cancelled",
                                null);
                        return;
                    }
                    if (!ensureProgramOpen()) {
                        writePartialPartition(relativeFile, fileBody);
                        return;
                    }

                    if (functionsSinceAnalysisCheck >= ANALYSIS_POLL_EVERY) {
                        functionsSinceAnalysisCheck = 0;
                        if (!waitForAnalysisIfNeeded()) {
                            writePartialPartition(relativeFile, fileBody);
                            return;
                        }
                    }

                    boolean evidenceBacked = isEvidenceBacked(part, func, ctx);
                    FunctionEmit emit = decompileOne(func, part, evidenceBacked, sweptMod);
                    fileBody.append(emit.text());
                    if (!emit.text().endsWith("\n")) {
                        fileBody.append('\n');
                    }
                    fileBody.append('\n');

                    String addrHex = func.getEntryPoint().toString(false);
                    indexRows.add(new IndexRow(
                            addrHex,
                            func.getName(),
                            part.slug(),
                            relativeFile,
                            evidenceBacked));

                    accum.done++;
                    if (emit.failed()) {
                        accum.failed++;
                    }
                    accum.bytes += emit.text().getBytes(StandardCharsets.UTF_8).length;
                    functionsSinceAnalysisCheck++;

                    sliceStartNs = maybeThrottle(sliceStartNs, cfg.throttlePercent());
                }

                checkout.root().writeFile(Path.of(relativeFile), fileBody.toString());
                // bytes already counted per function into accum
                writeModuleReadme(part, relativeFile, members.size());
                publish(checkout.progress()
                        .withCounts(total, accum.done, accum.failed)
                        .withBytesWritten(accum.bytes)
                        .withCurrentPartition(part.slug())
                        .withRootRecreated(checkout.root().rootRecreated())
                        .withEtaSeconds(etaSeconds(accum.done, total,
                                checkout.progress().startedEpochMs())),
                        "dirty", null);
            }

            writeIndexes(indexRows, ctx, cascade, partitions, total);
            writeTopReadme(total, partitions.size());

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
     * Seven-line header. {@code uri} uses the same lowercase-hex
     * {@link ServiceUtils#addressToJson} emits so it resolves as an MCP resource.
     */
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
            String programName) {
        String uri = functionResourceUri(programName, addressHex);
        return ""
                + "// fn: " + functionName + " @ " + addressHex + " size=" + sizeBytes + "\n"
                + "// part: " + partitionSlug + " " + method
                + " conf=" + String.format(Locale.ROOT, "%.2f", confidence)
                + " evidence_backed=" + evidenceBacked + "\n"
                + "// fp: " + fingerprint + "\n"
                + "// dts: " + dts + "\n"
                + "// mod: " + modificationNumber + "\n"
                + "// uri: " + uri + "\n"
                + "// see: modules/" + partitionSlug + "/README.md\n";
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

    /** Columns: address, name, partition_slug, file, evidence_backed */
    public static String formatByAddressRow(
            String addressHex,
            String name,
            String partitionSlug,
            String file,
            boolean evidenceBacked) {
        return addressHex + "\t" + name + "\t" + partitionSlug + "\t"
                + file + "\t" + evidenceBacked + "\n";
    }

    public static String byAddressHeader() {
        return "address\tname\tpartition_slug\tfile\tevidence_backed\n";
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
            Function func, Partition part, boolean evidenceBacked, long modNumber) {
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
                program.getName());
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
        if (throttlePercent <= 0) {
            return sliceStartNs;
        }
        long heldMs = (System.nanoTime() - sliceStartNs) / 1_000_000L;
        if (heldMs < SLICE_MS) {
            return sliceStartNs;
        }
        // sleep = slice * throttle / (100 - throttle); 10% → ~28 ms per 250 ms slice
        // (~20 s added on ls). Releases ProgramDB so interactive GETs stay live.
        long sleepMs = Math.max(1L, (long) SLICE_MS * throttlePercent / (100 - throttlePercent));
        try {
            Thread.sleep(sleepMs);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            requestCancel("interrupted");
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

    private void writePartialPartition(String relativeFile, StringBuilder body) {
        if (body == null || body.isEmpty()) {
            return;
        }
        try {
            checkout.root().writeFile(Path.of(relativeFile), body.toString());
        } catch (IOException ignored) {
            // Cancel/close path — best effort so Grep still sees what finished.
        }
    }

    private void writeModuleReadme(Partition part, String sourceFile, int memberCount)
            throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("# Module ").append(part.slug()).append("\n\n");
        sb.append("method: ").append(part.method()).append('\n');
        sb.append("confidence: ")
                .append(String.format(Locale.ROOT, "%.2f", part.confidence())).append('\n');
        sb.append("functions: ").append(memberCount).append('\n');
        sb.append("source: ").append(sourceFile).append('\n');
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
            int total) throws IOException {

        StringBuilder byAddr = new StringBuilder(byAddressHeader());
        rows.sort(Comparator.comparing(IndexRow::addressHex));
        for (IndexRow row : rows) {
            byAddr.append(formatByAddressRow(
                    row.addressHex(), row.name(), row.slug(), row.file(), row.evidenceBacked()));
        }
        checkout.root().writeFile(Path.of(CheckoutLayout.byAddressTsv()), byAddr.toString());

        checkout.root().writeFile(
                Path.of(CheckoutLayout.callgraphTsv()),
                renderCallgraph(ctx));

        checkout.root().writeFile(
                Path.of(CheckoutLayout.modulesIndexMd()),
                renderModulesIndex(ctx, cascade, partitions, total));
    }

    private String renderCallgraph(PartitionContext ctx) {
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
            int total) {
        PartitionContext.LiteralIndex li = ctx.literals();
        int withStrings = li.functionsWithStrings();
        int eligible = ctx.size();
        double pct = eligible == 0 ? 0.0 : (100.0 * withStrings / eligible);

        StringBuilder sb = new StringBuilder();
        sb.append("# Modules\n\n");
        sb.append("eligible_functions: ").append(eligible).append('\n');
        sb.append("assigned_functions: ").append(cascade.assignedFunctions()).append('\n');
        sb.append("partitions: ").append(partitions.size()).append('\n');
        sb.append("functions_in_tree: ").append(total).append('\n');
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
        sb.append("| slug | method | functions | confidence |\n");
        sb.append("| --- | --- | ---: | ---: |\n");
        for (Partition p : partitions) {
            sb.append("| ").append(p.slug())
                    .append(" | ").append(p.method())
                    .append(" | ").append(p.size())
                    .append(" | ").append(String.format(Locale.ROOT, "%.2f", p.confidence()))
                    .append(" |\n");
        }
        return sb.toString();
    }

    private void writeTopReadme(int total, int partitionCount) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("# Decompilation checkout: ").append(checkout.programName()).append("\n\n");
        sb.append("checkout_id: ").append(checkout.id()).append('\n');
        sb.append("domain_path: ").append(checkout.domainPath()).append('\n');
        sb.append("functions: ").append(total).append('\n');
        sb.append("partitions: ").append(partitionCount).append('\n');
        sb.append("\n## How to read\n\n");
        sb.append("- `modules/index.md` — strategy log (including not-applicable reasons) "
                + "and compartment table\n");
        sb.append("- `modules/<slug>/*.c` — one file per partition; each function has a "
                + "7-line header with a resolvable `ghidra://function/...` uri\n");
        sb.append("- `index/by-address.tsv` — complete address → file map "
                + "(failed decompiles still appear)\n");
        sb.append("- `STATUS.md` — trustworthiness without talking to Ghidra\n");
        checkout.root().writeFile(Path.of(CheckoutLayout.readmeMd()), sb.toString());
    }

    private void publish(SweepProgress progress, String state, Long sweptAt) {
        // /checkout_stop may have already stamped CANCELLED; never let a mid-sweep
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
            // Progress is still in memory for /checkout_status; disk is best-effort
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
            boolean evidenceBacked) {}

    private static final class SweepAccum {
        int done;
        int failed;
        long bytes;
    }
}
