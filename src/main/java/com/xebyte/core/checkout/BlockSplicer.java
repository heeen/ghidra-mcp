package com.xebyte.core.checkout;

import com.xebyte.core.ServiceUtils;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Splice refreshed decompilations into existing checkout partition files.
 *
 * <p>One compartment is one file (measured: 904 functions / 1.95 MB). Rewriting
 * a caller's file by re-decompiling every member costs ~7 s; splicing one block
 * costs ~8 ms. Never re-decompile a whole partition to refresh one function.
 *
 * <p>Block boundaries reuse {@link CheckoutTreeNarrower#splitFunctionChunks}: a
 * block starts only at a line beginning with {@code // fn: }, so a string
 * literal containing that text cannot open a false block.
 *
 * @since 7.2.0
 */
public final class BlockSplicer {

    private static final Pattern FP_LINE = Pattern.compile("^// fp:\\s*([0-9a-fA-F]+)\\s*$");
    private static final Pattern PART_LINE = Pattern.compile(
            "^// part: (\\S+) (\\S+) conf=([0-9.]+) evidence_backed=(true|false)\\s*$");
    private static final String FAILED_MARKER_PREFIX = "// DECOMPILATION FAILED: ";

    private BlockSplicer() {
    }

    // -------------------------------------------------------------------------
    // Pure helpers (offline-tested)
    // -------------------------------------------------------------------------

    /**
     * Locate the chunk whose header address matches {@code addressHex}.
     * Returns null when no line-start {@code // fn: … @ <addr>} matches —
     * callers must fail that address rather than guess an offset.
     */
    public static String findBlock(String fileBody, String addressHex) {
        String want = CheckoutTreeNarrower.normalizeHex(addressHex);
        if (want.isEmpty() || fileBody == null) {
            return null;
        }
        for (String chunk : CheckoutTreeNarrower.splitFunctionChunks(fileBody)) {
            String addr = CheckoutTreeNarrower.addressFromChunk(chunk);
            if (addr != null && want.equals(CheckoutTreeNarrower.normalizeHex(addr))) {
                return chunk;
            }
        }
        return null;
    }

    /** Fingerprint from the {@code // fp:} header line, or null if missing. */
    public static String fingerprintFromBlock(String block) {
        if (block == null) {
            return null;
        }
        for (String line : block.split("\n", -1)) {
            Matcher m = FP_LINE.matcher(line);
            if (m.matches()) {
                return m.group(1).toLowerCase(Locale.ROOT);
            }
        }
        return null;
    }

    /**
     * Body after the seven-line header — what {@link SweepJob#shortContentHash}
     * fingerprints. Missing header ⇒ whole block (defensive).
     */
    public static String bodyAfterHeader(String block) {
        if (block == null) {
            return "";
        }
        String[] lines = block.split("\n", -1);
        int consumed = 0;
        int idx = 0;
        // Header is exactly seven // lines; stop early if a non-comment appears.
        while (idx < lines.length && consumed < 7 && lines[idx].startsWith("// ")) {
            idx++;
            consumed++;
        }
        if (consumed < 7) {
            return block;
        }
        StringBuilder sb = new StringBuilder();
        for (; idx < lines.length; idx++) {
            if (sb.length() > 0 || !lines[idx].isEmpty() || idx + 1 < lines.length) {
                if (sb.length() > 0) {
                    sb.append('\n');
                }
                sb.append(lines[idx]);
            }
        }
        // Preserve a trailing newline when the original block had one after the header.
        if (block.endsWith("\n") && (sb.length() == 0 || !sb.toString().endsWith("\n"))) {
            // body may be empty for a header-only chunk
        }
        return sb.toString();
    }

    public static PartitionMeta partitionMetaFromBlock(String block) {
        if (block == null) {
            return null;
        }
        for (String line : block.split("\n", -1)) {
            Matcher m = PART_LINE.matcher(line);
            if (m.matches()) {
                double conf;
                try {
                    conf = Double.parseDouble(m.group(3));
                } catch (NumberFormatException e) {
                    conf = 0.0;
                }
                return new PartitionMeta(
                        m.group(1), m.group(2), conf, Boolean.parseBoolean(m.group(4)));
            }
        }
        return null;
    }

    /**
     * Replace located blocks in {@code fileBody}. Addresses whose blocks cannot
     * be found are listed in {@link SpliceResult#failed()}; the file text is
     * only rewritten when at least one block actually changes.
     *
     * <p>Unchanged fingerprints are counted and omitted from the write — an
     * over-broad caller set must be cheap.
     */
    public static SpliceResult spliceFile(
            String fileBody, Map<String, String> addressToNewBlock) {
        Objects.requireNonNull(addressToNewBlock, "addressToNewBlock");
        if (fileBody == null) {
            fileBody = "";
        }

        List<String> chunks = CheckoutTreeNarrower.splitFunctionChunks(fileBody);
        Map<String, Integer> indexByAddr = new LinkedHashMap<>();
        for (int i = 0; i < chunks.size(); i++) {
            String addr = CheckoutTreeNarrower.addressFromChunk(chunks.get(i));
            if (addr != null) {
                indexByAddr.put(CheckoutTreeNarrower.normalizeHex(addr), i);
            }
        }

        List<String> failed = new ArrayList<>();
        List<String> unchanged = new ArrayList<>();
        List<String> refreshed = new ArrayList<>();
        Map<String, String> nameUpdates = new LinkedHashMap<>();
        boolean anyChange = false;
        List<String> outChunks = new ArrayList<>(chunks);

        for (Map.Entry<String, String> e : addressToNewBlock.entrySet()) {
            String want = CheckoutTreeNarrower.normalizeHex(e.getKey());
            Integer idx = indexByAddr.get(want);
            if (idx == null) {
                failed.add(want);
                continue;
            }
            String oldBlock = outChunks.get(idx);
            String newBlock = e.getValue();
            String oldFp = fingerprintFromBlock(oldBlock);
            String newFp = fingerprintFromBlock(newBlock);
            if (oldFp != null && oldFp.equals(newFp)) {
                unchanged.add(want);
                continue;
            }
            outChunks.set(idx, trimTrailingExtraBlanks(newBlock));
            anyChange = true;
            refreshed.add(want);
            String newName = nameFromBlock(newBlock);
            String oldName = nameFromBlock(oldBlock);
            if (newName != null && (oldName == null || !oldName.equals(newName))) {
                nameUpdates.put(want, newName);
            }
        }

        if (!anyChange) {
            return new SpliceResult(fileBody, false, refreshed, unchanged, failed, nameUpdates);
        }

        StringBuilder sb = new StringBuilder();
        for (String chunk : outChunks) {
            sb.append(chunk);
            if (!chunk.endsWith("\n")) {
                sb.append('\n');
            }
            if (!chunk.endsWith("\n\n")) {
                sb.append('\n');
            }
        }
        return new SpliceResult(sb.toString(), true, refreshed, unchanged, failed, nameUpdates);
    }

    /** First {@code // fn: <name> @ …} name token, or null. */
    public static String nameFromBlock(String block) {
        if (block == null) {
            return null;
        }
        int nl = block.indexOf('\n');
        String first = nl < 0 ? block : block.substring(0, nl);
        if (!first.startsWith("// fn: ")) {
            return null;
        }
        String rest = first.substring("// fn: ".length());
        int at = rest.lastIndexOf(" @ ");
        if (at <= 0) {
            return null;
        }
        return rest.substring(0, at).trim();
    }

    /**
     * Update the name column in {@code by-address.tsv} text for addresses in
     * {@code nameByAddress}. Pure — offline tests pin the column rewrite.
     */
    public static String updateIndexNames(String indexTsv, Map<String, String> nameByAddress) {
        if (indexTsv == null || nameByAddress == null || nameByAddress.isEmpty()) {
            return indexTsv == null ? "" : indexTsv;
        }
        Map<String, String> want = new LinkedHashMap<>();
        for (Map.Entry<String, String> e : nameByAddress.entrySet()) {
            want.put(CheckoutTreeNarrower.normalizeHex(e.getKey()), e.getValue());
        }
        StringBuilder out = new StringBuilder();
        for (String line : indexTsv.split("\n", -1)) {
            if (line.isEmpty() && out.length() == 0) {
                continue;
            }
            if (line.isBlank() || line.startsWith("address\t")) {
                out.append(line).append('\n');
                continue;
            }
            String[] cols = line.split("\t", -1);
            if (cols.length < 2) {
                out.append(line).append('\n');
                continue;
            }
            String hex = CheckoutTreeNarrower.normalizeHex(cols[0]);
            String newName = want.get(hex);
            if (newName != null) {
                cols[1] = newName;
                out.append(String.join("\t", cols)).append('\n');
            } else {
                out.append(line).append('\n');
            }
        }
        // split(-1) yields a trailing empty element when the file ends with \n;
        // avoid doubling the final newline.
        String result = out.toString();
        if (indexTsv.endsWith("\n") && !result.endsWith("\n")) {
            return result + "\n";
        }
        if (!indexTsv.endsWith("\n") && result.endsWith("\n")) {
            return result.substring(0, result.length() - 1);
        }
        return result;
    }

    // -------------------------------------------------------------------------
    // Orchestration (Program + disk)
    // -------------------------------------------------------------------------

    /**
     * Refresh the given entry addresses in an existing checkout tree.
     * Never routes through {@code ThreadingStrategy} (same rule as
     * {@link SweepJob}).
     */
    public static RefreshResult refresh(
            Checkout checkout, Program program, List<String> addresses) throws IOException {
        Objects.requireNonNull(checkout, "checkout");
        Objects.requireNonNull(program, "program");
        long started = System.currentTimeMillis();

        List<String> skipped = new ArrayList<>();
        List<String> skippedReasons = new ArrayList<>();
        List<String> failed = new ArrayList<>();
        List<String> failedReasons = new ArrayList<>();
        List<String> refreshed = new ArrayList<>();
        List<String> unchanged = new ArrayList<>();
        Map<String, String> nameUpdates = new LinkedHashMap<>();
        int filesRewritten = 0;

        Path indexPath = checkout.root().path().resolve(CheckoutLayout.byAddressTsv());
        Map<String, IndexRow> index = loadIndex(indexPath);

        // Group in-tree addresses by relative file.
        Map<String, List<String>> byFile = new LinkedHashMap<>();
        for (String raw : addresses) {
            if (raw == null || raw.isBlank()) {
                continue;
            }
            String hex = CheckoutTreeNarrower.normalizeHex(raw);
            IndexRow row = index.get(hex);
            if (row == null) {
                skipped.add(hex);
                skippedReasons.add("not_in_tree");
                continue;
            }
            byFile.computeIfAbsent(row.file(), f -> new ArrayList<>()).add(hex);
        }

        if (byFile.isEmpty()) {
            return RefreshResult.of(
                    refreshed, unchanged, skipped, skippedReasons, failed, failedReasons,
                    0, System.currentTimeMillis() - started, false);
        }

        // Dirty before work — a crash mid-refresh must leave STATUS saying dirty.
        checkout.setProgress(checkout.progress().withLastError(null));
        CheckoutStatusMd.write(checkout, "dirty", null);

        DecompInterface decomp = null;
        try {
            decomp = ServiceUtils.createConfiguredDecompiler(program, opts -> {
                // Must match SweepJob: otherwise refreshed blocks render comments
                // differently from swept ones and Grep/fp drift on every plate edit.
                opts.setEOLCommentIncluded(true);
                opts.setCommentStyle(DecompileOptions.CommentStyleEnum.CPPStyle);
            });

            long mod = program.getModificationNumber();
            int timeout = checkout.config().decompileTimeoutSeconds();

            for (Map.Entry<String, List<String>> fileEntry : byFile.entrySet()) {
                String relative = fileEntry.getKey();
                Path abs = checkout.root().path().resolve(relative);
                if (!Files.isRegularFile(abs)) {
                    for (String hex : fileEntry.getValue()) {
                        failed.add(hex);
                        failedReasons.add("file_missing:" + relative);
                    }
                    continue;
                }
                String original = Files.readString(abs, StandardCharsets.UTF_8);
                Map<String, String> replacements = new LinkedHashMap<>();

                for (String hex : fileEntry.getValue()) {
                    String oldBlock = findBlock(original, hex);
                    if (oldBlock == null) {
                        failed.add(hex);
                        failedReasons.add("block_not_found");
                        continue;
                    }
                    Function func = resolveFunction(program, hex);
                    if (func == null) {
                        failed.add(hex);
                        failedReasons.add("function_not_found");
                        continue;
                    }
                    PartitionMeta part = partitionMetaFromBlock(oldBlock);
                    if (part == null) {
                        // Fall back so a slightly drifted header still refreshes.
                        IndexRow row = index.get(hex);
                        part = new PartitionMeta(
                                row != null ? row.slug() : "unknown",
                                "address-band",
                                0.0,
                                row != null && row.evidenceBacked());
                    }
                    String newBlock = decompileBlock(
                            decomp, func, part, mod, timeout, program.getName());
                    replacements.put(hex, newBlock);
                }

                if (replacements.isEmpty()) {
                    continue;
                }

                SpliceResult splice = spliceFile(original, replacements);
                failed.addAll(splice.failed());
                for (String f : splice.failed()) {
                    failedReasons.add("block_not_found");
                }
                unchanged.addAll(splice.unchanged());
                refreshed.addAll(splice.refreshed());
                nameUpdates.putAll(splice.nameUpdates());

                if (splice.rewritten()) {
                    checkout.root().writeFile(Path.of(relative), splice.newBody());
                    filesRewritten++;
                }
            }
        } finally {
            if (decomp != null) {
                try {
                    decomp.dispose();
                } catch (Exception ignored) {
                    // must not mask refresh outcome
                }
            }
        }

        if (!nameUpdates.isEmpty() && Files.isRegularFile(indexPath)) {
            String indexText = Files.readString(indexPath, StandardCharsets.UTF_8);
            String updated = updateIndexNames(indexText, nameUpdates);
            if (!updated.equals(indexText)) {
                checkout.root().writeFile(Path.of(CheckoutLayout.byAddressTsv()), updated);
            }
        }

        // Clean after — same ordering rule as the sweep.
        checkout.setProgress(checkout.progress().withLastError(null));
        String state = CheckoutStatusMd.stateForPhase(checkout.progress().phase());
        if ("dirty".equals(state) || "empty".equals(state)) {
            // COMPLETE → clean; STALE stays dirty on disk by design, but a
            // successful splice still bumps the revision so the poller fires.
            state = checkout.progress().phase() == SweepProgress.Phase.COMPLETE
                    ? "clean" : state;
        }
        if (checkout.progress().phase() == SweepProgress.Phase.COMPLETE
                || checkout.progress().phase() == SweepProgress.Phase.IDLE) {
            CheckoutStatusMd.write(checkout, "clean", null);
        } else if (checkout.progress().phase() == SweepProgress.Phase.STALE) {
            CheckoutStatusMd.write(checkout, "dirty", null);
        } else {
            CheckoutStatusMd.write(checkout, state, null);
        }

        return RefreshResult.of(
                refreshed, unchanged, skipped, skippedReasons, failed, failedReasons,
                filesRewritten, System.currentTimeMillis() - started, false);
    }

    /** Mark the checkout STALE without splicing — UNBOUNDED writes are not a refresh. */
    public static RefreshResult markStale(Checkout checkout) throws IOException {
        long started = System.currentTimeMillis();
        checkout.setProgress(checkout.progress()
                .withPhase(SweepProgress.Phase.STALE)
                .withLastError("program changed unboundedly; resweep needed"));
        CheckoutStatusMd.write(checkout, "dirty", null);
        return RefreshResult.of(
                List.of(), List.of(), List.of(), List.of(), List.of(), List.of(),
                0, System.currentTimeMillis() - started, true);
    }

    private static String decompileBlock(
            DecompInterface decomp,
            Function func,
            PartitionMeta part,
            long modNumber,
            int timeoutSeconds,
            String programName) {
        String addrHex = func.getEntryPoint().toString(false);
        long size = functionSize(func);
        String body;
        try {
            DecompileResults results = decomp.decompileFunction(
                    func, timeoutSeconds, TaskMonitor.DUMMY);
            if (results != null && results.decompileCompleted()
                    && results.getDecompiledFunction() != null
                    && results.getDecompiledFunction().getC() != null) {
                body = results.getDecompiledFunction().getC();
            } else {
                String reason = results != null && results.getErrorMessage() != null
                        && !results.getErrorMessage().isBlank()
                        ? results.getErrorMessage().trim()
                        : "decompile did not complete";
                body = FAILED_MARKER_PREFIX + reason + "\n";
            }
        } catch (Exception e) {
            String reason = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            body = FAILED_MARKER_PREFIX + reason + "\n";
        }
        String fp = SweepJob.shortContentHash(body);
        String header = SweepJob.renderFunctionHeader(
                func.getName(),
                addrHex,
                size,
                part.slug(),
                part.method(),
                part.confidence(),
                part.evidenceBacked(),
                fp,
                Instant.now(),
                modNumber,
                programName);
        return header + body;
    }

    private static long functionSize(Function func) {
        try {
            return func.getBody().getNumAddresses();
        } catch (Exception e) {
            return 0L;
        }
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

    private static Map<String, IndexRow> loadIndex(Path indexPath) throws IOException {
        Map<String, IndexRow> out = new LinkedHashMap<>();
        if (!Files.isRegularFile(indexPath)) {
            return out;
        }
        for (String line : Files.readAllLines(indexPath, StandardCharsets.UTF_8)) {
            if (line.isBlank() || line.startsWith("address\t")) {
                continue;
            }
            String[] cols = line.split("\t", -1);
            if (cols.length < 4) {
                continue;
            }
            String hex = CheckoutTreeNarrower.normalizeHex(cols[0]);
            out.put(hex, new IndexRow(
                    cols[0],
                    cols[1],
                    cols[2],
                    cols[3],
                    cols.length > 4 && Boolean.parseBoolean(cols[4])));
        }
        return out;
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

    // -------------------------------------------------------------------------
    // Result types
    // -------------------------------------------------------------------------

    public record PartitionMeta(
            String slug, String method, double confidence, boolean evidenceBacked) {}

    public record SpliceResult(
            String newBody,
            boolean rewritten,
            List<String> refreshed,
            List<String> unchanged,
            List<String> failed,
            Map<String, String> nameUpdates) {}

    public record RefreshResult(
            List<String> refreshed,
            List<String> unchanged,
            List<String> skipped,
            List<String> skippedReasons,
            List<String> failed,
            List<String> failedReasons,
            int filesRewritten,
            long elapsedMs,
            boolean markedStale) {

        public static RefreshResult of(
                List<String> refreshed,
                List<String> unchanged,
                List<String> skipped,
                List<String> skippedReasons,
                List<String> failed,
                List<String> failedReasons,
                int filesRewritten,
                long elapsedMs,
                boolean markedStale) {
            return new RefreshResult(
                    List.copyOf(refreshed),
                    List.copyOf(unchanged),
                    List.copyOf(skipped),
                    List.copyOf(skippedReasons),
                    List.copyOf(failed),
                    List.copyOf(failedReasons),
                    filesRewritten,
                    elapsedMs,
                    markedStale);
        }

        public Map<String, Object> toMap(String checkoutId, boolean busy, String phase) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("checkout_id", checkoutId);
            out.put("busy", busy);
            if (phase != null) {
                out.put("phase", phase);
            }
            out.put("refreshed", refreshed.size());
            out.put("unchanged", unchanged.size());
            out.put("skipped", skipped.size());
            out.put("failed", failed.size());
            out.put("files_rewritten", filesRewritten);
            out.put("elapsed_ms", elapsedMs);
            out.put("marked_stale", markedStale);
            if (!skipped.isEmpty()) {
                List<Map<String, String>> rows = new ArrayList<>();
                for (int i = 0; i < skipped.size(); i++) {
                    Map<String, String> row = new LinkedHashMap<>();
                    row.put("address", skipped.get(i));
                    row.put("reason", i < skippedReasons.size() ? skippedReasons.get(i) : "skipped");
                    rows.add(row);
                }
                out.put("skipped_detail", rows);
            }
            if (!failed.isEmpty()) {
                List<Map<String, String>> rows = new ArrayList<>();
                for (int i = 0; i < failed.size(); i++) {
                    Map<String, String> row = new LinkedHashMap<>();
                    row.put("address", failed.get(i));
                    row.put("reason", i < failedReasons.size() ? failedReasons.get(i) : "failed");
                    rows.add(row);
                }
                out.put("failed_detail", rows);
            }
            return out;
        }
    }

    private record IndexRow(
            String addressHex,
            String name,
            String slug,
            String file,
            boolean evidenceBacked) {}
}
