package com.xebyte.core.checkout;

import com.xebyte.core.FunctionFacts;
import com.xebyte.core.ServiceUtils;
import com.xebyte.core.partition.PartitionContext;
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
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Splice refreshed decompilations into existing checkout compartment files.
 *
 * <p>A compartment is many Read-budget files (measured bug: 904 functions /
 * 1.95 MB in one file). Rewriting a caller's file by re-decompiling every
 * member of a multi-megabyte compartment costs seconds; splicing one block
 * costs ~8 ms. Never re-decompile a whole partition to refresh one function.
 * Lookup is index-driven ({@code by-address.tsv} → relative path), so multi-file
 * compartments need no special splice logic.
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
        String want = CheckoutAddresses.normalize(addressHex);
        if (want.isEmpty() || fileBody == null) {
            return null;
        }
        for (String chunk : CheckoutTreeNarrower.splitFunctionChunks(fileBody)) {
            String addr = CheckoutTreeNarrower.addressFromChunk(chunk);
            if (addr != null && want.equals(CheckoutAddresses.normalize(addr))) {
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
     * Replace only the {@code // calls:} / {@code // callers:} lines. Inserts
     * them after {@code // fn:} when an older seven-line header lacks them —
     * never touches the body or fp/dts/mod/uri/see.
     */
    public static String patchNeighbourhoodLines(
            String block, String callsValue, String callersValue) {
        if (block == null) {
            return "";
        }
        String callsLine = "// calls: " + (callsValue != null ? callsValue : "(none)");
        String callersLine = "// callers: " + (callersValue != null ? callersValue : "(none)");
        String[] lines = block.split("\n", -1);
        boolean hadTrailing = block.endsWith("\n");
        // Drop the artificial empty element split(-1) adds for a trailing newline.
        int n = lines.length;
        if (hadTrailing && n > 0 && lines[n - 1].isEmpty()) {
            n--;
        }

        boolean hasCalls = false;
        boolean hasCallers = false;
        for (int i = 0; i < n; i++) {
            if (lines[i].startsWith("// calls:")) {
                lines[i] = callsLine;
                hasCalls = true;
            } else if (lines[i].startsWith("// callers:")) {
                lines[i] = callersLine;
                hasCallers = true;
            }
        }

        StringBuilder sb = new StringBuilder();
        if (hasCalls && hasCallers) {
            for (int i = 0; i < n; i++) {
                if (i > 0) {
                    sb.append('\n');
                }
                sb.append(lines[i]);
            }
        } else {
            // Older trees: insert after the fn: line so Grep still finds neighbourhood.
            for (int i = 0; i < n; i++) {
                if (i > 0) {
                    sb.append('\n');
                }
                sb.append(lines[i]);
                if (lines[i].startsWith("// fn: ")) {
                    if (!hasCalls) {
                        sb.append('\n').append(callsLine);
                    }
                    if (!hasCallers) {
                        sb.append('\n').append(callersLine);
                    }
                }
            }
        }
        if (hadTrailing || block.isEmpty()) {
            sb.append('\n');
        }
        return sb.toString();
    }

    /**
     * Extract the current {@code // calls:} / {@code // callers:} values
     * (text after the prefix), or null when absent.
     */
    public static String[] neighbourhoodValuesFromBlock(String block) {
        String calls = null;
        String callers = null;
        if (block == null) {
            return new String[]{null, null};
        }
        for (String line : block.split("\n", -1)) {
            if (line.equals(FunctionBlock.HEADER_END)) {
                break;
            }
            if (line.startsWith("// calls:")) {
                calls = line.substring("// calls:".length()).trim();
            } else if (line.startsWith("// callers:")) {
                callers = line.substring("// callers:".length()).trim();
            }
        }
        return new String[]{calls, callers};
    }

    /** Everything after the leading {@code // } comment block — body identity for patches. */
    public static String bodyAfterLeadingComments(String block) {
        if (block == null) {
            return "";
        }
        String[] lines = block.split("\n", -1);
        // The header ends at its terminator; the decompiler's own // lines below it are body.
        // Blocks written before the terminator existed end at the first non-comment line.
        int idx = FunctionBlock.bodyStart(lines);
        if (idx < 0) {
            idx = 0;
            while (idx < lines.length && lines[idx].startsWith("// ")) {
                idx++;
            }
        }
        StringBuilder sb = new StringBuilder();
        for (; idx < lines.length; idx++) {
            if (sb.length() > 0) {
                sb.append('\n');
            }
            sb.append(lines[idx]);
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
                indexByAddr.put(CheckoutAddresses.normalize(addr), i);
            }
        }

        List<String> failed = new ArrayList<>();
        List<String> unchanged = new ArrayList<>();
        List<String> refreshed = new ArrayList<>();
        Map<String, String> nameUpdates = new LinkedHashMap<>();
        boolean anyChange = false;
        List<String> outChunks = new ArrayList<>(chunks);

        for (Map.Entry<String, String> e : addressToNewBlock.entrySet()) {
            String want = CheckoutAddresses.normalize(e.getKey());
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
            want.put(CheckoutAddresses.normalize(e.getKey()), e.getValue());
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
            String hex = CheckoutAddresses.normalize(cols[0]);
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

    /**
     * Patch {@code caller_name}/{@code callee_name} columns when the address
     * columns match. Pure text — avoids rewriting the edge list after a rename.
     */
    public static String updateCallgraphNames(
            String callgraphTsv, Map<String, String> nameByAddress) {
        if (callgraphTsv == null || nameByAddress == null || nameByAddress.isEmpty()) {
            return callgraphTsv == null ? "" : callgraphTsv;
        }
        Map<String, String> want = new LinkedHashMap<>();
        for (Map.Entry<String, String> e : nameByAddress.entrySet()) {
            want.put(CheckoutAddresses.normalize(e.getKey()), e.getValue());
        }
        StringBuilder out = new StringBuilder();
        for (String line : callgraphTsv.split("\n", -1)) {
            if (line.isEmpty() && out.length() == 0) {
                continue;
            }
            if (line.isBlank() || line.startsWith("caller\t")) {
                out.append(line).append('\n');
                continue;
            }
            String[] cols = line.split("\t", -1);
            // caller  callee  caller_name  callee_name
            if (cols.length < 4) {
                out.append(line).append('\n');
                continue;
            }
            String callerHex = CheckoutAddresses.normalize(cols[0]);
            String calleeHex = CheckoutAddresses.normalize(cols[1]);
            String newCaller = want.get(callerHex);
            String newCallee = want.get(calleeHex);
            if (newCaller != null) {
                cols[2] = newCaller;
            }
            if (newCallee != null) {
                cols[3] = newCallee;
            }
            out.append(String.join("\t", cols)).append('\n');
        }
        String result = out.toString();
        if (callgraphTsv.endsWith("\n") && !result.endsWith("\n")) {
            return result + "\n";
        }
        if (!callgraphTsv.endsWith("\n") && result.endsWith("\n")) {
            return result.substring(0, result.length() - 1);
        }
        return result;
    }

    // -------------------------------------------------------------------------
    // Orchestration (Program + disk)
    // -------------------------------------------------------------------------

    /**
     * Refresh the given entry addresses in an existing checkout tree.
     *
     * <p>Two tiers: (a) re-decompile + full block rewrite for the addresses
     * passed in; (b) header-only {@code calls:}/{@code callers:} patch for each
     * neighbour (callers and callees) derived from the <em>live</em> call graph
     * — no decompile. Java owns the neighbour set so the bridge can keep
     * sending only addresses whose text changed.
     *
     * <p>Never routes through {@code ThreadingStrategy} (same rule as
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
        List<String> headerPatched = new ArrayList<>();
        List<String> unchanged = new ArrayList<>();
        Map<String, String> nameUpdates = new LinkedHashMap<>();
        Map<String, List<AddressIndex.Row>> addressRows = new LinkedHashMap<>();
        int filesRewritten = 0;

        Path indexPath = checkout.root().path().resolve(CheckoutLayout.byAddressTsv());
        Map<String, IndexRow> index = loadIndex(indexPath);

        // Group in-tree addresses by relative file.
        LinkedHashSet<String> refreshHex = new LinkedHashSet<>();
        Map<String, List<String>> byFile = new LinkedHashMap<>();
        for (String raw : addresses) {
            if (raw == null || raw.isBlank()) {
                continue;
            }
            String hex = CheckoutAddresses.normalize(raw);
            IndexRow row = index.get(hex);
            if (row == null) {
                skipped.add(hex);
                skippedReasons.add("not_in_tree");
                continue;
            }
            refreshHex.add(hex);
            byFile.computeIfAbsent(row.file(), f -> new ArrayList<>()).add(hex);
        }

        if (byFile.isEmpty() && refreshHex.isEmpty()) {
            return RefreshResult.of(
                    refreshed, headerPatched, unchanged, skipped, skippedReasons,
                    failed, failedReasons,
                    0, System.currentTimeMillis() - started, false);
        }

        // Dirty before work — a crash mid-refresh must leave STATUS saying dirty.
        checkout.setProgress(checkout.progress().withLastError(null));
        CheckoutStatusMd.write(checkout, "dirty");
        long refreshingAt = program.getModificationNumber();

        // Live call graph once for both tiers — rename correctness without knowing
        // the old name; neighbours get header patches from current edges.
        PartitionContext ctx = new PartitionContext(program);

        DecompInterface decomp = null;
        try {
            if (!byFile.isEmpty()) {
                decomp = ServiceUtils.createConfiguredDecompiler(program, FunctionFacts::configureDecompiler);

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
                        Function func = CheckoutAddresses.function(program, hex);
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
                        FunctionBlock.Built built = decompileBlock(
                                decomp, func, part, mod, timeout, program.getName());
                        replacements.put(hex, built.text());
                        addressRows.put(hex, built.addresses());
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
            }

            // Tier (b): header-only for neighbours not already fully rewritten.
            filesRewritten += patchNeighbourHeaders(
                    checkout, program, ctx, index, refreshHex, headerPatched, failed,
                    failedReasons);
        } finally {
            if (decomp != null) {
                try {
                    decomp.dispose();
                } catch (Exception ignored) {
                    // must not mask refresh outcome
                }
            }
        }

        AddressIndex.update(checkout, addressRows);

        if (!nameUpdates.isEmpty()) {
            if (Files.isRegularFile(indexPath)) {
                String indexText = Files.readString(indexPath, StandardCharsets.UTF_8);
                String updated = updateIndexNames(indexText, nameUpdates);
                if (!updated.equals(indexText)) {
                    checkout.root().writeFile(Path.of(CheckoutLayout.byAddressTsv()), updated);
                }
            }
            Path callgraphPath = checkout.root().path().resolve(CheckoutLayout.callgraphTsv());
            if (Files.isRegularFile(callgraphPath)) {
                String cgText = Files.readString(callgraphPath, StandardCharsets.UTF_8);
                String updatedCg = updateCallgraphNames(cgText, nameUpdates);
                if (!updatedCg.equals(cgText)) {
                    checkout.root().writeFile(Path.of(CheckoutLayout.callgraphTsv()), updatedCg);
                }
            }
        }

        // Settled after — same ordering rule as the sweep. Each refreshed block was
        // rewritten in place: the tree is no longer byte-for-byte the sweep's output.
        checkout.setProgress(checkout.progress()
                .withLastError(null)
                .reconciledAt(refreshingAt, refreshed.size(), 0));
        CheckoutStatusMd.write(checkout, CheckoutStatusMd.settledState(checkout.progress()));

        return RefreshResult.of(
                refreshed, headerPatched, unchanged, skipped, skippedReasons,
                failed, failedReasons,
                filesRewritten, System.currentTimeMillis() - started, false);
    }

    /**
     * For each neighbour of {@code refreshHex}, rewrite only its
     * {@code calls:}/{@code callers:} lines from the live graph. Returns how
     * many files were rewritten.
     */
    private static int patchNeighbourHeaders(
            Checkout checkout,
            Program program,
            PartitionContext ctx,
            Map<String, IndexRow> index,
            Set<String> refreshHex,
            List<String> headerPatched,
            List<String> failed,
            List<String> failedReasons) throws IOException {

        Set<String> neighbourHex = neighbourAddresses(ctx, program, refreshHex);
        neighbourHex.removeAll(refreshHex);

        Map<String, List<String>> byFile = new LinkedHashMap<>();
        for (String hex : neighbourHex) {
            IndexRow row = index.get(hex);
            if (row == null) {
                continue; // not in tree — exclusion / out of scope
            }
            byFile.computeIfAbsent(row.file(), f -> new ArrayList<>()).add(hex);
        }

        int filesRewritten = 0;
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
            String body = original;
            boolean any = false;
            for (String hex : fileEntry.getValue()) {
                String oldBlock = findBlock(body, hex);
                if (oldBlock == null) {
                    failed.add(hex);
                    failedReasons.add("block_not_found");
                    continue;
                }
                Function func = CheckoutAddresses.function(program, hex);
                if (func == null) {
                    failed.add(hex);
                    failedReasons.add("function_not_found");
                    continue;
                }
                String[] now = FunctionBlock.neighbourValues(func);
                String callsVal = now[0];
                String callersVal = now[1];
                String[] existing = neighbourhoodValuesFromBlock(oldBlock);
                if (Objects.equals(callsVal, existing[0])
                        && Objects.equals(callersVal, existing[1])) {
                    continue;
                }
                String newBlock = patchNeighbourhoodLines(oldBlock, callsVal, callersVal);
                // Body must stay byte-identical — only the two neighbourhood lines move.
                // Skip-all-leading-comments (not a fixed count) so a 7→9 insert still compares.
                if (!bodyAfterLeadingComments(oldBlock).equals(bodyAfterLeadingComments(newBlock))) {
                    failed.add(hex);
                    failedReasons.add("header_patch_touched_body");
                    continue;
                }
                String replaced = replaceBlock(body, hex, newBlock);
                if (replaced == null) {
                    failed.add(hex);
                    failedReasons.add("block_not_found");
                    continue;
                }
                body = replaced;
                any = true;
                headerPatched.add(hex);
            }
            if (any) {
                checkout.root().writeFile(Path.of(relative), body);
                filesRewritten++;
            }
        }
        return filesRewritten;
    }

    /** Live callers ∪ callees of every address in {@code seeds}. */
    static Set<String> neighbourAddresses(
            PartitionContext ctx, Program program, Set<String> seeds) {
        Set<String> out = new LinkedHashSet<>();
        PartitionContext.CallGraph cg = ctx.callGraph();
        List<Function> fns = ctx.functions();
        for (String hex : seeds) {
            Function func = CheckoutAddresses.function(program, hex);
            if (func == null) {
                continue;
            }
            Integer idx = ctx.indexOf(func.getEntryPoint());
            if (idx == null) {
                continue;
            }
            addNeighbourHexes(out, fns, cg.callees().get(idx));
            addNeighbourHexes(out, fns, cg.callers().get(idx));
        }
        return out;
    }

    private static void addNeighbourHexes(
            Set<String> out, List<Function> fns, Set<Integer> indices) {
        if (indices == null) {
            return;
        }
        for (int i : indices) {
            if (i >= 0 && i < fns.size()) {
                out.add(CheckoutAddresses.of(fns.get(i)));
            }
        }
    }

    /** Replace one block in a file body without fingerprint comparison; null if missing. */
    static String replaceBlock(String fileBody, String addressHex, String newBlock) {
        if (fileBody == null) {
            fileBody = "";
        }
        String want = CheckoutAddresses.normalize(addressHex);
        List<String> chunks = CheckoutTreeNarrower.splitFunctionChunks(fileBody);
        boolean found = false;
        List<String> outChunks = new ArrayList<>(chunks.size());
        for (String chunk : chunks) {
            String addr = CheckoutTreeNarrower.addressFromChunk(chunk);
            if (addr != null && want.equals(CheckoutAddresses.normalize(addr))) {
                outChunks.add(trimTrailingExtraBlanks(newBlock));
                found = true;
            } else {
                outChunks.add(chunk);
            }
        }
        if (!found) {
            return null;
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
        return sb.toString();
    }

    /** One function's block, decompiled with the checkout's pooled decompiler. */
    static FunctionBlock.Built decompileBlock(
            DecompInterface decomp,
            Function func,
            PartitionMeta part,
            long modNumber,
            int timeoutSeconds,
            String programName) {
        return FunctionBlock.build(func, decomp, timeoutSeconds, TaskMonitor.DUMMY, part.slug(),
                part.method(), part.confidence(), part.evidenceBacked(), modNumber, programName);
    }

    private static long functionSize(Function func) {
        try {
            return func.getBody().getNumAddresses();
        } catch (Exception e) {
            return 0L;
        }
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
            String hex = CheckoutAddresses.normalize(cols[0]);
            out.put(hex, new IndexRow(
                    cols[0],
                    cols[1],
                    cols[2],
                    cols[3],
                    cols.length > 4 && Boolean.parseBoolean(cols[4]),
                    cols.length > 5 ? cols[5] : ""));
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
            List<String> headerPatched,
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
                List<String> headerPatched,
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
                    List.copyOf(headerPatched),
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
            out.put("header_patched", headerPatched.size());
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
            boolean evidenceBacked,
            String ifp) {}
}
