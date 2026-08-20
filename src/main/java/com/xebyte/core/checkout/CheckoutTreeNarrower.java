package com.xebyte.core.checkout;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Immediate on-disk narrowing for {@code /checkout_configure}.
 *
 * <p>Leaving an excluded function's body on disk would be a lie {@code Grep}
 * would still hit. A compartment may span many Read-budget files, so every
 * file that held a removed member is rewritten (or deleted when emptied) —
 * never only the first remaining row's path.
 */
public final class CheckoutTreeNarrower {

    /** First header line: {@code // fn: Name @ <addr> size=N} */
    private static final Pattern FN_HEADER = Pattern.compile(
            "^// fn: .* @ ([0-9A-Fa-f]+) size=");

    private CheckoutTreeNarrower() {
    }

    /**
     * Drop every on-disk function that is out of scope under {@code evaluator}.
     * Rewrites partially-hit partition files; deletes empty compartments;
     * rebuilds {@code index/by-address.tsv} and a slim {@code modules/index.md}.
     */
    public static NarrowResult narrow(
            Checkout checkout, Program program, ExclusionEvaluator evaluator) throws IOException {
        Path root = checkout.root().path();
        Path indexPath = root.resolve(CheckoutLayout.byAddressTsv());
        List<IndexEntry> entries = Files.isRegularFile(indexPath)
                ? readIndex(indexPath)
                : List.of();

        if (entries.isEmpty()) {
            // Nothing materialised yet — config alone is enough; no files to lie.
            return new NarrowResult(0, 0, List.of());
        }

        FunctionManager fm = program.getFunctionManager();
        List<IndexEntry> kept = new ArrayList<>();
        Set<String> removedAddresses = new LinkedHashSet<>();
        Map<String, Integer> perPartitionRemoved = new LinkedHashMap<>();

        for (IndexEntry entry : entries) {
            Function func = resolveFunction(fm, program, entry.addressHex());
            boolean inScope;
            if (func == null) {
                // Address no longer maps — drop it; the tree must not claim it.
                inScope = false;
            } else {
                inScope = evaluator.isInScope(func, entry.slug());
            }
            if (inScope) {
                kept.add(entry);
            } else {
                removedAddresses.add(normalizeHex(entry.addressHex()));
                perPartitionRemoved.merge(entry.slug(), 1, Integer::sum);
            }
        }

        if (removedAddresses.isEmpty()) {
            return new NarrowResult(0, entries.size(), List.of());
        }

        // Group remaining rows by partition so we know which files to rewrite.
        Map<String, List<IndexEntry>> bySlug = new LinkedHashMap<>();
        for (IndexEntry e : kept) {
            bySlug.computeIfAbsent(e.slug(), s -> new ArrayList<>()).add(e);
        }

        List<String> rewritten = new ArrayList<>();
        Set<String> touchedSlugs = new LinkedHashSet<>(perPartitionRemoved.keySet());

        // Every file that belonged to a touched slug — including ones that
        // lose ALL members — must be rewritten or deleted. Indexing only the
        // remaining rows would leave dead bodies in sibling budget files.
        Map<String, Set<String>> filesBySlug = new LinkedHashMap<>();
        for (IndexEntry e : entries) {
            if (touchedSlugs.contains(e.slug())) {
                filesBySlug.computeIfAbsent(e.slug(), s -> new LinkedHashSet<>()).add(e.file());
            }
        }

        for (String slug : touchedSlugs) {
            List<IndexEntry> remaining = bySlug.getOrDefault(slug, List.of());
            if (remaining.isEmpty()) {
                deleteModuleDir(root.resolve("modules").resolve(slug));
                rewritten.add(slug + " (deleted)");
                continue;
            }

            Set<String> files = filesBySlug.getOrDefault(slug, Set.of());
            for (String relative : files) {
                Path file = root.resolve(relative);
                if (!Files.isRegularFile(file)) {
                    continue;
                }
                String body = Files.readString(file, StandardCharsets.UTF_8);
                String filtered = rewritePartitionFile(body, removedAddresses);
                if (filtered.isBlank()) {
                    Files.deleteIfExists(file);
                } else {
                    checkout.root().writeFile(Path.of(relative), filtered);
                }
            }
            rewriteModuleReadme(checkout, slug, remaining);
            rewritten.add(slug + " (rewritten, " + remaining.size() + " kept)");
        }

        writeIndex(checkout, kept);
        writeModulesIndex(checkout, kept, bySlug);
        return new NarrowResult(removedAddresses.size(), kept.size(),
                List.copyOf(rewritten));
    }

    /**
     * Keep function chunks whose entry hex is not in {@code removedAddresses}.
     * Exposed for offline tests — the configure path must rewrite, not delete,
     * when a partition loses only some members.
     */
    public static String rewritePartitionFile(String fileBody, Set<String> removedAddresses) {
        if (fileBody == null || fileBody.isEmpty() || removedAddresses == null
                || removedAddresses.isEmpty()) {
            return fileBody == null ? "" : fileBody;
        }
        Set<String> removed = new LinkedHashSet<>();
        for (String a : removedAddresses) {
            removed.add(normalizeHex(a));
        }

        List<String> chunks = splitFunctionChunks(fileBody);
        StringBuilder out = new StringBuilder();
        for (String chunk : chunks) {
            String addr = addressFromChunk(chunk);
            if (addr != null && removed.contains(normalizeHex(addr))) {
                continue;
            }
            out.append(chunk);
            if (!chunk.endsWith("\n")) {
                out.append('\n');
            }
            // Preserve the blank line the sweep inserts between functions.
            if (!chunk.endsWith("\n\n")) {
                out.append('\n');
            }
        }
        return out.toString();
    }

    /** Split a partition {@code .c} into per-function chunks (header + body). */
    public static List<String> splitFunctionChunks(String fileBody) {
        List<String> chunks = new ArrayList<>();
        if (fileBody == null || fileBody.isEmpty()) {
            return chunks;
        }
        String[] lines = fileBody.split("\n", -1);
        StringBuilder cur = null;
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            boolean startsFn = line.startsWith("// fn: ");
            if (startsFn) {
                if (cur != null) {
                    chunks.add(trimTrailingBlank(cur.toString()));
                }
                cur = new StringBuilder();
            }
            if (cur == null) {
                // Preamble / stray text before the first header — keep with next
                // chunk by starting one, or drop if the file is malformed.
                if (!line.isEmpty()) {
                    cur = new StringBuilder();
                } else {
                    continue;
                }
            }
            cur.append(line);
            if (i < lines.length - 1 || fileBody.endsWith("\n")) {
                cur.append('\n');
            }
        }
        if (cur != null && !cur.isEmpty()) {
            chunks.add(trimTrailingBlank(cur.toString()));
        }
        return chunks;
    }

    public static String addressFromChunk(String chunk) {
        if (chunk == null) {
            return null;
        }
        int nl = chunk.indexOf('\n');
        String first = nl < 0 ? chunk : chunk.substring(0, nl);
        Matcher m = FN_HEADER.matcher(first);
        if (!m.find()) {
            return null;
        }
        return m.group(1);
    }

    private static String trimTrailingBlank(String s) {
        // Leave a single trailing newline; strip extra blank lines the splitter
        // may have absorbed so rewrite can re-insert a consistent separator.
        while (s.endsWith("\n\n")) {
            s = s.substring(0, s.length() - 1);
        }
        return s;
    }

    private static Function resolveFunction(FunctionManager fm, Program program, String hex) {
        var addr = com.xebyte.core.ServiceUtils.parseAddress(program, hex);
        if (addr == null) {
            return null;
        }
        return fm.getFunctionAt(addr);
    }

    private static List<IndexEntry> readIndex(Path indexPath) throws IOException {
        List<String> lines = Files.readAllLines(indexPath, StandardCharsets.UTF_8);
        List<IndexEntry> out = new ArrayList<>();
        for (String line : lines) {
            if (line.isBlank() || line.startsWith("address\t")) {
                continue;
            }
            String[] cols = line.split("\t", -1);
            if (cols.length < 4) {
                continue;
            }
            out.add(new IndexEntry(
                    cols[0],
                    cols[1],
                    cols[2],
                    cols[3],
                    cols.length > 4 && Boolean.parseBoolean(cols[4])));
        }
        return out;
    }

    private static void writeIndex(Checkout checkout, List<IndexEntry> kept) throws IOException {
        StringBuilder sb = new StringBuilder(SweepJob.byAddressHeader());
        for (IndexEntry e : kept) {
            sb.append(SweepJob.formatByAddressRow(
                    e.addressHex(), e.name(), e.slug(), e.file(), e.evidenceBacked()));
        }
        checkout.root().writeFile(Path.of(CheckoutLayout.byAddressTsv()), sb.toString());
    }

    private static void writeModulesIndex(
            Checkout checkout,
            List<IndexEntry> kept,
            Map<String, List<IndexEntry>> bySlug) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("# Modules\n\n");
        sb.append("functions_in_tree: ").append(kept.size()).append('\n');
        sb.append("partitions: ").append(bySlug.size()).append('\n');
        sb.append("note: narrowed by /checkout_configure — full strategy log "
                + "rewritten on next sweep\n\n");
        sb.append("## Compartments\n\n");
        sb.append("| slug | functions | files |\n");
        sb.append("| --- | ---: | ---: |\n");
        for (Map.Entry<String, List<IndexEntry>> e : bySlug.entrySet()) {
            Set<String> files = new LinkedHashSet<>();
            for (IndexEntry row : e.getValue()) {
                files.add(row.file());
            }
            sb.append("| ").append(e.getKey())
                    .append(" | ").append(e.getValue().size())
                    .append(" | ").append(files.size())
                    .append(" |\n");
        }
        checkout.root().writeFile(Path.of(CheckoutLayout.modulesIndexMd()), sb.toString());
    }

    private static void rewriteModuleReadme(
            Checkout checkout, String slug, List<IndexEntry> remaining) throws IOException {
        Map<String, List<IndexEntry>> byFile = new LinkedHashMap<>();
        for (IndexEntry e : remaining) {
            byFile.computeIfAbsent(e.file(), f -> new ArrayList<>()).add(e);
        }
        StringBuilder sb = new StringBuilder();
        sb.append("# Module ").append(slug).append("\n\n");
        sb.append("functions: ").append(remaining.size()).append('\n');
        sb.append("files: ").append(byFile.size()).append('\n');
        sb.append("note: member list narrowed by /checkout_configure\n");
        sb.append("\n## Files\n\n");
        sb.append("| file | first | last | functions |\n");
        sb.append("| --- | --- | --- | ---: |\n");
        for (Map.Entry<String, List<IndexEntry>> e : byFile.entrySet()) {
            List<IndexEntry> rows = e.getValue();
            String first = rows.get(0).addressHex();
            String last = rows.get(rows.size() - 1).addressHex();
            sb.append("| ").append(e.getKey())
                    .append(" | ").append(first)
                    .append(" | ").append(last)
                    .append(" | ").append(rows.size())
                    .append(" |\n");
        }
        checkout.root().writeFile(Path.of(CheckoutLayout.moduleReadme(slug)), sb.toString());
    }

    private static void deleteModuleDir(Path dir) throws IOException {
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
            public FileVisitResult postVisitDirectory(Path d, IOException exc)
                    throws IOException {
                if (exc != null) {
                    throw exc;
                }
                Files.deleteIfExists(d);
                return FileVisitResult.CONTINUE;
            }
        });
    }

    public static String normalizeHex(String hex) {
        if (hex == null) {
            return "";
        }
        String t = hex.trim();
        if (t.startsWith("0x") || t.startsWith("0X")) {
            t = t.substring(2);
        }
        // Strip a space: prefix if present (mem:00100000 → 00100000 for compare
        // against header hex which is toString(false)).
        int colon = t.lastIndexOf(':');
        if (colon >= 0) {
            t = t.substring(colon + 1);
        }
        return t.toLowerCase(Locale.ROOT);
    }

    public record NarrowResult(int functionsRemoved, int functionsRemaining, List<String> modulesTouched) {}

    private record IndexEntry(
            String addressHex,
            String name,
            String slug,
            String file,
            boolean evidenceBacked) {}
}
