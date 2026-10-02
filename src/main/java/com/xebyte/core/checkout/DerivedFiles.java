package com.xebyte.core.checkout;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import com.xebyte.core.partition.PartitionContext;

/**
 * Every file in a checkout that is not a function block: the indexes, the callgraph, the
 * READMEs and {@code AGENTS.md}, rendered from the by-address rows and the sweep's
 * {@link PartitionMeta}.
 *
 * <p>One renderer for every writer, so the tree is the same whichever path produced it: the
 * sweep, a full or targeted reconcile, an adoption, the narrower. The sweep and the
 * reconciler used to render these separately, and the reconciler's versions were thinner (a
 * stub {@code modules/index.md}, module READMEs without their evidence) or missing; a tree
 * that had been reconciled could not be told apart from a broken one. Every pass now ends by
 * calling {@link #writeAll}, and a file that already says the right thing is not rewritten.
 */
public final class DerivedFiles {

    private DerivedFiles() {
    }

    /**
     * Write every derived file for {@code rows}. {@code meta} is null only for a tree swept
     * before it was kept; then the files that need it are left as they are, and the full
     * reconcile that finds such a tree sweeps instead (see {@code TreeReconciler}).
     */
    static void writeAll(Checkout checkout, Program program, List<TreeFiles.IndexEntry> rows,
            PartitionMeta meta, PartitionContext ctx) throws IOException {
        List<TreeFiles.IndexEntry> sorted = new ArrayList<>(rows);
        sorted.sort((a, b) -> CheckoutAddresses.normalize(a.addressHex())
                .compareTo(CheckoutAddresses.normalize(b.addressHex())));
        Map<String, List<TreeFiles.IndexEntry>> bySlug = new LinkedHashMap<>();
        for (TreeFiles.IndexEntry e : sorted) {
            bySlug.computeIfAbsent(e.slug(), s -> new ArrayList<>()).add(e);
        }

        writeIfChanged(checkout, CheckoutLayout.byAddressTsv(), byAddress(sorted));
        writeIfChanged(checkout, CheckoutLayout.callgraphTsv(), SweepJob.renderCallgraphTsv(ctx));
        // Written by builds before the refs line carried the pool word; a fresh tree has none.
        Files.deleteIfExists(checkout.root().path().resolve("index/addresses.tsv"));
        deleteEmptyModules(checkout, bySlug.keySet());
        if (meta == null) {
            return;
        }
        writeIfChanged(checkout, CheckoutLayout.modulesIndexMd(), modulesIndex(meta, sorted, bySlug));
        for (Map.Entry<String, List<TreeFiles.IndexEntry>> e : bySlug.entrySet()) {
            writeIfChanged(checkout, CheckoutLayout.moduleReadme(e.getKey()),
                    ModuleReadme.render(e.getKey(), grouping(checkout, meta, e.getKey()),
                            e.getValue().size(), files(e.getValue())));
        }
        writeIfChanged(checkout, CheckoutLayout.readmeMd(), topReadme(checkout, sorted.size(), bySlug.size()));
        boolean peripherals = meta.partitions().stream()
                .anyMatch(p -> "mmio-page".equals(p.method()) && bySlug.containsKey(p.slug()));
        writeIfChanged(checkout, CheckoutLayout.agentsMd(), CheckoutGuidance.agentsMd(
                checkout.programName(), checkout.id(), checkout.root().path().toString(),
                isStripped(program), peripherals));
    }

    /** Write {@code content} unless the file already holds exactly that; true if written. */
    static boolean writeIfChanged(Checkout checkout, String relative, String content) throws IOException {
        Path abs = checkout.root().path().resolve(relative);
        byte[] bytes = content.getBytes(StandardCharsets.UTF_8);
        if (Files.isRegularFile(abs) && Arrays.equals(Files.readAllBytes(abs), bytes)) {
            return false;
        }
        checkout.root().writeFile(Path.of(relative), bytes);
        return true;
    }

    /**
     * Write a compartment file unless it already says the same apart from the render stamps
     * ({@code dts}, {@code mod}); true if written. A sweep over an unchanged program then
     * touches nothing: no mtime churn for a watcher, no diff in a committed tree.
     */
    static boolean writeIfContentChanged(Checkout checkout, String relative, String content)
            throws IOException {
        Path abs = checkout.root().path().resolve(relative);
        if (Files.isRegularFile(abs) && withoutStamps(Files.readString(abs, StandardCharsets.UTF_8))
                .equals(withoutStamps(content))) {
            return false;
        }
        checkout.root().writeFile(Path.of(relative), content);
        return true;
    }

    private static String withoutStamps(String text) {
        StringBuilder sb = new StringBuilder(text.length());
        for (String line : text.split("\n", -1)) {
            if (!line.startsWith("// dts: ") && !line.startsWith("// mod: ")) {
                sb.append(line).append('\n');
            }
        }
        return sb.toString();
    }

    /**
     * Delete compartment files that no row points at: what a previous sweep or layout left
     * behind. The sweep updates a tree in place rather than wiping it first, so this is how
     * it ends with nothing a fresh tree would not hold.
     */
    static void deleteUnreferenced(Checkout checkout, List<TreeFiles.IndexEntry> rows) throws IOException {
        Set<String> wanted = new LinkedHashSet<>();
        rows.forEach(r -> wanted.add(r.file()));
        Path root = checkout.root().path();
        Path modules = root.resolve("modules");
        if (!Files.isDirectory(modules)) {
            return;
        }
        try (java.util.stream.Stream<Path> walk = Files.walk(modules)) {
            for (Path p : walk.filter(f -> f.toString().endsWith(".c")).toList()) {
                if (!wanted.contains(root.relativize(p).toString().replace('\\', '/'))) {
                    Files.deleteIfExists(p);
                }
            }
        }
    }

    private static String byAddress(List<TreeFiles.IndexEntry> sorted) {
        StringBuilder sb = new StringBuilder(SweepJob.byAddressHeader());
        for (TreeFiles.IndexEntry e : sorted) {
            sb.append(SweepJob.formatByAddressRow(e.addressHex(), e.name(), e.slug(), e.file(),
                    e.evidenceBacked(), e.ifp()));
        }
        return sb.toString();
    }

    private static ModuleReadme.Grouping grouping(Checkout checkout, PartitionMeta meta, String slug)
            throws IOException {
        PartitionMeta.Part part = meta.part(slug);
        if (part != null) {
            return new ModuleReadme.Grouping(part.method(), part.confidence(), part.evidence(), null);
        }
        // A compartment the sweep did not form (a pin added since): keep what its README says.
        Path readme = checkout.root().path().resolve(CheckoutLayout.moduleReadme(slug));
        return ModuleReadme.parse(Files.isRegularFile(readme)
                ? Files.readString(readme, StandardCharsets.UTF_8) : null);
    }

    /** The file table: files in address order of their first function, first/last/count each. */
    private static List<ModuleReadme.FileRow> files(List<TreeFiles.IndexEntry> sortedRows) {
        Map<String, List<TreeFiles.IndexEntry>> byFile = new LinkedHashMap<>();
        for (TreeFiles.IndexEntry e : sortedRows) {
            byFile.computeIfAbsent(e.file(), f -> new ArrayList<>()).add(e);
        }
        List<ModuleReadme.FileRow> out = new ArrayList<>(byFile.size());
        for (Map.Entry<String, List<TreeFiles.IndexEntry>> e : byFile.entrySet()) {
            List<TreeFiles.IndexEntry> r = e.getValue();
            out.add(new ModuleReadme.FileRow(e.getKey(), r.get(0).addressHex(),
                    r.get(r.size() - 1).addressHex(), r.size()));
        }
        return out;
    }

    private static String modulesIndex(PartitionMeta meta, List<TreeFiles.IndexEntry> rows,
            Map<String, List<TreeFiles.IndexEntry>> bySlug) {
        int eligible = meta.eligibleFunctions();
        double pct = eligible == 0 ? 0.0 : (100.0 * meta.functionsWithStrings() / eligible);
        StringBuilder sb = new StringBuilder();
        sb.append("# Modules\n\n");
        sb.append("eligible_functions: ").append(eligible).append('\n');
        sb.append("functions_in_scope: ").append(meta.functionsInScope()).append('\n');
        sb.append("assigned_functions: ").append(meta.assignedFunctions()).append('\n');
        sb.append("partitions: ").append(bySlug.size()).append('\n');
        sb.append("functions_in_tree: ").append(rows.size()).append('\n');
        if (!meta.removedByRule().isEmpty()) {
            sb.append("\n## Exclusions removed\n\n");
            meta.removedByRule().forEach((k, v) ->
                    sb.append("- ").append(k).append(": removed ").append(v).append('\n'));
        }
        sb.append("\n## Coverage\n\n");
        sb.append(String.format(Locale.ROOT,
                "%d of %d eligible functions (%.1f%%) carry a referenced-string signal; "
                        + "the rest inherit their compartment by address containment.\n\n",
                meta.functionsWithStrings(), eligible, pct));
        // The caveat has to be about THIS binary: an earlier version restated one specimen's
        // numbers (1299/3230 = 40%) into every tree, which on a 25k-function ELF whose real
        // figure is 9.9% was a false claim in the one file meant to be honest about coverage.
        sb.append("Compartments are structural, not semantic: they are coherent but "
                + "unscored (no ground-truth comparison exists yet). A slug names no "
                + "meaning — read each compartment's README.md for the rule and evidence "
                + "that formed it, and treat a low evidence-backed count as a boundary "
                + "around a poorly-evidenced interior rather than a claim about its "
                + "contents.\n\n");
        sb.append("## Strategy log\n\n");
        for (Map.Entry<String, Object> e : meta.strategyLog().entrySet()) {
            sb.append("### ").append(e.getKey()).append("\n\n");
            if (e.getValue() instanceof Map<?, ?> m) {
                m.forEach((k, v) -> sb.append("- ").append(k).append(": ").append(v).append('\n'));
            } else {
                sb.append(e.getValue()).append('\n');
            }
            sb.append('\n');
        }
        sb.append("## Compartments\n\n");
        sb.append("| slug | method | functions | files | confidence |\n");
        sb.append("| --- | --- | ---: | ---: | ---: |\n");
        Set<String> listed = new LinkedHashSet<>();
        for (PartitionMeta.Part p : meta.partitions()) {
            List<TreeFiles.IndexEntry> members = bySlug.get(p.slug());
            if (members == null) {
                continue;
            }
            listed.add(p.slug());
            sb.append(compartmentRow(p.slug(), p.method(), members, String.format(Locale.ROOT, "%.2f", p.confidence())));
        }
        for (Map.Entry<String, List<TreeFiles.IndexEntry>> e : bySlug.entrySet()) {
            if (!listed.contains(e.getKey())) {
                sb.append(compartmentRow(e.getKey(), "added after sweep", e.getValue(), "-"));
            }
        }
        return sb.toString();
    }

    private static String compartmentRow(String slug, String method,
            List<TreeFiles.IndexEntry> members, String confidence) {
        Set<String> files = new LinkedHashSet<>();
        members.forEach(m -> files.add(m.file()));
        return "| " + slug + " | " + method + " | " + members.size() + " | " + files.size()
                + " | " + confidence + " |\n";
    }

    private static String topReadme(Checkout checkout, int functions, int partitions) {
        StringBuilder sb = new StringBuilder();
        sb.append("# Decompilation checkout: ").append(checkout.programName()).append("\n\n");
        sb.append("checkout_id: ").append(checkout.id()).append('\n');
        sb.append("domain_path: ").append(checkout.domainPath()).append('\n');
        sb.append("functions: ").append(functions).append('\n');
        sb.append("partitions: ").append(partitions).append('\n');
        sb.append("\n## How to read\n\n");
        sb.append("- `AGENTS.md` — **start here**: what this tree is, whether it is current, "
                + "and how to search it\n");
        sb.append("- `modules/index.md` — strategy log (including not-applicable reasons) "
                + "and compartment table\n");
        sb.append("- `modules/<slug>/*.c` — Read-budget files inside each compartment "
                + "(named by first-function address); each function has a header "
                + "with calls/callers and a resolvable `ghidra://function/...` uri\n");
        sb.append("- `index/by-address.tsv` — complete address → file map "
                + "(failed decompiles still appear); `ifp` column is a "
                + "DB-cheap input fingerprint for reconcile without re-decompiling\n");
        sb.append("- `index/partitions.json` — how the sweep grouped the program\n");
        sb.append("- `STATUS.md` — trustworthiness without talking to Ghidra\n");
        return sb.toString();
    }

    /** A module directory left without members (its last function removed) goes. */
    private static void deleteEmptyModules(Checkout checkout, Set<String> slugs) throws IOException {
        Path modules = checkout.root().path().resolve("modules");
        if (!Files.isDirectory(modules)) {
            return;
        }
        try (DirectoryStream<Path> dirs = Files.newDirectoryStream(modules, Files::isDirectory)) {
            for (Path dir : dirs) {
                if (!slugs.contains(dir.getFileName().toString())) {
                    TreeFiles.deleteModuleDir(dir);
                }
            }
        }
    }

    /**
     * True when almost every name is Ghidra's own, which makes name-based Grep useless:
     * measured, {@code ls} carries 12 real names across 25,231 functions.
     */
    static boolean isStripped(Program program) {
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
}
