package com.xebyte.core.checkout;

import com.xebyte.core.FunctionFacts;
import ghidra.program.model.listing.Function;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * {@code index/addresses.tsv}: every address a function in the tree uses, one row per
 * (address, kind, via, function). {@code grep 0x40003c0c index/addresses.tsv} names the
 * functions that touch a register, however their C spells it: through a literal-pool word
 * ({@code pointer}, with the word in {@code via}), or as base + offset ({@code load} /
 * {@code store}). The rows are {@link FunctionFacts#addressRefs}, the same source as each
 * block's {@code // refs:} line and {@code get_functions}' {@code refs}, uncapped.
 *
 * <p>The sweep writes it whole; every pass that rewrites blocks replaces those functions'
 * rows ({@link #update}), and a removed function's rows go with its block.
 */
public final class AddressIndex {

    static final String HEADER = "address\tkind\tvia\tfunction\tentry\n";

    private AddressIndex() {
    }

    /** One row. {@code address} and {@code via} are {@code 0x...}; {@code entry} is bare hex, as in by-address.tsv. */
    public record Row(String address, String kind, String via, String function, String entry) {
    }

    private static final Comparator<Row> ORDER = Comparator.comparing(Row::address)
            .thenComparing(Row::entry).thenComparing(Row::kind).thenComparing(Row::via);

    /** {@code func}'s rows. */
    public static List<Row> rows(Function func, List<FunctionFacts.AddressRef> refs) {
        String entry = func.getEntryPoint().toString(false);
        List<Row> out = new ArrayList<>(refs.size());
        for (FunctionFacts.AddressRef r : refs) {
            out.add(new Row("0x" + r.address().toString(false), r.kind(),
                    r.via() != null ? "0x" + r.via().toString(false) : "", func.getName(), entry));
        }
        return out;
    }

    public static String render(Collection<Row> rows) {
        List<Row> sorted = new ArrayList<>(rows);
        sorted.sort(ORDER);
        StringBuilder sb = new StringBuilder(HEADER);
        for (Row r : sorted) {
            sb.append(r.address()).append('\t').append(r.kind()).append('\t').append(r.via())
                    .append('\t').append(r.function()).append('\t').append(r.entry()).append('\n');
        }
        return sb.toString();
    }

    public static List<Row> parse(String text) {
        List<Row> out = new ArrayList<>();
        for (String line : text.split("\n")) {
            if (line.isEmpty() || line.equals(HEADER.strip())) {
                continue;
            }
            String[] f = line.split("\t", -1);
            if (f.length == 5) {
                out.add(new Row(f[0], f[1], f[2], f[3], f[4]));
            }
        }
        return out;
    }

    /** Write the whole index (the sweep). */
    public static void write(Checkout checkout, Collection<Row> rows) throws IOException {
        checkout.root().writeFile(Path.of(CheckoutLayout.addressesTsv()), render(rows));
    }

    /**
     * Replace the rows of the functions in {@code replaced}, keyed by bare entry hex. A tree
     * swept before this index existed has none; it is left alone until the next sweep rather
     * than given a partial one that reads as complete.
     */
    public static void update(Checkout checkout, Map<String, List<Row>> replaced) throws IOException {
        if (replaced.isEmpty()) {
            return;
        }
        List<Row> existing = read(checkout);
        if (existing == null) {
            return;
        }
        List<Row> kept = new ArrayList<>();
        for (Row r : existing) {
            if (!replaced.containsKey(r.entry())) {
                kept.add(r);
            }
        }
        replaced.values().forEach(kept::addAll);
        write(checkout, kept);
    }

    /** Drop the rows of functions no longer in the tree ({@code entries}: bare entry hex). */
    public static void retain(Checkout checkout, Set<String> entries) throws IOException {
        List<Row> existing = read(checkout);
        if (existing == null) {
            return;
        }
        List<Row> kept = new ArrayList<>();
        for (Row r : existing) {
            if (entries.contains(r.entry())) {
                kept.add(r);
            }
        }
        if (kept.size() != existing.size()) {
            write(checkout, kept);
        }
    }

    private static List<Row> read(Checkout checkout) throws IOException {
        Path path = checkout.root().path().resolve(CheckoutLayout.addressesTsv());
        return Files.isRegularFile(path) ? parse(Files.readString(path, StandardCharsets.UTF_8)) : null;
    }
}
