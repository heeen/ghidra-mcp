package com.xebyte.core.checkout;

import com.xebyte.core.JsonHelper;
import com.xebyte.core.partition.Partition;
import com.xebyte.core.partition.PartitionCascade;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * What a sweep decided about the program's grouping, kept as {@code index/partitions.json}:
 * the cascade's strategy log, the exclusion scope, and each compartment's method,
 * confidence and evidence.
 *
 * <p>It used to exist only rendered into markdown, so nothing after the sweep could
 * reproduce {@code modules/index.md} or a module README, and the reconciler wrote its own
 * thinner versions instead. With it persisted, every derived file is a function of this
 * and the by-address rows ({@link DerivedFiles}), whichever path wrote it.
 *
 * <p>Every value is a string (or a map of strings) from the moment it is built, so what the
 * sweep renders and what a later pass reads back from disk are the same values.
 */
public record PartitionMeta(
        int eligibleFunctions,
        int functionsInScope,
        int assignedFunctions,
        int functionsWithStrings,
        Map<String, String> removedByRule,
        Map<String, Object> strategyLog,
        List<Part> partitions) {

    /** One compartment's grouping. */
    public record Part(String slug, String method, double confidence, Map<String, String> evidence) {
    }

    static PartitionMeta of(PartitionCascade.Result cascade, List<Partition> partitions,
            ExclusionEvaluator.ScopeStats scope, int functionsWithStrings) {
        Map<String, String> removed = new LinkedHashMap<>();
        scope.removedByRule().forEach((k, v) -> removed.put(k, String.valueOf(v)));
        Map<String, Object> log = new LinkedHashMap<>();
        cascade.strategyLog().forEach((k, v) -> log.put(k, stringify(v)));
        List<Part> parts = new ArrayList<>(partitions.size());
        for (Partition p : partitions) {
            Map<String, String> evidence = new LinkedHashMap<>();
            p.evidence().forEach((k, v) -> evidence.put(k, String.valueOf(v)));
            parts.add(new Part(p.slug(), p.method(), p.confidence(), evidence));
        }
        return new PartitionMeta(scope.eligibleFunctions(), scope.functionsInScope(),
                cascade.assignedFunctions(), functionsWithStrings, removed, log, parts);
    }

    private static Object stringify(Object v) {
        if (v instanceof Map<?, ?> m) {
            Map<String, String> out = new LinkedHashMap<>();
            m.forEach((k, x) -> out.put(String.valueOf(k), String.valueOf(x)));
            return out;
        }
        return String.valueOf(v);
    }

    public Part part(String slug) {
        for (Part p : partitions) {
            if (p.slug().equals(slug)) {
                return p;
            }
        }
        return null;
    }

    // ------------------------------------------------------------------ disk

    void write(Checkout checkout) throws IOException {
        List<Map<String, Object>> parts = new ArrayList<>();
        for (Part p : partitions) {
            parts.add(JsonHelper.mapOf("slug", p.slug(), "method", p.method(),
                    "confidence", p.confidence(), "evidence", p.evidence()));
        }
        Map<String, Object> json = JsonHelper.mapOf(
                "eligible_functions", eligibleFunctions,
                "functions_in_scope", functionsInScope,
                "assigned_functions", assignedFunctions,
                "functions_with_strings", functionsWithStrings,
                "removed_by_rule", removedByRule,
                "strategy_log", strategyLog,
                "partitions", parts);
        DerivedFiles.writeIfChanged(checkout, CheckoutLayout.partitionsJson(), JsonHelper.toJson(json) + "\n");
    }

    /** The meta a sweep left, or null for a tree swept before it was kept. */
    @SuppressWarnings("unchecked")
    static PartitionMeta read(Checkout checkout) throws IOException {
        Path path = checkout.root().path().resolve(CheckoutLayout.partitionsJson());
        if (!Files.isRegularFile(path)) {
            return null;
        }
        Map<String, Object> json = JsonHelper.parseJson(Files.readString(path, StandardCharsets.UTF_8));
        if (!json.containsKey("partitions")) {
            return null;
        }
        List<Part> parts = new ArrayList<>();
        for (Object o : (List<Object>) json.get("partitions")) {
            Map<String, Object> p = (Map<String, Object>) o;
            parts.add(new Part(String.valueOf(p.get("slug")), String.valueOf(p.get("method")),
                    ((Number) p.get("confidence")).doubleValue(), strings(p.get("evidence"))));
        }
        Map<String, Object> log = new LinkedHashMap<>();
        ((Map<String, Object>) json.getOrDefault("strategy_log", Map.of())).forEach(
                (k, v) -> log.put(k, v instanceof Map<?, ?> ? strings(v) : String.valueOf(v)));
        return new PartitionMeta(
                JsonHelper.getInt(json.get("eligible_functions"), 0),
                JsonHelper.getInt(json.get("functions_in_scope"), 0),
                JsonHelper.getInt(json.get("assigned_functions"), 0),
                JsonHelper.getInt(json.get("functions_with_strings"), 0),
                strings(json.get("removed_by_rule")), log, parts);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, String> strings(Object o) {
        Map<String, String> out = new LinkedHashMap<>();
        if (o instanceof Map<?, ?> m) {
            ((Map<Object, Object>) m).forEach((k, v) -> out.put(String.valueOf(k), String.valueOf(v)));
        }
        return out;
    }
}
