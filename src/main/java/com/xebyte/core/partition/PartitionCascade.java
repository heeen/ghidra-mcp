package com.xebyte.core.partition;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Runs partitioners in precedence order over a shrinking pool of functions.
 *
 * <p>Records both what was placed and what was <em>skipped and why</em>, because
 * the checkout's {@code index.md} has to be able to tell an agent that RTTI was
 * tried and found to cover 1.6% of the binary. "This strategy did not apply" is a
 * fact about the binary and belongs in the output.
 *
 * @since 7.2.0
 */
public final class PartitionCascade {

    private final List<Partitioner> partitioners;

    public PartitionCascade(List<Partitioner> partitioners) {
        this.partitioners = new ArrayList<>(partitioners);
        this.partitioners.sort(Comparator.comparingInt(Partitioner::precedence));
    }

    public Result run(PartitionContext ctx) {
        List<Partition> all = new ArrayList<>();
        Map<String, Object> log = new LinkedHashMap<>();

        for (Partitioner p : partitioners) {
            int poolBefore = ctx.size() - ctx.assignedCount();
            if (poolBefore == 0) {
                log.put(p.name(), Map.of("status", "skipped", "reason", "nothing left unassigned"));
                continue;
            }
            Applicability a = p.probe(ctx);
            if (!a.applicable()) {
                log.put(p.name(), Map.of("status", "not_applicable", "reason", a.reason()));
                continue;
            }
            List<Partition> produced = p.partition(ctx);
            int placed = 0;
            for (Partition part : produced) {
                List<Integer> idx = new ArrayList<>(part.size());
                for (var f : part.members()) {
                    Integer i = ctx.indexOf(f.getEntryPoint());
                    // Already claimed by an earlier, higher-evidence strategy: that
                    // claim wins. Overlap is expected, not an error — a class-named
                    // function is also inside some address band.
                    if (i != null && !ctx.isAssigned(i)) idx.add(i);
                }
                if (idx.isEmpty()) continue;
                ctx.markAssigned(idx);
                placed += idx.size();
                all.add(part);
            }
            log.put(p.name(), Map.of(
                    "status", "ran",
                    "expected_coverage", a.expectedCoverage(),
                    "reason", a.reason(),
                    "partitions", produced.size(),
                    "functions_placed", placed,
                    "pool_before", poolBefore));
        }
        return new Result(all, log, ctx.size(), ctx.assignedCount());
    }

    public record Result(
            List<Partition> partitions,
            Map<String, Object> strategyLog,
            int totalFunctions,
            int assignedFunctions) {
    }
}
