package com.xebyte.core.checkout;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Immutable, lock-free progress snapshot for a checkout sweep.
 *
 * <p>Swapped onto a {@code volatile} field so {@code /decompile_checkout_status} never
 * needs a lock. {@code statusRevision} is monotonic and is the bridge poller's
 * change key — bump it on every swap.
 *
 * <p>{@code eligibleFunctions} is {@link com.xebyte.core.partition.PartitionContext}'s
 * floor; {@code functionsInScope} is after exclusion/includeOnly. Reporting both
 * makes a surprising exclusion visible rather than mysterious.
 *
 * <p>{@code splicedSinceSweep} counts insert+remove since the last full sweep.
 * Containment placement is a local approximation of a global decision — this
 * number makes the drift visible. It must never trigger an auto-resweep.
 */
public record SweepProgress(
        Phase phase,
        int functionsTotal,
        int functionsDone,
        int functionsFailed,
        long bytesWritten,
        String currentPartition,
        long startedEpochMs,
        Long etaSeconds,
        int rootRecreated,
        String lastError,
        long statusRevision,
        int eligibleFunctions,
        int functionsInScope,
        Map<String, Integer> exclusionRemovals,
        int splicedSinceSweep,
        int disassembledOnDemand,
        int disassemblyFailed,
        int bodiesRecomputed,
        int bodyRecomputeFailed) {

    public enum Phase {
        IDLE,
        QUEUED,
        WAITING_FOR_ANALYSIS,
        PARTITIONING,
        DECOMPILING,
        COMPLETE,
        CANCELLED,
        FAILED,
        STALE
    }

    public SweepProgress {
        if (phase == null) {
            phase = Phase.IDLE;
        }
        if (functionsTotal < 0) {
            functionsTotal = 0;
        }
        if (functionsDone < 0) {
            functionsDone = 0;
        }
        if (functionsFailed < 0) {
            functionsFailed = 0;
        }
        if (bytesWritten < 0) {
            bytesWritten = 0;
        }
        if (rootRecreated < 0) {
            rootRecreated = 0;
        }
        if (statusRevision < 0) {
            statusRevision = 0;
        }
        if (eligibleFunctions < 0) {
            eligibleFunctions = 0;
        }
        if (functionsInScope < 0) {
            functionsInScope = 0;
        }
        if (splicedSinceSweep < 0) {
            splicedSinceSweep = 0;
        }
        if (disassembledOnDemand < 0) {
            disassembledOnDemand = 0;
        }
        if (disassemblyFailed < 0) {
            disassemblyFailed = 0;
        }
        if (bodiesRecomputed < 0) {
            bodiesRecomputed = 0;
        }
        if (bodyRecomputeFailed < 0) {
            bodyRecomputeFailed = 0;
        }
        exclusionRemovals = exclusionRemovals == null
                ? Map.of()
                : Map.copyOf(exclusionRemovals);
    }

    public static SweepProgress idle() {
        return new SweepProgress(
                Phase.IDLE, 0, 0, 0, 0L, null, 0L, null, 0, null, 0L,
                0, 0, Map.of(), 0, 0, 0, 0, 0);
    }

    public SweepProgress withPhase(Phase newPhase) {
        return copy(newPhase, functionsTotal, functionsDone, functionsFailed, bytesWritten,
                currentPartition, startedEpochMs, etaSeconds, rootRecreated, lastError,
                eligibleFunctions, functionsInScope, exclusionRemovals, splicedSinceSweep,
                disassembledOnDemand, disassemblyFailed, bodiesRecomputed, bodyRecomputeFailed);
    }

    public SweepProgress withCounts(int total, int done, int failed) {
        return copy(phase, total, done, failed, bytesWritten,
                currentPartition, startedEpochMs, etaSeconds, rootRecreated, lastError,
                eligibleFunctions, functionsInScope, exclusionRemovals, splicedSinceSweep,
                disassembledOnDemand, disassemblyFailed, bodiesRecomputed, bodyRecomputeFailed);
    }

    public SweepProgress withBytesWritten(long bytes) {
        return copy(phase, functionsTotal, functionsDone, functionsFailed, bytes,
                currentPartition, startedEpochMs, etaSeconds, rootRecreated, lastError,
                eligibleFunctions, functionsInScope, exclusionRemovals, splicedSinceSweep,
                disassembledOnDemand, disassemblyFailed, bodiesRecomputed, bodyRecomputeFailed);
    }

    public SweepProgress withCurrentPartition(String partition) {
        return copy(phase, functionsTotal, functionsDone, functionsFailed, bytesWritten,
                partition, startedEpochMs, etaSeconds, rootRecreated, lastError,
                eligibleFunctions, functionsInScope, exclusionRemovals, splicedSinceSweep,
                disassembledOnDemand, disassemblyFailed, bodiesRecomputed, bodyRecomputeFailed);
    }

    public SweepProgress withStartedEpochMs(long epochMs) {
        return copy(phase, functionsTotal, functionsDone, functionsFailed, bytesWritten,
                currentPartition, epochMs, etaSeconds, rootRecreated, lastError,
                eligibleFunctions, functionsInScope, exclusionRemovals, splicedSinceSweep,
                disassembledOnDemand, disassemblyFailed, bodiesRecomputed, bodyRecomputeFailed);
    }

    public SweepProgress withEtaSeconds(Long eta) {
        return copy(phase, functionsTotal, functionsDone, functionsFailed, bytesWritten,
                currentPartition, startedEpochMs, eta, rootRecreated, lastError,
                eligibleFunctions, functionsInScope, exclusionRemovals, splicedSinceSweep,
                disassembledOnDemand, disassemblyFailed, bodiesRecomputed, bodyRecomputeFailed);
    }

    public SweepProgress withRootRecreated(int count) {
        return copy(phase, functionsTotal, functionsDone, functionsFailed, bytesWritten,
                currentPartition, startedEpochMs, etaSeconds, count, lastError,
                eligibleFunctions, functionsInScope, exclusionRemovals, splicedSinceSweep,
                disassembledOnDemand, disassemblyFailed, bodiesRecomputed, bodyRecomputeFailed);
    }

    public SweepProgress withLastError(String error) {
        return copy(phase, functionsTotal, functionsDone, functionsFailed, bytesWritten,
                currentPartition, startedEpochMs, etaSeconds, rootRecreated, error,
                eligibleFunctions, functionsInScope, exclusionRemovals, splicedSinceSweep,
                disassembledOnDemand, disassemblyFailed, bodiesRecomputed, bodyRecomputeFailed);
    }

    public SweepProgress withScope(int eligible, int inScope, Map<String, Integer> removals) {
        Map<String, Integer> map = removals == null ? Map.of() : new LinkedHashMap<>(removals);
        return copy(phase, functionsTotal, functionsDone, functionsFailed, bytesWritten,
                currentPartition, startedEpochMs, etaSeconds, rootRecreated, lastError,
                eligible, inScope, map, splicedSinceSweep,
                disassembledOnDemand, disassemblyFailed, bodiesRecomputed, bodyRecomputeFailed);
    }

    public SweepProgress withSplicedSinceSweep(int count) {
        return copy(phase, functionsTotal, functionsDone, functionsFailed, bytesWritten,
                currentPartition, startedEpochMs, etaSeconds, rootRecreated, lastError,
                eligibleFunctions, functionsInScope, exclusionRemovals, count,
                disassembledOnDemand, disassemblyFailed, bodiesRecomputed, bodyRecomputeFailed);
    }

    public SweepProgress withDisassemblyCounts(int succeeded, int failed) {
        return copy(phase, functionsTotal, functionsDone, functionsFailed, bytesWritten,
                currentPartition, startedEpochMs, etaSeconds, rootRecreated, lastError,
                eligibleFunctions, functionsInScope, exclusionRemovals, splicedSinceSweep,
                succeeded, failed, bodiesRecomputed, bodyRecomputeFailed);
    }

    public SweepProgress withBodyReflowCounts(int recomputed, int failed) {
        return copy(phase, functionsTotal, functionsDone, functionsFailed, bytesWritten,
                currentPartition, startedEpochMs, etaSeconds, rootRecreated, lastError,
                eligibleFunctions, functionsInScope, exclusionRemovals, splicedSinceSweep,
                disassembledOnDemand, disassemblyFailed, recomputed, failed);
    }

    private SweepProgress copy(
            Phase newPhase,
            int total,
            int done,
            int failed,
            long bytes,
            String partition,
            long started,
            Long eta,
            int recreated,
            String error,
            int eligible,
            int inScope,
            Map<String, Integer> removals,
            int spliced,
            int disassembled,
            int disassemblyFailures,
            int bodies,
            int bodyFailures) {
        return new SweepProgress(
                newPhase, total, done, failed, bytes, partition, started, eta, recreated, error,
                statusRevision + 1, eligible, inScope, removals, spliced,
                disassembled, disassemblyFailures, bodies, bodyFailures);
    }
}
