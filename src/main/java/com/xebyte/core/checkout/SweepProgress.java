package com.xebyte.core.checkout;

/**
 * Immutable, lock-free progress snapshot for a checkout sweep.
 *
 * <p>Swapped onto a {@code volatile} field so {@code /checkout_status} never
 * needs a lock. {@code statusRevision} is monotonic and is the bridge poller's
 * change key — bump it on every swap.
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
        long statusRevision) {

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
    }

    public static SweepProgress idle() {
        return new SweepProgress(
                Phase.IDLE, 0, 0, 0, 0L, null, 0L, null, 0, null, 0L);
    }

    public SweepProgress withPhase(Phase newPhase) {
        return copy(newPhase, functionsTotal, functionsDone, functionsFailed, bytesWritten,
                currentPartition, startedEpochMs, etaSeconds, rootRecreated, lastError);
    }

    public SweepProgress withCounts(int total, int done, int failed) {
        return copy(phase, total, done, failed, bytesWritten,
                currentPartition, startedEpochMs, etaSeconds, rootRecreated, lastError);
    }

    public SweepProgress withBytesWritten(long bytes) {
        return copy(phase, functionsTotal, functionsDone, functionsFailed, bytes,
                currentPartition, startedEpochMs, etaSeconds, rootRecreated, lastError);
    }

    public SweepProgress withCurrentPartition(String partition) {
        return copy(phase, functionsTotal, functionsDone, functionsFailed, bytesWritten,
                partition, startedEpochMs, etaSeconds, rootRecreated, lastError);
    }

    public SweepProgress withStartedEpochMs(long epochMs) {
        return copy(phase, functionsTotal, functionsDone, functionsFailed, bytesWritten,
                currentPartition, epochMs, etaSeconds, rootRecreated, lastError);
    }

    public SweepProgress withEtaSeconds(Long eta) {
        return copy(phase, functionsTotal, functionsDone, functionsFailed, bytesWritten,
                currentPartition, startedEpochMs, eta, rootRecreated, lastError);
    }

    public SweepProgress withRootRecreated(int count) {
        return copy(phase, functionsTotal, functionsDone, functionsFailed, bytesWritten,
                currentPartition, startedEpochMs, etaSeconds, count, lastError);
    }

    public SweepProgress withLastError(String error) {
        return copy(phase, functionsTotal, functionsDone, functionsFailed, bytesWritten,
                currentPartition, startedEpochMs, etaSeconds, rootRecreated, error);
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
            String error) {
        return new SweepProgress(
                newPhase, total, done, failed, bytes, partition, started, eta, recreated, error,
                statusRevision + 1);
    }
}
