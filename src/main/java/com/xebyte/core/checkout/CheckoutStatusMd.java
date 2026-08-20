package com.xebyte.core.checkout;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Locale;

/**
 * STATUS.md renderer — shared by create/start/stop endpoints and {@link SweepJob}.
 *
 * <p>Answers "is this tree trustworthy?" with zero Ghidra calls. Written
 * <em>before</em> a sweep as {@code dirty} and again after as
 * {@code clean}/{@code cancelled}/{@code failed}; a crash leaves {@code dirty}.
 */
public final class CheckoutStatusMd {

    private CheckoutStatusMd() {
    }

    public static String stateForPhase(SweepProgress.Phase phase) {
        return switch (phase) {
            case QUEUED, WAITING_FOR_ANALYSIS, PARTITIONING, DECOMPILING -> "dirty";
            case COMPLETE -> "clean";
            case CANCELLED -> "cancelled";
            case FAILED -> "failed";
            case STALE -> "dirty";
            case IDLE -> "empty";
        };
    }

    public static String render(Checkout checkout, String state, Long sweptAtModificationNumber) {
        SweepProgress p = checkout.progress();
        StringBuilder sb = new StringBuilder();
        sb.append("# Checkout STATUS\n\n");
        sb.append("state: ").append(state).append('\n');
        sb.append("phase: ").append(p.phase().name().toLowerCase(Locale.ROOT)).append('\n');
        sb.append("checkout_id: ").append(checkout.id()).append('\n');
        sb.append("swept_at_modification_number: ")
                .append(sweptAtModificationNumber != null ? sweptAtModificationNumber : "")
                .append('\n');
        sb.append("functions_total: ").append(p.functionsTotal()).append('\n');
        sb.append("functions_done: ").append(p.functionsDone()).append('\n');
        sb.append("functions_failed: ").append(p.functionsFailed()).append('\n');
        sb.append("bytes_written: ").append(p.bytesWritten()).append('\n');
        sb.append("updated: ").append(Instant.now()).append('\n');
        return sb.toString();
    }

    public static void write(Checkout checkout, String state, Long sweptAtModificationNumber)
            throws IOException {
        checkout.root().writeFile(
                Path.of(CheckoutLayout.statusMd()),
                render(checkout, state, sweptAtModificationNumber));
    }
}
