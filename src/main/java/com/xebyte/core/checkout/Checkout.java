package com.xebyte.core.checkout;

import java.util.Objects;

/**
 * One registered checkout: identity, display name, config, progress, and root.
 *
 * <p>Must <em>not</em> hold a {@code ghidra.program.model.listing.Program}
 * reference — that would pin a {@code ProgramDB} and break program close.
 * The key stores domain path and root as strings only; callers re-resolve
 * through {@code ProgramProvider} when they need a live Program. Only a
 * running sweep job pins via {@code addConsumer}/{@code release}.
 */
public final class Checkout {

    private final CheckoutKey key;
    private final String programName;
    private final CheckoutRoot root;
    private volatile CheckoutConfig config;
    private volatile SweepProgress progress;
    /** Program modification number at its last save (or clean open); null while unknown. */
    private volatile Long savedAtModification;
    /** The tree went stale when its program closed; reconcile in full when it reopens. */
    private volatile boolean recoverOnReattach;
    /** Names given to symbols since the last save: what a discarded session may leave behind. */
    private final java.util.Set<String> namesSinceSave = java.util.concurrent.ConcurrentHashMap.newKeySet();

    /**
     * Held by every writer of the tree (a sweep, a reconcile) for its whole run. Each reads the
     * index and files, computes, then writes; two at once each work from a view the other is
     * changing, and the later write undoes the earlier one. Measured: a refresh racing the
     * full reconcile an adoption queues left deleted files unrestored.
     */
    private final java.util.concurrent.locks.ReentrantLock treeLock =
            new java.util.concurrent.locks.ReentrantLock();

    public java.util.concurrent.locks.ReentrantLock treeLock() {
        return treeLock;
    }

    public Checkout(CheckoutKey key, String programName, CheckoutConfig config, CheckoutRoot root) {
        this.key = Objects.requireNonNull(key, "key");
        this.programName = Objects.requireNonNull(programName, "programName");
        this.root = Objects.requireNonNull(root, "root");
        this.config = Objects.requireNonNull(config, "config");
        this.progress = SweepProgress.idle();
    }

    public CheckoutKey key() {
        return key;
    }

    public String id() {
        return key.id();
    }

    public String programName() {
        return programName;
    }

    public String domainPath() {
        return key.domainPath();
    }

    public CheckoutRoot root() {
        return root;
    }

    public CheckoutConfig config() {
        return config;
    }

    public void setConfig(CheckoutConfig config) {
        this.config = Objects.requireNonNull(config, "config");
    }

    public SweepProgress progress() {
        return progress;
    }

    public void setProgress(SweepProgress progress) {
        this.progress = Objects.requireNonNull(progress, "progress");
    }

    public Long savedAtModification() {
        return savedAtModification;
    }

    public void setSavedAtModification(Long modification) {
        this.savedAtModification = modification;
    }

    public java.util.Set<String> namesSinceSave() {
        return namesSinceSave;
    }

    public boolean recoverOnReattach() {
        return recoverOnReattach;
    }

    public void setRecoverOnReattach(boolean recover) {
        this.recoverOnReattach = recover;
    }
}
