package com.xebyte.core.checkout;

import java.util.Objects;

/**
 * One registered checkout: identity, display name, config, progress, and root.
 *
 * <p>Must <em>not</em> hold a {@code ghidra.program.model.listing.Program}
 * reference — that would pin a {@code ProgramDB} and break program close.
 * The key stores domain path and root as strings only; callers re-resolve
 * through {@code ProgramProvider} when they need a live Program. Only a
 * running sweep job pins via {@code addConsumer}/{@code removeConsumer}.
 */
public final class Checkout {

    private final CheckoutKey key;
    private final String programName;
    private final CheckoutRoot root;
    private volatile CheckoutConfig config;
    private volatile SweepProgress progress;

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
}
