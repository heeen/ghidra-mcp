package com.xebyte.core.checkout;

import java.util.List;

/**
 * Immutable sweep / layout configuration for one checkout.
 *
 * <p>Clamps on construction rather than rejecting silently: a caller that
 * asks for {@code throttlePercent=150} still gets a usable config (90), and
 * {@code bandSize=0} floors to 1 so partitioning never divides by zero.
 *
 * @param rootPath                 absolute checkout root, or {@code null} to
 *                                 use the default under {@code java.io.tmpdir}
 * @param enabledStrategies        partition strategy names; empty = full cascade
 * @param bandSize                 address-band width when bands apply (floored at 1)
 * @param exclusions               drop matching functions after partitioning
 * @param includeOnly              when non-empty, keep only matches (applied first)
 * @param throttlePercent          interactive yield 0..90 (default 10)
 * @param decompileTimeoutSeconds  per-function decompile budget
 * @param analysisWaitSeconds      cap on waiting for auto-analysis before sweeping
 */
public record CheckoutConfig(
        String rootPath,
        List<String> enabledStrategies,
        int bandSize,
        List<ExclusionRule> exclusions,
        List<ExclusionRule> includeOnly,
        int throttlePercent,
        int decompileTimeoutSeconds,
        int analysisWaitSeconds) {

    public static final int DEFAULT_BAND_SIZE = 20;
    public static final int DEFAULT_THROTTLE_PERCENT = 10;
    public static final int DEFAULT_DECOMPILE_TIMEOUT_SECONDS = 30;
    public static final int DEFAULT_ANALYSIS_WAIT_SECONDS = 600;

    public CheckoutConfig {
        enabledStrategies = enabledStrategies == null
                ? List.of()
                : List.copyOf(enabledStrategies);
        exclusions = exclusions == null ? List.of() : List.copyOf(exclusions);
        includeOnly = includeOnly == null ? List.of() : List.copyOf(includeOnly);
        bandSize = Math.max(1, bandSize);
        throttlePercent = Math.clamp(throttlePercent, 0, 90);
        if (decompileTimeoutSeconds < 1) {
            decompileTimeoutSeconds = DEFAULT_DECOMPILE_TIMEOUT_SECONDS;
        }
        if (analysisWaitSeconds < 1) {
            analysisWaitSeconds = DEFAULT_ANALYSIS_WAIT_SECONDS;
        }
        if (rootPath != null && rootPath.isBlank()) {
            rootPath = null;
        }
    }

    /** Defaults: full cascade, no exclusions, band 20, throttle 10%. */
    public static CheckoutConfig defaults() {
        return new CheckoutConfig(
                null,
                List.of(),
                DEFAULT_BAND_SIZE,
                List.of(),
                List.of(),
                DEFAULT_THROTTLE_PERCENT,
                DEFAULT_DECOMPILE_TIMEOUT_SECONDS,
                DEFAULT_ANALYSIS_WAIT_SECONDS);
    }

    public static Builder builder() {
        return new Builder();
    }

    public CheckoutConfig withRootPath(String newRootPath) {
        return new CheckoutConfig(
                newRootPath, enabledStrategies, bandSize, exclusions, includeOnly,
                throttlePercent, decompileTimeoutSeconds, analysisWaitSeconds);
    }

    public CheckoutConfig withEnabledStrategies(List<String> strategies) {
        return new CheckoutConfig(
                rootPath, strategies, bandSize, exclusions, includeOnly,
                throttlePercent, decompileTimeoutSeconds, analysisWaitSeconds);
    }

    public CheckoutConfig withBandSize(int newBandSize) {
        return new CheckoutConfig(
                rootPath, enabledStrategies, newBandSize, exclusions, includeOnly,
                throttlePercent, decompileTimeoutSeconds, analysisWaitSeconds);
    }

    public CheckoutConfig withExclusions(List<ExclusionRule> rules) {
        return new CheckoutConfig(
                rootPath, enabledStrategies, bandSize, rules, includeOnly,
                throttlePercent, decompileTimeoutSeconds, analysisWaitSeconds);
    }

    public CheckoutConfig withIncludeOnly(List<ExclusionRule> rules) {
        return new CheckoutConfig(
                rootPath, enabledStrategies, bandSize, exclusions, rules,
                throttlePercent, decompileTimeoutSeconds, analysisWaitSeconds);
    }

    public CheckoutConfig withThrottlePercent(int percent) {
        return new CheckoutConfig(
                rootPath, enabledStrategies, bandSize, exclusions, includeOnly,
                percent, decompileTimeoutSeconds, analysisWaitSeconds);
    }

    public CheckoutConfig withDecompileTimeoutSeconds(int seconds) {
        return new CheckoutConfig(
                rootPath, enabledStrategies, bandSize, exclusions, includeOnly,
                throttlePercent, seconds, analysisWaitSeconds);
    }

    public CheckoutConfig withAnalysisWaitSeconds(int seconds) {
        return new CheckoutConfig(
                rootPath, enabledStrategies, bandSize, exclusions, includeOnly,
                throttlePercent, decompileTimeoutSeconds, seconds);
    }

    public static final class Builder {
        private String rootPath;
        private List<String> enabledStrategies = List.of();
        private int bandSize = DEFAULT_BAND_SIZE;
        private List<ExclusionRule> exclusions = List.of();
        private List<ExclusionRule> includeOnly = List.of();
        private int throttlePercent = DEFAULT_THROTTLE_PERCENT;
        private int decompileTimeoutSeconds = DEFAULT_DECOMPILE_TIMEOUT_SECONDS;
        private int analysisWaitSeconds = DEFAULT_ANALYSIS_WAIT_SECONDS;

        public Builder rootPath(String rootPath) {
            this.rootPath = rootPath;
            return this;
        }

        public Builder enabledStrategies(List<String> enabledStrategies) {
            this.enabledStrategies = enabledStrategies;
            return this;
        }

        public Builder bandSize(int bandSize) {
            this.bandSize = bandSize;
            return this;
        }

        public Builder exclusions(List<ExclusionRule> exclusions) {
            this.exclusions = exclusions;
            return this;
        }

        public Builder includeOnly(List<ExclusionRule> includeOnly) {
            this.includeOnly = includeOnly;
            return this;
        }

        public Builder throttlePercent(int throttlePercent) {
            this.throttlePercent = throttlePercent;
            return this;
        }

        public Builder decompileTimeoutSeconds(int decompileTimeoutSeconds) {
            this.decompileTimeoutSeconds = decompileTimeoutSeconds;
            return this;
        }

        public Builder analysisWaitSeconds(int analysisWaitSeconds) {
            this.analysisWaitSeconds = analysisWaitSeconds;
            return this;
        }

        public CheckoutConfig build() {
            return new CheckoutConfig(
                    rootPath,
                    enabledStrategies,
                    bandSize,
                    exclusions,
                    includeOnly,
                    throttlePercent,
                    decompileTimeoutSeconds,
                    analysisWaitSeconds);
        }
    }
}
