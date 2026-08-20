package com.xebyte.core.checkout;

/**
 * One exclusion / include-only predicate for a checkout sweep.
 *
 * <p>Three kinds only — each answers something the others cannot, and all
 * evaluate per function with no extra pass. Deliberately no {@code name:}
 * regex kind: name-based filtering is cut from v1 (see the checkout plan).
 *
 * @param kind  how {@code value} is interpreted
 * @param value the tag name, partition slug, or {@code lo-hi} address range
 */
public record ExclusionRule(Kind kind, String value) {

    public enum Kind {
        TAG,
        PARTITION,
        RANGE
    }

    private static final String ACCEPTED_FORMS =
            "accepted forms: tag:<name>, partition:<slug>, range:<lo>-<hi>";

    public ExclusionRule {
        if (kind == null) {
            throw new IllegalArgumentException("kind must not be null");
        }
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("value must not be blank (" + ACCEPTED_FORMS + ")");
        }
        value = value.trim();
    }

    /**
     * Parse a compact spec such as {@code tag:LIB_CRT}, {@code partition:c07},
     * or {@code range:6fdd0000-6fde0000}.
     *
     * @throws IllegalArgumentException when the spec is malformed; the message
     *     always names the accepted forms
     */
    public static ExclusionRule parse(String spec) {
        if (spec == null || spec.isBlank()) {
            throw new IllegalArgumentException("exclusion spec must not be blank (" + ACCEPTED_FORMS + ")");
        }
        String trimmed = spec.trim();
        int colon = trimmed.indexOf(':');
        if (colon <= 0 || colon == trimmed.length() - 1) {
            throw new IllegalArgumentException(
                    "malformed exclusion spec '" + trimmed + "' (" + ACCEPTED_FORMS + ")");
        }
        String kindToken = trimmed.substring(0, colon).trim().toLowerCase();
        String value = trimmed.substring(colon + 1).trim();
        if (value.isEmpty()) {
            throw new IllegalArgumentException(
                    "malformed exclusion spec '" + trimmed + "' (" + ACCEPTED_FORMS + ")");
        }
        Kind kind = switch (kindToken) {
            case "tag" -> Kind.TAG;
            case "partition" -> Kind.PARTITION;
            case "range" -> Kind.RANGE;
            default -> throw new IllegalArgumentException(
                    "unknown exclusion kind '" + kindToken + "' (" + ACCEPTED_FORMS + ")");
        };
        if (kind == Kind.RANGE && !value.contains("-")) {
            throw new IllegalArgumentException(
                    "malformed range exclusion '" + trimmed + "' (" + ACCEPTED_FORMS + ")");
        }
        return new ExclusionRule(kind, value);
    }
}
