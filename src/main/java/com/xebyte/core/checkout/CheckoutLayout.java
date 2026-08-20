package com.xebyte.core.checkout;

import java.util.Locale;

/**
 * Pure path and filename generation for a checkout tree.
 *
 * <p>No Ghidra imports — take pointer size in bytes so offline tests can pin
 * lexical-order == address-order without a Program. Filenames are deliberately
 * not rename-stable: a stale path after a rename gives a loud ENOENT instead
 * of silently serving the wrong function.
 */
public final class CheckoutLayout {

    public static final int MAX_SANITISED_NAME_LENGTH = 96;

    private CheckoutLayout() {
    }

    /**
     * {@code <zero-padded-address>_<SanitisedName>.c} — collision-free by
     * construction; zero-padding makes lexical sort match address order.
     *
     * @param address           function entry as an unsigned offset
     * @param functionName      raw Ghidra / demangled name
     * @param pointerSizeBytes  program pointer size ({@code 4} or {@code 8});
     *                          hex width is {@code pointerSizeBytes * 2}
     */
    public static String functionFileName(long address, String functionName, int pointerSizeBytes) {
        int hexWidth = Math.max(1, pointerSizeBytes) * 2;
        String hex = String.format(Locale.ROOT, "%0" + hexWidth + "x", address);
        // Cap at hexWidth in case a larger address was passed (mask not applied).
        if (hex.length() > hexWidth) {
            hex = hex.substring(hex.length() - hexWidth);
        }
        return hex + "_" + sanitiseName(functionName) + ".c";
    }

    /**
     * Keep {@code [A-Za-z0-9_.-]}; collapse any other run to a single {@code _};
     * truncate to {@link #MAX_SANITISED_NAME_LENGTH}.
     */
    public static String sanitiseName(String name) {
        if (name == null || name.isEmpty()) {
            return "unnamed";
        }
        StringBuilder out = new StringBuilder(name.length());
        boolean lastWasSep = false;
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if (isSafe(c)) {
                out.append(c);
                lastWasSep = false;
            } else if (!lastWasSep) {
                out.append('_');
                lastWasSep = true;
            }
        }
        String result = out.toString();
        // Trim leading/trailing underscores produced by leading operators etc.
        while (result.startsWith("_")) {
            result = result.substring(1);
        }
        while (result.endsWith("_")) {
            result = result.substring(0, result.length() - 1);
        }
        if (result.isEmpty()) {
            result = "unnamed";
        }
        if (result.length() > MAX_SANITISED_NAME_LENGTH) {
            result = result.substring(0, MAX_SANITISED_NAME_LENGTH);
        }
        return result;
    }

    private static boolean isSafe(char c) {
        return (c >= 'A' && c <= 'Z')
                || (c >= 'a' && c <= 'z')
                || (c >= '0' && c <= '9')
                || c == '_' || c == '.' || c == '-';
    }

    public static String checkoutJson() {
        return "checkout.json";
    }

    public static String statusMd() {
        return "STATUS.md";
    }

    public static String readmeMd() {
        return "README.md";
    }

    public static String modulesIndexMd() {
        return "modules/index.md";
    }

    public static String moduleReadme(String slug) {
        return "modules/" + requireSlug(slug) + "/README.md";
    }

    public static String moduleFunctionFile(String slug, String fileName) {
        return "modules/" + requireSlug(slug) + "/" + requireFileName(fileName);
    }

    public static String byAddressTsv() {
        return "index/by-address.tsv";
    }

    public static String callgraphTsv() {
        return "callgraph.tsv";
    }

    public static String stringsTxt() {
        return "strings.txt";
    }

    public static String globalsTxt() {
        return "globals.txt";
    }

    private static String requireSlug(String slug) {
        if (slug == null || slug.isBlank()) {
            throw new IllegalArgumentException("module slug must not be blank");
        }
        if (slug.indexOf('/') >= 0 || slug.indexOf('\\') >= 0 || slug.contains("..")) {
            throw new IllegalArgumentException("module slug must be a plain name: " + slug);
        }
        return slug;
    }

    private static String requireFileName(String fileName) {
        if (fileName == null || fileName.isBlank()) {
            throw new IllegalArgumentException("file name must not be blank");
        }
        if (fileName.indexOf('/') >= 0 || fileName.indexOf('\\') >= 0) {
            throw new IllegalArgumentException("file name must not contain separators: " + fileName);
        }
        return fileName;
    }
}
