package com.xebyte.core.checkout;

import com.xebyte.headless.HeadlessPaths;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;

/**
 * Identity of one checkout: normalised domain-file path plus normalised root.
 *
 * <p>The id is <em>derived</em> ({@code co_} + first 8 hex of SHA-256 of the
 * key), never stored. That is what makes disk adoption work across a Ghidra
 * restart with no global index: the same program + root re-derives the same
 * directory and finds {@code checkout.json}.
 *
 * <p>The domain path is what separates {@code /Vanilla/1.13d/D2Common.dll}
 * from {@code /Mods/PD2-S12/D2Common.dll} — same basename, different
 * checkouts. The root is in the key because two checkouts of one program
 * with different exclusions (hence different roots) are legitimate.
 */
public final class CheckoutKey {

    private final String domainPath;
    private final String rootPath;

    private CheckoutKey(String domainPath, String rootPath) {
        this.domainPath = domainPath;
        this.rootPath = rootPath;
    }

    public static CheckoutKey of(String domainPath, String rootPath) {
        Objects.requireNonNull(domainPath, "domainPath");
        Objects.requireNonNull(rootPath, "rootPath");
        return new CheckoutKey(normaliseDomainPath(domainPath), normaliseRootPath(rootPath));
    }

    public static CheckoutKey of(String domainPath, Path rootPath) {
        Objects.requireNonNull(rootPath, "rootPath");
        return of(domainPath, rootPath.toString());
    }

    /** Normalised {@code domainPath|rootPath} material hashed for {@link #id()}. */
    public String key() {
        return domainPath + "|" + rootPath;
    }

    /**
     * Derived checkout id. Recomputed every call so adoption never depends on
     * a persisted id field going stale.
     */
    public String id() {
        return "co_" + shortHash();
    }

    /**
     * On-disk directory name: {@code safeBasename(programName)-}{@shortHash}.
     * Basename alone is not unique across project folders; the hash is.
     */
    public String directoryName(String programName) {
        return HeadlessPaths.safeBasename(programName) + "-" + shortHash();
    }

    public String domainPath() {
        return domainPath;
    }

    public String rootPath() {
        return rootPath;
    }

    public String shortHash() {
        return sha256Hex(key()).substring(0, 8);
    }

    static String normaliseDomainPath(String path) {
        String n = path.replace('\\', '/').trim();
        if (n.isEmpty()) {
            throw new IllegalArgumentException("domainPath must not be blank");
        }
        while (n.contains("//")) {
            n = n.replace("//", "/");
        }
        return n;
    }

    static String normaliseRootPath(String path) {
        return Path.of(path).toAbsolutePath().normalize().toString();
    }

    private static String sha256Hex(String material) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(material.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is required by the JRE; this is unreachable in practice.
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof CheckoutKey that)) {
            return false;
        }
        return domainPath.equals(that.domainPath) && rootPath.equals(that.rootPath);
    }

    @Override
    public int hashCode() {
        return Objects.hash(domainPath, rootPath);
    }

    @Override
    public String toString() {
        return "CheckoutKey{id=" + id() + ", key=" + key() + "}";
    }
}
