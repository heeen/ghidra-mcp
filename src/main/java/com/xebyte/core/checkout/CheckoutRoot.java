package com.xebyte.core.checkout;

import com.xebyte.core.SecurityConfig;
import com.xebyte.core.SafePaths;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Objects;

/**
 * Resolved checkout root plus safe, recreate-tolerant writing.
 *
 * <p>Default roots live under {@code java.io.tmpdir/ghidra-mcp-checkout/},
 * deliberately <em>not</em> {@code Application.getUserTempDirectory()} —
 * Ghidra caches a handle to a directory that can be deleted out from under a
 * running process (measured), after which imports fail with a misleading
 * "No such file or directory". Every write therefore
 * {@link Files#createDirectories} first; if the root has vanished since it was
 * established, {@link #rootRecreated()} increments so silent healing is
 * visible. A {@link NoSuchFileException} mid-write recreates once and retries.
 */
public final class CheckoutRoot {

    private final Path root;
    private int rootRecreated;
    /** True after the first successful ensure/write — distinguishes create from recreate. */
    private boolean established;

    private CheckoutRoot(Path root) {
        this.root = root.toAbsolutePath().normalize();
    }

    /**
     * Explicit caller-supplied root. Routed through
     * {@link SecurityConfig#resolveWithinFileRoot(String)}; when
     * {@code files.root} is unset that returns the path unconstrained,
     * so we also require the input to be absolute (relative roots silently
     * binding to cwd are never what an agent meant).
     *
     * @throws IllegalArgumentException when the path is rejected
     */
    public static CheckoutRoot explicit(String path) {
        Objects.requireNonNull(path, "path");
        String trimmed = path.trim();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException("checkout root must not be blank");
        }
        Path input = Path.of(trimmed);
        if (!input.isAbsolute()) {
            // Unconditional, not merely a stand-in for an unset allow-list: a
            // relative root binds to the server process's cwd, which is never
            // where the caller meant and is not visible to them.
            throw new IllegalArgumentException(
                    "checkout root must be an absolute path: " + trimmed);
        }
        Path resolved = SecurityConfig.getInstance().resolveWithinFileRoot(trimmed);
        if (resolved == null) {
            throw new IllegalArgumentException(
                    "checkout root escapes files.root: " + trimmed);
        }
        return new CheckoutRoot(resolved);
    }

    /**
     * Default root: {@code ${java.io.tmpdir}/ghidra-mcp-checkout/<dirName>}.
     */
    public static CheckoutRoot defaultRoot(String dirName) {
        Objects.requireNonNull(dirName, "dirName");
        if (dirName.isBlank() || dirName.contains("/") || dirName.contains("\\")
                || dirName.contains("..")) {
            throw new IllegalArgumentException("invalid checkout directory name: " + dirName);
        }
        Path root = Path.of(System.getProperty("java.io.tmpdir"), "ghidra-mcp-checkout", dirName);
        return new CheckoutRoot(root);
    }

    /** Already-resolved absolute root (tests and registry default-path wiring). */
    public static CheckoutRoot ofResolved(Path root) {
        return new CheckoutRoot(root);
    }

    public Path path() {
        return root;
    }

    /** Times this root was recreated after vanishing mid-write. */
    public synchronized int rootRecreated() {
        return rootRecreated;
    }

    public void writeFile(Path relative, String content) throws IOException {
        writeFile(relative, content.getBytes(StandardCharsets.UTF_8));
    }

    public void writeFile(Path relative, byte[] content) throws IOException {
        Objects.requireNonNull(relative, "relative");
        Objects.requireNonNull(content, "content");
        if (relative.isAbsolute()) {
            throw new IllegalArgumentException("relative path must not be absolute: " + relative);
        }
        try {
            writeFileOnce(relative, content);
        } catch (NoSuchFileException first) {
            // TOCTOU: directory vanished between createDirectories and write.
            recreateRoot();
            try {
                writeFileOnce(relative, content);
            } catch (NoSuchFileException second) {
                throw new IOException(
                        "checkout root vanished and recreate failed: " + root, second);
            }
        }
    }

    private void writeFileOnce(Path relative, byte[] content) throws IOException {
        Path target = root.resolve(relative).normalize();
        if (!SafePaths.isWithin(root.toFile(), target.toFile())) {
            throw new SecurityException(
                    "checkout write escapes root: " + relative + " (root=" + root + ")");
        }
        ensureParentForWrite(target);
        // Re-check after createDirectories: a symlink race could have moved us.
        if (!SafePaths.isWithin(root.toFile(), target.toFile())) {
            throw new SecurityException(
                    "checkout write escapes root after createDirectories: " + relative);
        }
        Path tmp = target.resolveSibling(target.getFileName().toString() + ".tmp");
        try {
            Files.write(tmp, content);
            try {
                Files.move(tmp, target,
                        StandardCopyOption.REPLACE_EXISTING,
                        StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException e) {
            try {
                Files.deleteIfExists(tmp);
            } catch (IOException ignored) {
                // Best-effort cleanup; the original failure is what matters.
            }
            throw e;
        }
    }

    private void ensureParentForWrite(Path target) throws IOException {
        synchronized (this) {
            if (established && !Files.isDirectory(root)) {
                rootRecreated++;
            }
        }
        Path parent = target.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        } else {
            Files.createDirectories(root);
        }
        synchronized (this) {
            established = true;
        }
    }

    private synchronized void recreateRoot() throws IOException {
        Files.createDirectories(root);
        rootRecreated++;
        established = true;
    }

    /** Ensure the root directory exists (e.g. before first status write). */
    public void ensureExists() throws IOException {
        Files.createDirectories(root);
        synchronized (this) {
            established = true;
        }
    }

    /**
     * Delete the entire tree when it is still contained in this root.
     * Used by {@code /decompile_checkout_delete?delete_files=true}.
     */
    public void deleteTree() throws IOException {
        if (!Files.exists(root)) {
            return;
        }
        Files.walkFileTree(root, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs)
                    throws IOException {
                if (!SafePaths.isWithin(root.toFile(), file.toFile())) {
                    throw new SecurityException("refusing to delete escaped path: " + file);
                }
                Files.deleteIfExists(file);
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult postVisitDirectory(Path dir, IOException exc)
                    throws IOException {
                if (exc != null) {
                    throw exc;
                }
                Files.deleteIfExists(dir);
                return FileVisitResult.CONTINUE;
            }
        });
    }
}
