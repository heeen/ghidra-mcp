package com.xebyte.offline;

import com.xebyte.core.checkout.CheckoutConfig;
import com.xebyte.core.checkout.CheckoutKey;
import com.xebyte.core.checkout.CheckoutRegistry;
import com.xebyte.core.checkout.CheckoutRoot;
import com.xebyte.headless.HeadlessPaths;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.stream.Stream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Offline tests for {@link CheckoutRoot} — containment, same-basename
 * directory divergence, recreate-and-retry, and cancel-safe atomic writes.
 */
public class CheckoutRootTest {

    private Path tempBase;

    @Before
    public void setUp() throws IOException {
        tempBase = Files.createTempDirectory("checkout-root-test");
    }

    @After
    public void tearDown() throws IOException {
        if (tempBase != null && Files.exists(tempBase)) {
            try (Stream<Path> walk = Files.walk(tempBase)) {
                walk.sorted(Comparator.reverseOrder()).forEach(p -> {
                    try {
                        Files.deleteIfExists(p);
                    } catch (IOException ignored) {
                        // best-effort
                    }
                });
            }
        }
    }

    @Test
    public void sameBasenameDifferentDomainPathsProduceDifferentDirectories() {
        Path parent = CheckoutRegistry.defaultParent();
        CheckoutKey vanilla = CheckoutKey.of("/Vanilla/1.13d/D2Common.dll", parent.toString());
        CheckoutKey mod = CheckoutKey.of("/Mods/PD2-S12/D2Common.dll", parent.toString());

        String dirA = vanilla.directoryName("D2Common.dll");
        String dirB = mod.directoryName("D2Common.dll");

        assertTrue(dirA.startsWith("D2Common.dll-"));
        assertTrue(dirB.startsWith("D2Common.dll-"));
        assertNotEquals(
                "domain path must separate same-basename checkouts",
                dirA, dirB);
        assertNotEquals(vanilla.id(), mod.id());
        assertEquals(8, vanilla.shortHash().length());
        assertTrue(dirA.endsWith(vanilla.shortHash()));
        assertTrue(dirB.endsWith(mod.shortHash()));
    }

    @Test
    public void isWithinRejectsSiblingPrefixCollision() throws IOException {
        Path exports = tempBase.resolve("exports");
        Path evil = tempBase.resolve("exports-evil");
        Files.createDirectories(exports);
        Files.createDirectories(evil);

        assertTrue(HeadlessPaths.isWithin(exports.toFile(), exports.resolve("out.c").toFile()));
        assertFalse(
                "sibling exports-evil must not count as inside exports",
                HeadlessPaths.isWithin(exports.toFile(), evil.resolve("out.c").toFile()));
    }

    @Test
    public void writeRejectsPathEscape() throws IOException {
        Path rootDir = tempBase.resolve("checkout");
        Files.createDirectories(rootDir);
        CheckoutRoot root = CheckoutRoot.ofResolved(rootDir);
        root.ensureExists();
        try {
            root.writeFile(Path.of("..", "escape.c"), "nope");
            fail("expected SecurityException for escaped write");
        } catch (SecurityException expected) {
            assertTrue(expected.getMessage().contains("escapes"));
        }
    }

    @Test
    public void recreateAndRetryWhenRootDeletedMidFlight() throws IOException {
        Path rootDir = tempBase.resolve("vanishing");
        CheckoutRoot root = CheckoutRoot.ofResolved(rootDir);
        root.ensureExists();
        root.writeFile(Path.of("STATUS.md"), "dirty\n");
        assertEquals(0, root.rootRecreated());

        // Measured failure mode: the temp tree is deleted under a running process.
        deleteRecursively(rootDir);
        assertFalse(Files.exists(rootDir));

        root.writeFile(Path.of("STATUS.md"), "recovered\n");
        assertTrue(Files.isRegularFile(rootDir.resolve("STATUS.md")));
        assertEquals(1, root.rootRecreated());
        assertEquals("recovered\n", Files.readString(rootDir.resolve("STATUS.md")));
    }

    @Test
    public void successfulWriteLeavesNoTmpBehind() throws IOException {
        Path rootDir = tempBase.resolve("atomic");
        CheckoutRoot root = CheckoutRoot.ofResolved(rootDir);
        root.ensureExists();
        root.writeFile(Path.of("modules", "c01", "00001000_Foo.c"), "int Foo(void) { return 0; }\n");

        Path written = rootDir.resolve("modules/c01/00001000_Foo.c");
        assertTrue(Files.isRegularFile(written));
        try (Stream<Path> walk = Files.walk(rootDir)) {
            long tmpCount = walk
                    .filter(p -> p.getFileName().toString().endsWith(".tmp"))
                    .count();
            assertEquals("cancel-safe write must not leave .tmp files", 0, tmpCount);
        }
    }

    @Test
    public void explicitRootRejectsRelativePath() {
        try {
            CheckoutRoot.explicit("relative/checkout");
            fail("relative root must be rejected");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("absolute"));
        }
    }

    @Test
    public void defaultsConfigRoundTripThroughExplicitRoot() throws IOException {
        Path rootDir = tempBase.resolve("explicit-co");
        Files.createDirectories(rootDir);
        CheckoutRoot root = CheckoutRoot.explicit(rootDir.toAbsolutePath().toString());
        assertEquals(rootDir.toAbsolutePath().normalize(), root.path());
        CheckoutConfig cfg = CheckoutConfig.defaults().withRootPath(root.path().toString());
        assertEquals(root.path().toString(), cfg.rootPath());
    }

    private static void deleteRecursively(Path dir) throws IOException {
        if (!Files.exists(dir)) {
            return;
        }
        try (Stream<Path> walk = Files.walk(dir)) {
            walk.sorted(Comparator.reverseOrder()).forEach(p -> {
                try {
                    Files.deleteIfExists(p);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            });
        }
    }
}
