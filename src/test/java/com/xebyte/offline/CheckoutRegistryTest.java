package com.xebyte.offline;

import com.xebyte.core.checkout.Checkout;
import com.xebyte.core.checkout.CheckoutConfig;
import com.xebyte.core.checkout.CheckoutKey;
import com.xebyte.core.checkout.CheckoutRegistry;
import com.xebyte.core.checkout.CheckoutRoot;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

/**
 * Offline tests for {@link CheckoutRegistry} — singleton shape, resolve
 * ambiguity, and the single-thread enqueue hook.
 */
public class CheckoutRegistryTest {

    private Path tempA;
    private Path tempB;

    @Before
    public void setUp() throws IOException {
        CheckoutRegistry.getInstance().clearForTests();
        tempA = Files.createTempDirectory("checkout-reg-a");
        tempB = Files.createTempDirectory("checkout-reg-b");
    }

    @After
    public void tearDown() throws IOException {
        CheckoutRegistry.getInstance().clearForTests();
        deleteRecursively(tempA);
        deleteRecursively(tempB);
    }

    @Test
    public void getInstanceIsStableSingleton() {
        assertSame(CheckoutRegistry.getInstance(), CheckoutRegistry.getInstance());
    }

    @Test
    public void resolveAmbiguityNamesBothCandidates() throws IOException {
        CheckoutRegistry registry = CheckoutRegistry.getInstance();

        CheckoutConfig cfgA = CheckoutConfig.defaults()
                .withRootPath(tempA.toAbsolutePath().toString());
        CheckoutConfig cfgB = CheckoutConfig.defaults()
                .withRootPath(tempB.toAbsolutePath().toString());

        Checkout a = registry.create("/Vanilla/1.13d/D2Common.dll", "D2Common.dll", cfgA);
        Checkout b = registry.create("/Mods/PD2-S12/D2Common.dll", "D2Common.dll", cfgB);

        assertNotNull(a);
        assertNotNull(b);
        assertFalse(a.id().equals(b.id()));

        CheckoutRegistry.ResolveResult result = registry.resolve("D2Common.dll");
        assertFalse(result.isOk());
        assertNotNull(result.error());
        assertTrue(
                "ambiguity error must name first candidate id: " + result.error(),
                result.error().contains(a.id()));
        assertTrue(
                "ambiguity error must name second candidate id: " + result.error(),
                result.error().contains(b.id()));
        assertTrue(result.error().contains("/Vanilla/1.13d/D2Common.dll"));
        assertTrue(result.error().contains("/Mods/PD2-S12/D2Common.dll"));
    }

    @Test
    public void resolveByIdAndDomainPathIsUnique() throws IOException {
        CheckoutRegistry registry = CheckoutRegistry.getInstance();
        Checkout created = registry.create(
                "/Vanilla/1.13d/D2Common.dll",
                "D2Common.dll",
                CheckoutConfig.defaults().withRootPath(tempA.toAbsolutePath().toString()));

        CheckoutRegistry.ResolveResult byId = registry.resolve(created.id());
        assertTrue(byId.isOk());
        assertSame(created, byId.checkout());

        CheckoutRegistry.ResolveResult byPath = registry.resolve("/Vanilla/1.13d/D2Common.dll");
        assertTrue(byPath.isOk());
        assertSame(created, byPath.checkout());
    }

    @Test
    public void createIsIdempotentForSameKey() throws IOException {
        CheckoutRegistry registry = CheckoutRegistry.getInstance();
        CheckoutConfig cfg = CheckoutConfig.defaults()
                .withRootPath(tempA.toAbsolutePath().toString());
        Checkout first = registry.create("/proj/app.exe", "app.exe", cfg);
        Checkout second = registry.create("/proj/app.exe", "app.exe", cfg);
        assertSame(first, second);
        assertEquals(1, registry.all().size());
    }

    @Test
    public void defaultRootsDivergeForSameBasename() throws IOException {
        CheckoutRegistry registry = CheckoutRegistry.getInstance();
        Checkout a = registry.create(
                "/Vanilla/1.13d/D2Common.dll", "D2Common.dll", CheckoutConfig.defaults());
        Checkout b = registry.create(
                "/Mods/PD2-S12/D2Common.dll", "D2Common.dll", CheckoutConfig.defaults());

        assertNotEqualsPaths(a.root().path(), b.root().path());
        assertTrue(a.root().path().getFileName().toString().startsWith("D2Common.dll-"));
        assertTrue(b.root().path().getFileName().toString().startsWith("D2Common.dll-"));

        // Clean default trees created under tmpdir.
        registry.delete(a.id(), true);
        registry.delete(b.id(), true);
    }

    @Test
    public void enqueueRunsOnNamedDaemonThread() throws Exception {
        CountDownLatch done = new CountDownLatch(1);
        AtomicReference<Thread> seen = new AtomicReference<>();
        CheckoutRegistry.getInstance().enqueue(() -> {
            seen.set(Thread.currentThread());
            done.countDown();
        });
        assertTrue(done.await(5, TimeUnit.SECONDS));
        Thread t = seen.get();
        assertNotNull(t);
        assertEquals("GhidraMCP-Checkout-Sweep", t.getName());
        assertTrue(t.isDaemon());
        assertEquals(Thread.MIN_PRIORITY, t.getPriority());
    }

    @Test
    public void deleteRemovesRegistration() throws IOException {
        CheckoutRegistry registry = CheckoutRegistry.getInstance();
        Checkout c = registry.create(
                "/x/y.exe",
                "y.exe",
                CheckoutConfig.defaults().withRootPath(tempA.toAbsolutePath().toString()));
        assertTrue(registry.delete(c.id(), false));
        assertTrue(registry.byId(c.id()) == null);
        assertFalse(registry.resolve(c.id()).isOk());
    }

    @Test
    public void registerAndKeyDerivation() {
        CheckoutKey key = CheckoutKey.of("/a/b.dll", tempA.toAbsolutePath().toString());
        assertTrue(key.id().startsWith("co_"));
        assertEquals(11, key.id().length()); // co_ + 8 hex
        CheckoutRoot root = CheckoutRoot.ofResolved(tempA);
        Checkout checkout = new Checkout(key, "b.dll", CheckoutConfig.defaults(), root);
        CheckoutRegistry.getInstance().register(checkout);
        assertSame(checkout, CheckoutRegistry.getInstance().byId(key.id()));
    }

    private static void assertNotEqualsPaths(Path a, Path b) {
        assertFalse(a.toAbsolutePath().normalize().equals(b.toAbsolutePath().normalize()));
    }

    private static void deleteRecursively(Path dir) throws IOException {
        if (dir == null || !Files.exists(dir)) {
            return;
        }
        try (Stream<Path> walk = Files.walk(dir)) {
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
