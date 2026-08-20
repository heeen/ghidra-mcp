package com.xebyte.core.checkout;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;

/**
 * JVM-wide checkout registry — {@link com.xebyte.core.NamingPolicy}-shaped
 * {@code private static final INSTANCE}, never nulled.
 *
 * <p>Contrast {@code ServerManager}, which nulls its instance on last-tool
 * deregister: hanging checkouts off that lifecycle would drop in-flight state
 * and orphan on-disk trees whenever the last tool closed. Services are also
 * constructed at three independent sites, so an instance field would be three
 * registries in one GUI JVM. Only a static singleton is JVM-wide.
 *
 * <p>One single-thread daemon executor runs sweeps; throughput is
 * {@code ProgramDB}-lock-bound, so a second concurrent sweep would only halve
 * the first. SweepJob itself lands in a later step — {@link #enqueue(Runnable)}
 * is the hook.
 */
public final class CheckoutRegistry {

    private static final CheckoutRegistry INSTANCE = new CheckoutRegistry();

    private final Map<String, Checkout> byId = new LinkedHashMap<>();
    private final ExecutorService sweepExecutor;

    private CheckoutRegistry() {
        ThreadFactory factory = runnable -> {
            Thread t = new Thread(runnable, "GhidraMCP-Checkout-Sweep");
            t.setDaemon(true);
            t.setPriority(Thread.MIN_PRIORITY);
            return t;
        };
        this.sweepExecutor = Executors.newSingleThreadExecutor(factory);
    }

    public static CheckoutRegistry getInstance() {
        return INSTANCE;
    }

    /**
     * Default-root parent used in the key so hashing is non-circular:
     * {@code id} / directory suffix = SHA-256({@code domain|parent})[0:8],
     * files live at {@code parent/<basename>-<hash>/}.
     */
    public static Path defaultParent() {
        return Path.of(System.getProperty("java.io.tmpdir"), "ghidra-mcp-checkout")
                .toAbsolutePath()
                .normalize();
    }

    /**
     * Create (or return existing-by-id) a checkout for {@code domainPath}.
     * Does not start a sweep.
     */
    public synchronized Checkout create(
            String domainPath, String programName, CheckoutConfig config) throws IOException {
        Objects.requireNonNull(domainPath, "domainPath");
        Objects.requireNonNull(programName, "programName");
        CheckoutConfig cfg = config != null ? config : CheckoutConfig.defaults();

        // Key material uses the shared parent (not the unique child dir) so the
        // directory suffix can be the same 8 hex chars as id().
        CheckoutKey defaultKey = CheckoutKey.of(domainPath, defaultParent().toString());
        CheckoutRoot defaultRoot = CheckoutRoot.defaultRoot(defaultKey.directoryName(programName));

        final CheckoutKey key;
        final CheckoutRoot root;
        if (cfg.rootPath() != null) {
            root = CheckoutRoot.explicit(cfg.rootPath());
            // An explicit root that IS this program's default root must key the same
            // way the default branch does. Otherwise one tree acquires two identities
            // — measured: creating with no root and then re-creating from a config
            // that had been persisted with the resolved absolute root produced
            // co_7de33ad7 and co_adeb2a7d for the same directory, each with its own
            // resource URI, so a client subscribed to the first stopped being told
            // about changes.
            key = root.path().equals(defaultRoot.path())
                    ? defaultKey
                    : CheckoutKey.of(domainPath, root.path());
        } else {
            key = defaultKey;
            root = defaultRoot;
        }

        Checkout existing = byId.get(key.id());
        if (existing != null) {
            return existing;
        }

        CheckoutConfig resolved = cfg.withRootPath(root.path().toString());
        root.ensureExists();
        Checkout checkout = new Checkout(key, programName, resolved, root);
        byId.put(checkout.id(), checkout);
        return checkout;
    }

    /** Register an already-built checkout (tests / adopt path). */
    public synchronized Checkout register(Checkout checkout) {
        Objects.requireNonNull(checkout, "checkout");
        byId.put(checkout.id(), checkout);
        return checkout;
    }

    public synchronized Checkout byId(String id) {
        if (id == null) {
            return null;
        }
        return byId.get(id);
    }

    public synchronized Collection<Checkout> all() {
        return List.copyOf(byId.values());
    }

    /**
     * Resolve by checkout id, program name, or domain path.
     *
     * <p>On ambiguity returns an error naming both candidates rather than
     * guessing — the same failure mode {@code switch_program} has when
     * matching by name across versioned project folders.
     */
    public synchronized ResolveResult resolve(String selector) {
        if (selector == null || selector.isBlank()) {
            return ResolveResult.error("checkout selector must not be blank");
        }
        String sel = selector.trim();

        Checkout byExactId = byId.get(sel);
        if (byExactId != null) {
            return ResolveResult.ok(byExactId);
        }

        List<Checkout> matches = new ArrayList<>();
        for (Checkout c : byId.values()) {
            if (sel.equals(c.id())
                    || sel.equals(c.programName())
                    || sel.equals(c.domainPath())
                    || basenameEquals(sel, c.programName())
                    || basenameEquals(sel, c.domainPath())) {
                matches.add(c);
            }
        }

        if (matches.isEmpty()) {
            return ResolveResult.error("no checkout matches selector: " + sel);
        }
        if (matches.size() == 1) {
            return ResolveResult.ok(matches.get(0));
        }
        Checkout a = matches.get(0);
        Checkout b = matches.get(1);
        return ResolveResult.error(
                "ambiguous checkout selector '" + sel + "': matches "
                        + a.id() + " (" + a.domainPath() + ") and "
                        + b.id() + " (" + b.domainPath() + ")");
    }

    public synchronized boolean delete(String id, boolean deleteFiles) throws IOException {
        Checkout removed = byId.remove(id);
        if (removed == null) {
            return false;
        }
        if (deleteFiles) {
            removed.root().deleteTree();
        }
        return true;
    }

    /**
     * Enqueue work on the single JVM-wide sweep thread.
     * SweepJob (step 5) submits here; this step only provides the hook.
     */
    public void enqueue(Runnable job) {
        Objects.requireNonNull(job, "job");
        sweepExecutor.execute(job);
    }

    /** Test helper: drop all registrations without touching disk. */
    public synchronized void clearForTests() {
        byId.clear();
    }

    private static boolean basenameEquals(String selector, String pathOrName) {
        if (pathOrName == null) {
            return false;
        }
        return selector.equals(com.xebyte.headless.HeadlessPaths.safeBasename(pathOrName));
    }

    /**
     * Result of {@link CheckoutRegistry#resolve(String)} — either a single
     * checkout or an error message (not found / ambiguous).
     */
    public record ResolveResult(Checkout checkout, String error) {
        public static ResolveResult ok(Checkout checkout) {
            return new ResolveResult(Objects.requireNonNull(checkout), null);
        }

        public static ResolveResult error(String message) {
            return new ResolveResult(null, Objects.requireNonNull(message));
        }

        public boolean isOk() {
            return checkout != null;
        }
    }
}
