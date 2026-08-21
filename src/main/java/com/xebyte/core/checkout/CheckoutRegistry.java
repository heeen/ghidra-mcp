package com.xebyte.core.checkout;

import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.function.Function;

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
 * <p>One single-thread daemon executor runs sweeps <em>and</em> the
 * {@link DirtyQueue} drain; throughput is {@code ProgramDB}-lock-bound, so a
 * second concurrent decompile stream would only thrash the first.
 * {@link SweepJob} submits via {@link #enqueueSweep(SweepJob)}.
 */
public final class CheckoutRegistry {

    private static final CheckoutRegistry INSTANCE = new CheckoutRegistry();

    private final Map<String, Checkout> byId = new LinkedHashMap<>();
    private final Map<String, SweepJob> activeJobs = new ConcurrentHashMap<>();
    private final Map<String, CheckoutObserver> observers = new ConcurrentHashMap<>();
    private final Map<String, Program> observerPrograms = new ConcurrentHashMap<>();
    private final ExecutorService sweepExecutor;
    private final DirtyQueue dirtyQueue;
    private volatile Function<Checkout, Program> programLookup;

    private CheckoutRegistry() {
        ThreadFactory factory = runnable -> {
            Thread t = new Thread(runnable, "GhidraMCP-Checkout-Sweep");
            t.setDaemon(true);
            t.setPriority(Thread.MIN_PRIORITY);
            return t;
        };
        this.sweepExecutor = Executors.newSingleThreadExecutor(factory);
        this.dirtyQueue = new DirtyQueue(this);
    }

    public static CheckoutRegistry getInstance() {
        return INSTANCE;
    }

    public DirtyQueue dirtyQueue() {
        return dirtyQueue;
    }

    /**
     * How the dirty queue re-resolves a Program without the observer holding
     * one. Set by {@code FrontEndProgramProvider} (cache owner); null means
     * auto-reconcile cannot run.
     */
    public void setProgramLookup(Function<Checkout, Program> lookup) {
        this.programLookup = lookup;
    }

    Function<Checkout, Program> programLookup() {
        return programLookup;
    }

    boolean isSweepActive(String checkoutId) {
        return checkoutId != null && activeJobs.containsKey(checkoutId);
    }

    /**
     * Attach a {@link CheckoutObserver} when this program has a registered
     * checkout. Idempotent. Holds the observer by checkout id — never stores
     * the Program on the observer itself.
     */
    public void ensureObserver(Program program) {
        if (program == null || program.isClosed()) {
            return;
        }
        Checkout checkout = findCheckoutFor(program);
        if (checkout == null) {
            return;
        }
        String id = checkout.id();
        if (observers.containsKey(id)) {
            // Same checkout, possibly a different Program instance after
            // orphan recovery — rebind the listener to the live object.
            Program prior = observerPrograms.get(id);
            if (prior == program) {
                return;
            }
            detachObserver(id);
        }
        CheckoutObserver obs = new CheckoutObserver(id, dirtyQueue);
        try {
            program.addListener(obs);
            observers.put(id, obs);
            observerPrograms.put(id, program);
        } catch (Exception e) {
            Msg.warn(this, "Failed to attach checkout observer for " + id
                    + ": " + e.getMessage());
        }
    }

    /** Detach every observer bound to this Program (cache release / evict). */
    public void detachObservers(Program program) {
        if (program == null) {
            return;
        }
        List<String> ids = new ArrayList<>();
        for (Map.Entry<String, Program> e : observerPrograms.entrySet()) {
            if (e.getValue() == program) {
                ids.add(e.getKey());
            }
        }
        for (String id : ids) {
            detachObserver(id);
        }
    }

    /** Detach by checkout id (delete path / CLOSED). */
    public void detachObserver(String checkoutId) {
        if (checkoutId == null) {
            return;
        }
        CheckoutObserver obs = observers.remove(checkoutId);
        Program program = observerPrograms.remove(checkoutId);
        dirtyQueue.clear(checkoutId);
        if (obs != null && program != null && !program.isClosed()) {
            try {
                program.removeListener(obs);
            } catch (Exception e) {
                Msg.warn(this, "Failed to detach checkout observer for "
                        + checkoutId + ": " + e.getMessage());
            }
        }
    }

    private Checkout findCheckoutFor(Program program) {
        String domain = null;
        DomainFile df = program.getDomainFile();
        if (df != null) {
            domain = df.getPathname();
        }
        String name = program.getName();
        synchronized (this) {
            for (Checkout c : byId.values()) {
                if (domain != null && domain.equals(c.domainPath())) {
                    return c;
                }
                if (name != null && name.equals(c.programName())) {
                    return c;
                }
            }
        }
        return null;
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
        // Drop the listener before the tree — a deleted checkout must not keep
        // splicing into a path that no longer exists.
        detachObserver(id);
        if (deleteFiles) {
            removed.root().deleteTree();
        }
        return true;
    }

    /**
     * Enqueue a {@link SweepJob} on the single JVM-wide sweep thread.
     * Tracks the job so {@link #cancelSweep} can flip its flag and
     * {@code stopProcess()} the in-flight decompile.
     */
    public void enqueueSweep(SweepJob job) {
        Objects.requireNonNull(job, "job");
        activeJobs.put(job.checkoutId(), job);
        sweepExecutor.execute(job);
    }

    /**
     * Cancel a queued or running sweep. A job still queued is marked cancelled
     * before {@link SweepJob#run()} does any work.
     */
    public void cancelSweep(String checkoutId, String reason) {
        if (checkoutId == null) {
            return;
        }
        SweepJob job = activeJobs.get(checkoutId);
        if (job != null) {
            job.requestCancel(reason != null ? reason : "cancelled by /decompile_checkout_stop");
        }
    }

    /** Called from {@link SweepJob} finally — only clears if still this job. */
    void clearActiveJob(String checkoutId, SweepJob job) {
        activeJobs.remove(checkoutId, job);
    }

    /** Test / raw hook: enqueue arbitrary work on the sweep thread. */
    public void enqueue(Runnable job) {
        Objects.requireNonNull(job, "job");
        sweepExecutor.execute(job);
    }

    /** Test helper: drop all registrations without touching disk. */
    public synchronized void clearForTests() {
        for (String id : new ArrayList<>(observers.keySet())) {
            detachObserver(id);
        }
        byId.clear();
        activeJobs.clear();
        dirtyQueue.clearAll();
        programLookup = null;
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
