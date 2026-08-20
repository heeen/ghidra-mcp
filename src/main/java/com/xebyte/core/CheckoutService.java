package com.xebyte.core;

import com.xebyte.core.checkout.Checkout;
import com.xebyte.core.checkout.CheckoutConfig;
import com.xebyte.core.checkout.CheckoutKey;
import com.xebyte.core.checkout.CheckoutLayout;
import com.xebyte.core.checkout.CheckoutRegistry;
import com.xebyte.core.checkout.CheckoutRoot;
import com.xebyte.core.checkout.CheckoutStatusMd;
import com.xebyte.core.checkout.CheckoutTreeNarrower;
import com.xebyte.core.checkout.ExclusionEvaluator;
import com.xebyte.core.checkout.ExclusionRule;
import com.xebyte.core.checkout.SweepJob;
import com.xebyte.core.checkout.SweepProgress;
import com.xebyte.core.partition.Partition;
import com.xebyte.core.partition.PartitionCascade;
import com.xebyte.core.partition.PartitionContext;
import com.xebyte.core.partition.Partitioner;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

/**
 * Manage decompilation checkouts — persistent on-disk trees an agent can Grep.
 *
 * <p>Status is its own {@link ToolAccess#READ_ONLY} endpoint (not an {@code action}
 * on a POST) because plan mode forces a permission prompt for every non-read-only
 * MCP tool that no allow-rule can suppress, and a checkout is polled while
 * planning by construction. All write paths are host-filesystem only: they never
 * mutate program state, which is why the bridge marks them {@code NONE} for
 * resource invalidation.
 *
 * <p>Sweeps run as {@link SweepJob} on {@link CheckoutRegistry}'s daemon thread —
 * never through {@code ThreadingStrategy}.
 *
 * @since 7.2.0
 */
public class CheckoutService {

    private static final int ADOPT_SCAN_CAP = 64;
    private static final String RESOURCE_URI_PREFIX = "ghidra://checkout/";
    private static final String POLL_PATH = "/checkout_status";

    private final ProgramProvider programProvider;

    public CheckoutService(ProgramProvider programProvider) {
        this.programProvider = programProvider;
    }

    // =========================================================================
    // /checkout_status — READ_ONLY poll target
    // =========================================================================

    @McpTool(path = "/checkout_status", method = "GET",
        description = "Report checkout status and config. Optional checkout selector "
            + "(id, program name, or domain path). With no selector, lists registered "
            + "checkouts and scans the default parent for adoptable on-disk trees. "
            + "Never errors when the program is closed or the root is missing — "
            + "reports program:\"closed\" / root_present:false instead.",
        category = "checkout", access = ToolAccess.READ_ONLY)
    public Response checkoutStatus(
            @Param(value = "checkout", defaultValue = "",
                   description = "Checkout id, program name, or domain path. "
                       + "Omit to list all + scan for adoptable on-disk checkouts.")
            String checkoutSelector) {

        CheckoutRegistry registry = CheckoutRegistry.getInstance();

        if (checkoutSelector != null && !checkoutSelector.isBlank()) {
            CheckoutRegistry.ResolveResult resolved = registry.resolve(checkoutSelector);
            if (!resolved.isOk()) {
                return Response.err(resolved.error());
            }
            return Response.ok(statusMap(resolved.checkout()));
        }

        List<Map<String, Object>> registered = new ArrayList<>();
        Set<String> knownRoots = new LinkedHashSet<>();
        for (Checkout c : registry.all()) {
            registered.add(statusMap(c));
            knownRoots.add(c.root().path().toAbsolutePath().normalize().toString());
        }

        List<Map<String, Object>> adoptable = scanAdoptable(knownRoots);

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("checkouts", registered);
        out.put("adoptable_on_disk", adoptable);
        out.put("checkout_count", registered.size());
        out.put("adoptable_count", adoptable.size());
        return Response.ok(out);
    }

    // =========================================================================
    // /checkout_create — WRITE, no sweep
    // =========================================================================

    @McpTool(path = "/checkout_create", method = "POST",
        description = "Register a decompilation checkout and write checkout.json / "
            + "STATUS.md under the root. Does not sweep. If checkout.json already "
            + "exists under the derived root, adopts it (adopted:true) and reconciles "
            + "swept_at_modification_number against the live program.",
        category = "checkout", access = ToolAccess.WRITE)
    public Response checkoutCreate(
            @Param(value = "program", defaultValue = "",
                   description = "Target program name (omit for the active program).")
            String programName,
            @Param(value = "root", source = ParamSource.BODY, defaultValue = "",
                   description = "Absolute checkout root. Omit for the default under "
                       + "java.io.tmpdir/ghidra-mcp-checkout/.")
            String root,
            @Param(value = "strategies", source = ParamSource.BODY, defaultValue = "",
                   description = "Comma-separated partition strategies. Empty = full cascade.")
            String strategies,
            @Param(value = "band_size", source = ParamSource.BODY, defaultValue = "20",
                   description = "Address-band width when bands apply.")
            int bandSize,
            @Param(value = "exclusions", source = ParamSource.BODY, defaultValue = "",
                   description = "CSV of tag:/partition:/range: exclusion specs.")
            String exclusions,
            @Param(value = "include_only", source = ParamSource.BODY, defaultValue = "",
                   description = "CSV of tag:/partition:/range: include-only specs.")
            String includeOnly,
            @Param(value = "throttle_percent", source = ParamSource.BODY, defaultValue = "10",
                   description = "Interactive yield 0..90 after each decompiled function.")
            int throttlePercent) {

        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) {
            return pe.error();
        }
        Program program = pe.program();

        List<ExclusionRule> exclRules;
        List<ExclusionRule> includeRules;
        List<String> strategyList;
        try {
            exclRules = parseRuleCsv(exclusions);
            includeRules = parseRuleCsv(includeOnly);
            strategyList = parseCsvTokens(strategies);
        } catch (IllegalArgumentException e) {
            return Response.err(e.getMessage());
        }

        CheckoutConfig requested = CheckoutConfig.builder()
                .rootPath(blankToNull(root))
                .enabledStrategies(strategyList)
                .bandSize(bandSize)
                .exclusions(exclRules)
                .includeOnly(includeRules)
                .throttlePercent(throttlePercent)
                .build();

        try {
            ExclusionEvaluator.validateRanges(program, requested);
        } catch (IllegalArgumentException e) {
            return Response.err(e.getMessage());
        }

        String domainPath = domainPathOf(program);
        String resolvedName = program.getName();

        final Path derivedRoot;
        try {
            derivedRoot = deriveRootPath(domainPath, resolvedName, requested);
        } catch (IllegalArgumentException e) {
            return Response.err(e.getMessage());
        }

        Path jsonPath = derivedRoot.resolve(CheckoutLayout.checkoutJson());
        boolean adoptable = Files.isRegularFile(jsonPath);

        try {
            if (adoptable) {
                return adoptExisting(program, domainPath, resolvedName, derivedRoot,
                        jsonPath, requested);
            }
            return createFresh(program, domainPath, resolvedName, requested);
        } catch (IOException e) {
            return Response.err("checkout create failed: " + e.getMessage());
        } catch (IllegalArgumentException e) {
            return Response.err(e.getMessage());
        }
    }

    // =========================================================================
    // /checkout_configure — WRITE, persist + classify only (no delete/resweep)
    // =========================================================================

    @McpTool(path = "/checkout_configure", method = "POST",
        description = "Update checkout configuration (all optional). Classifies the change "
            + "and acts: narrowing deletes now-out-of-scope function bodies immediately; "
            + "widening marks phase STALE with pending_functions (no auto-sweep); "
            + "repartitioning sets requires_full_resweep and STALE. Never starts a sweep.",
        category = "checkout", access = ToolAccess.WRITE)
    public Response checkoutConfigure(
            @Param(value = "checkout", source = ParamSource.BODY,
                   description = "Checkout id, program name, or domain path.")
            String checkoutSelector,
            @Param(value = "root", source = ParamSource.BODY, defaultValue = "",
                   description = "Ignored for now — root is identity; changing it needs a new checkout.")
            String root,
            @Param(value = "strategies", source = ParamSource.BODY, defaultValue = "",
                   description = "Comma-separated partition strategies. Omit to leave unchanged.")
            String strategies,
            @Param(value = "band_size", source = ParamSource.BODY, defaultValue = "",
                   description = "Address-band width. Omit to leave unchanged.")
            Integer bandSize,
            @Param(value = "exclusions", source = ParamSource.BODY, defaultValue = "",
                   description = "CSV of exclusion specs. Omit to leave unchanged.")
            String exclusions,
            @Param(value = "include_only", source = ParamSource.BODY, defaultValue = "",
                   description = "CSV of include-only specs. Omit to leave unchanged.")
            String includeOnly,
            @Param(value = "throttle_percent", source = ParamSource.BODY, defaultValue = "",
                   description = "Interactive yield 0..90. Omit to leave unchanged.")
            Integer throttlePercent) {

        CheckoutRegistry.ResolveResult resolved =
                CheckoutRegistry.getInstance().resolve(checkoutSelector);
        if (!resolved.isOk()) {
            return Response.err(resolved.error());
        }
        Checkout checkout = resolved.checkout();
        CheckoutConfig old = checkout.config();

        // Root is part of the checkout key — moving it would be a different checkout.
        if (root != null && !root.isBlank() && old.rootPath() != null) {
            String requestedRoot = Path.of(root).toAbsolutePath().normalize().toString();
            String existingRoot = Path.of(old.rootPath()).toAbsolutePath().normalize().toString();
            if (!requestedRoot.equals(existingRoot)) {
                return Response.err(
                        "root cannot be changed on an existing checkout; create a new one "
                                + "with a different root");
            }
        }

        CheckoutConfig.Builder b = CheckoutConfig.builder()
                .rootPath(old.rootPath())
                .enabledStrategies(old.enabledStrategies())
                .bandSize(old.bandSize())
                .exclusions(old.exclusions())
                .includeOnly(old.includeOnly())
                .throttlePercent(old.throttlePercent())
                .decompileTimeoutSeconds(old.decompileTimeoutSeconds())
                .analysisWaitSeconds(old.analysisWaitSeconds());

        boolean strategiesTouched = strategies != null && !strategies.isBlank();
        boolean exclusionsTouched = exclusions != null && !exclusions.isBlank();
        boolean includeTouched = includeOnly != null && !includeOnly.isBlank();

        try {
            if (strategiesTouched) {
                b.enabledStrategies(parseCsvTokens(strategies));
            }
            if (bandSize != null) {
                b.bandSize(bandSize);
            }
            if (exclusionsTouched) {
                b.exclusions(parseRuleCsv(exclusions));
            }
            if (includeTouched) {
                b.includeOnly(parseRuleCsv(includeOnly));
            }
            if (throttlePercent != null) {
                b.throttlePercent(throttlePercent);
            }
        } catch (IllegalArgumentException e) {
            return Response.err(e.getMessage());
        }

        // Empty CSV with a present-but-blank body cannot clear lists through the
        // bridge (empty strings are dropped). Callers that need to clear must pass
        // a sentinel later; for now "omit" means leave unchanged.
        CheckoutConfig updated = b.build();

        Program live = findOpenProgram(checkout);
        // RANGE bounds need AddressFactory — reject here, not mid-sweep.
        if (live != null && !live.isClosed()) {
            try {
                ExclusionEvaluator.validateRanges(live, updated);
            } catch (IllegalArgumentException e) {
                return Response.err(e.getMessage());
            }
        } else if (hasRangeRules(updated)) {
            return Response.err(
                    "program is closed; cannot validate range exclusions against AddressFactory");
        }

        String change = classifyConfigChange(old, updated,
                strategiesTouched, bandSize != null, exclusionsTouched, includeTouched);

        checkout.setConfig(updated);
        try {
            writeCheckoutJson(checkout);
        } catch (IOException e) {
            return Response.err("failed to persist checkout.json: " + e.getMessage());
        }

        Map<String, Object> out = statusMap(checkout);
        out.put("config_change", change);
        out.put("behaviour", change);

        try {
            applyConfigBehaviour(checkout, live, old, updated, change, out);
        } catch (IOException e) {
            return Response.err("config behaviour failed: " + e.getMessage());
        } catch (IllegalArgumentException e) {
            return Response.err(e.getMessage());
        }

        // Refresh status fields after phase / file mutations.
        Map<String, Object> refreshed = statusMap(checkout);
        refreshed.put("config_change", change);
        refreshed.put("behaviour", change);
        for (String key : List.of(
                "functions_removed", "modules_touched", "pending_functions",
                "requires_full_resweep", "action")) {
            if (out.containsKey(key)) {
                refreshed.put(key, out.get(key));
            }
        }
        return Response.ok(refreshed);
    }

    // =========================================================================
    // /checkout_start — WRITE, enqueue SweepJob
    // =========================================================================

    @McpTool(path = "/checkout_start", method = "POST",
        description = "Enqueue a checkout sweep. Returns immediately with phase queued "
            + "and the resource URI to poll via /checkout_status.",
        category = "checkout", access = ToolAccess.WRITE)
    public Response checkoutStart(
            @Param(value = "checkout", source = ParamSource.BODY,
                   description = "Checkout id, program name, or domain path.")
            String checkoutSelector) {

        CheckoutRegistry.ResolveResult resolved =
                CheckoutRegistry.getInstance().resolve(checkoutSelector);
        if (!resolved.isOk()) {
            return Response.err(resolved.error());
        }
        Checkout checkout = resolved.checkout();
        SweepProgress.Phase phase = checkout.progress().phase();

        if (phase == SweepProgress.Phase.QUEUED
                || phase == SweepProgress.Phase.WAITING_FOR_ANALYSIS
                || phase == SweepProgress.Phase.PARTITIONING
                || phase == SweepProgress.Phase.DECOMPILING) {
            return Response.ok(startResponse(checkout));
        }

        Program live = findOpenProgram(checkout);
        if (live == null || live.isClosed()) {
            return Response.err("program is closed; cannot start checkout sweep");
        }

        checkout.setProgress(checkout.progress().withPhase(SweepProgress.Phase.QUEUED));
        try {
            CheckoutStatusMd.write(checkout, "dirty", null);
        } catch (IOException e) {
            return Response.err("failed to update STATUS.md: " + e.getMessage());
        }

        SweepJob job = new SweepJob(checkout, live);
        CheckoutRegistry.getInstance().enqueueSweep(job);

        return Response.ok(startResponse(checkout));
    }

    // =========================================================================
    // /checkout_stop — WRITE, idempotent
    // =========================================================================

    @McpTool(path = "/checkout_stop", method = "POST",
        description = "Cancel a queued or running checkout sweep. Idempotent: stopping "
            + "an idle/complete checkout is success, not an error.",
        category = "checkout", access = ToolAccess.WRITE)
    public Response checkoutStop(
            @Param(value = "checkout", source = ParamSource.BODY,
                   description = "Checkout id, program name, or domain path.")
            String checkoutSelector) {

        CheckoutRegistry.ResolveResult resolved =
                CheckoutRegistry.getInstance().resolve(checkoutSelector);
        if (!resolved.isOk()) {
            return Response.err(resolved.error());
        }
        Checkout checkout = resolved.checkout();
        SweepProgress.Phase phase = checkout.progress().phase();
        boolean cancelled = false;

        if (phase == SweepProgress.Phase.QUEUED
                || phase == SweepProgress.Phase.WAITING_FOR_ANALYSIS
                || phase == SweepProgress.Phase.PARTITIONING
                || phase == SweepProgress.Phase.DECOMPILING) {
            // Flag + stopProcess on the in-flight decompile — do not wait out the timeout.
            CheckoutRegistry.getInstance()
                    .cancelSweep(checkout.id(), "cancelled by /checkout_stop");
            checkout.setProgress(checkout.progress()
                    .withPhase(SweepProgress.Phase.CANCELLED)
                    .withLastError("cancelled by /checkout_stop"));
            cancelled = true;
            try {
                CheckoutStatusMd.write(checkout, "cancelled", null);
            } catch (IOException e) {
                return Response.err("failed to update STATUS.md: " + e.getMessage());
            }
        }

        Map<String, Object> out = statusMap(checkout);
        out.put("cancelled", cancelled);
        out.put("idempotent", !cancelled);
        return Response.ok(out);
    }

    // =========================================================================
    // /checkout_delete — DESTRUCTIVE
    // =========================================================================

    @McpTool(path = "/checkout_delete", method = "POST",
        description = "Deregister a checkout. With delete_files=true, also removes the "
            + "on-disk tree (containment-checked).",
        category = "checkout", access = ToolAccess.DESTRUCTIVE)
    public Response checkoutDelete(
            @Param(value = "checkout", source = ParamSource.BODY,
                   description = "Checkout id, program name, or domain path.")
            String checkoutSelector,
            @Param(value = "delete_files", source = ParamSource.BODY, defaultValue = "false",
                   description = "When true, delete the checkout tree from disk.")
            boolean deleteFiles) {

        CheckoutRegistry.ResolveResult resolved =
                CheckoutRegistry.getInstance().resolve(checkoutSelector);
        if (!resolved.isOk()) {
            return Response.err(resolved.error());
        }
        Checkout checkout = resolved.checkout();
        String id = checkout.id();
        String rootPath = checkout.root().path().toString();

        try {
            boolean removed = CheckoutRegistry.getInstance().delete(id, deleteFiles);
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("checkout_id", id);
            out.put("deleted", removed);
            out.put("files_deleted", deleteFiles);
            out.put("root", rootPath);
            return Response.ok(out);
        } catch (IOException e) {
            return Response.err("checkout delete failed: " + e.getMessage());
        }
    }

    // =========================================================================
    // Internals
    // =========================================================================

    private Response createFresh(
            Program program, String domainPath, String programName, CheckoutConfig requested)
            throws IOException {
        Checkout checkout = CheckoutRegistry.getInstance()
                .create(domainPath, programName, requested);
        writeCheckoutJson(checkout);
        // Nothing has been swept yet — "dirty" would mean a crash mid-sweep.
        CheckoutStatusMd.write(checkout, "empty", null);

        Map<String, Object> out = statusMap(checkout);
        out.put("adopted", false);
        out.put("files_on_disk", countFiles(checkout.root().path()));
        out.put("live_modification_number", program.getModificationNumber());
        return Response.ok(out);
    }

    private Response adoptExisting(
            Program program,
            String domainPath,
            String programName,
            Path derivedRoot,
            Path jsonPath,
            CheckoutConfig requested) throws IOException {
        Map<String, Object> disk = JsonHelper.parseJson(
                Files.readString(jsonPath, StandardCharsets.UTF_8));
        CheckoutConfig loaded = configFromDisk(disk, derivedRoot.toString());

        CheckoutRegistry registry = CheckoutRegistry.getInstance();
        // Key off the REQUEST, not the absolute root recorded on disk — see
        // deriveKey. Registering with `loaded` here would force the explicit
        // branch and mint a duplicate id for a tree that already has one.
        Checkout existing = registry.byId(deriveKey(domainPath, requested).id());
        Checkout checkout;
        if (existing != null) {
            existing.setConfig(loaded);
            checkout = existing;
        } else {
            checkout = registry.create(domainPath, programName, requested);
            checkout.setConfig(loaded);
        }

        StatusFile statusFile = readStatusMd(derivedRoot);
        Long sweptAt = statusFile.sweptAtModificationNumber();
        if (sweptAt == null) {
            sweptAt = longField(disk, "swept_at_modification_number");
        }

        long liveMod = program.getModificationNumber();
        // A dirty STATUS.md means the previous sweep did not finish (crash /
        // cancel / kill). Re-derive id finds the same tree across a Ghidra
        // restart; STALE tells the agent Grep results may be incomplete.
        if ("dirty".equalsIgnoreCase(statusFile.state())) {
            checkout.setProgress(checkout.progress()
                    .withPhase(SweepProgress.Phase.STALE)
                    .withLastError("previous sweep did not finish (STATUS.md state=dirty)"));
        } else if (sweptAt != null && sweptAt != liveMod) {
            checkout.setProgress(checkout.progress()
                    .withPhase(SweepProgress.Phase.STALE)
                    .withLastError("swept_at_modification_number=" + sweptAt
                            + " != live " + liveMod));
        }

        int files = countFiles(derivedRoot);
        Map<String, Object> out = statusMap(checkout);
        out.put("adopted", true);
        out.put("files_on_disk", files);
        out.put("swept_at_modification_number", sweptAt);
        out.put("live_modification_number", liveMod);
        out.put("fresh", sweptAt != null && sweptAt == liveMod
                && !"dirty".equalsIgnoreCase(statusFile.state()));
        return Response.ok(out);
    }

    private Map<String, Object> statusMap(Checkout checkout) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("checkout_id", checkout.id());
        out.put("program_name", checkout.programName());
        out.put("domain_path", checkout.domainPath());

        Program live = findOpenProgram(checkout);
        if (live != null) {
            out.put("program", live.getName());
            out.put("live_modification_number", live.getModificationNumber());
        } else {
            // Closed is a normal poll state — an agent asks about a checkout
            // precisely when the program may have gone away.
            out.put("program", "closed");
        }

        Path root = checkout.root().path();
        boolean rootPresent = Files.isDirectory(root);
        out.put("root", root.toString());
        out.put("root_present", rootPresent);
        out.put("root_recreated", checkout.root().rootRecreated());

        SweepProgress progress = checkout.progress();
        out.put("phase", progress.phase().name().toLowerCase(Locale.ROOT));
        out.put("functions_total", progress.functionsTotal());
        out.put("functions_done", progress.functionsDone());
        out.put("functions_failed", progress.functionsFailed());
        out.put("bytes_written", progress.bytesWritten());
        out.put("eligible_functions", progress.eligibleFunctions());
        out.put("functions_in_scope", progress.functionsInScope());
        // Per-rule counts, not just the aggregate: "3230 became 2036" invites the
        // question this answers. Without it a rule that silently matched far more
        // than intended is indistinguishable from one that worked. index.md carries
        // the same breakdown, but an agent polling status should not have to open a
        // file to find out what its own configure call did.
        if (!progress.exclusionRemovals().isEmpty()) {
            out.put("removed_by_rule", new LinkedHashMap<>(progress.exclusionRemovals()));
        }
        out.put("exclusion_removals", progress.exclusionRemovals());
        out.put("current_partition", progress.currentPartition());
        out.put("started_epoch_ms", progress.startedEpochMs());
        out.put("eta_seconds", progress.etaSeconds());
        out.put("last_error", progress.lastError());
        out.put("status_revision", progress.statusRevision());
        out.put("resource_uri", RESOURCE_URI_PREFIX + checkout.id());
        out.put("config", configToMap(checkout.config()));

        if (rootPresent) {
            StatusFile statusFile = readStatusMd(root);
            out.put("status_state", statusFile.state());
            if (statusFile.sweptAtModificationNumber() != null) {
                out.put("swept_at_modification_number", statusFile.sweptAtModificationNumber());
            }
        } else {
            out.put("status_state", null);
        }

        return out;
    }

    private List<Map<String, Object>> scanAdoptable(Set<String> knownRoots) {
        List<Map<String, Object>> found = new ArrayList<>();
        Path parent = CheckoutRegistry.defaultParent();
        if (!Files.isDirectory(parent)) {
            return found;
        }
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(parent)) {
            List<Path> dirs = new ArrayList<>();
            for (Path entry : stream) {
                if (Files.isDirectory(entry)) {
                    dirs.add(entry);
                }
            }
            dirs.sort(Comparator.comparing(p -> p.getFileName().toString()));
            int scanned = 0;
            for (Path dir : dirs) {
                if (scanned >= ADOPT_SCAN_CAP) {
                    break;
                }
                scanned++;
                String abs = dir.toAbsolutePath().normalize().toString();
                if (knownRoots.contains(abs)) {
                    continue;
                }
                Path json = dir.resolve(CheckoutLayout.checkoutJson());
                if (!Files.isRegularFile(json)) {
                    continue;
                }
                Map<String, Object> disk = JsonHelper.parseJson(
                        Files.readString(json, StandardCharsets.UTF_8));
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("root", abs);
                row.put("checkout_id", stringField(disk, "checkout_id"));
                row.put("program_name", stringField(disk, "program_name"));
                row.put("domain_path", stringField(disk, "domain_path"));
                row.put("files_on_disk", countFiles(dir));
                StatusFile statusFile = readStatusMd(dir);
                row.put("status_state", statusFile.state());
                row.put("adoptable", true);
                found.add(row);
            }
        } catch (IOException e) {
            // Listing must never fail the status call — surface the scan error
            // as an empty adoptable list rather than aborting registered status.
        }
        return found;
    }

    private Program findOpenProgram(Checkout checkout) {
        Program[] open = programProvider.getAllOpenPrograms();
        if (open == null) {
            return null;
        }
        for (Program p : open) {
            if (p == null) {
                continue;
            }
            if (checkout.domainPath().equals(domainPathOf(p))
                    || checkout.programName().equals(p.getName())) {
                return p;
            }
        }
        return null;
    }

    private static Map<String, Object> startResponse(Checkout checkout) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("checkout_id", checkout.id());
        out.put("phase", checkout.progress().phase().name().toLowerCase(Locale.ROOT));
        out.put("resource_uri", RESOURCE_URI_PREFIX + checkout.id());
        out.put("poll", POLL_PATH);
        return out;
    }

    private static Path deriveRootPath(String domainPath, String programName, CheckoutConfig cfg) {
        if (cfg.rootPath() != null) {
            return CheckoutRoot.explicit(cfg.rootPath()).path();
        }
        return CheckoutRoot.defaultRoot(
                deriveKey(domainPath, cfg).directoryName(programName)).path();
    }

    /**
     * The one place a checkout's key material is chosen, so an id cannot depend on
     * how its root happened to be expressed.
     *
     * <p>A default-rooted checkout keys off the shared <em>parent</em>, never the
     * child directory, because the child's name contains the hash — keying off it
     * would be circular. Adoption must ask this the same way {@code create} does,
     * from the caller's <em>request</em> rather than from the absolute root stored
     * in {@code checkout.json}: doing the latter took the explicit branch, hashed
     * different material, missed the lookup, and minted a second registration
     * pointing at the same tree with a different id and a different resource URI —
     * so a client subscribed to the first stopped receiving updates.
     */
    private static CheckoutKey deriveKey(String domainPath, CheckoutConfig cfg) {
        if (cfg.rootPath() != null) {
            return CheckoutKey.of(domainPath, CheckoutRoot.explicit(cfg.rootPath()).path());
        }
        return CheckoutKey.of(domainPath, CheckoutRegistry.defaultParent().toString());
    }

    private static String domainPathOf(Program program) {
        if (program.getDomainFile() != null) {
            return program.getDomainFile().getPathname();
        }
        return program.getName();
    }

    private static void writeCheckoutJson(Checkout checkout) throws IOException {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("checkout_id", checkout.id());
        payload.put("domain_path", checkout.domainPath());
        payload.put("program_name", checkout.programName());
        payload.putAll(configToMap(checkout.config()));
        String json = JsonHelper.toJson(payload) + "\n";
        checkout.root().writeFile(Path.of(CheckoutLayout.checkoutJson()), json);
    }

    private static StatusFile readStatusMd(Path root) {
        Path statusPath = root.resolve(CheckoutLayout.statusMd());
        if (!Files.isRegularFile(statusPath)) {
            return new StatusFile(null, null);
        }
        try {
            String text = Files.readString(statusPath, StandardCharsets.UTF_8);
            String state = null;
            Long sweptAt = null;
            for (String line : text.split("\n")) {
                String trimmed = line.trim();
                if (trimmed.startsWith("state:")) {
                    state = trimmed.substring("state:".length()).trim();
                    if (state.isEmpty()) {
                        state = null;
                    }
                } else if (trimmed.startsWith("swept_at_modification_number:")) {
                    String v = trimmed.substring("swept_at_modification_number:".length()).trim();
                    if (!v.isEmpty()) {
                        try {
                            sweptAt = Long.parseLong(v);
                        } catch (NumberFormatException ignored) {
                            // leave null
                        }
                    }
                }
            }
            return new StatusFile(state, sweptAt);
        } catch (IOException e) {
            return new StatusFile(null, null);
        }
    }

    private static CheckoutConfig configFromDisk(Map<String, Object> disk, String rootPath) {
        CheckoutConfig.Builder b = CheckoutConfig.builder().rootPath(rootPath);
        Object strategies = disk.get("enabled_strategies");
        if (strategies instanceof List<?> list) {
            List<String> names = new ArrayList<>();
            for (Object o : list) {
                if (o != null) {
                    names.add(o.toString());
                }
            }
            b.enabledStrategies(names);
        }
        Integer band = intField(disk, "band_size");
        if (band != null) {
            b.bandSize(band);
        }
        Integer throttle = intField(disk, "throttle_percent");
        if (throttle != null) {
            b.throttlePercent(throttle);
        }
        Integer decompileTimeout = intField(disk, "decompile_timeout_seconds");
        if (decompileTimeout != null) {
            b.decompileTimeoutSeconds(decompileTimeout);
        }
        Integer analysisWait = intField(disk, "analysis_wait_seconds");
        if (analysisWait != null) {
            b.analysisWaitSeconds(analysisWait);
        }
        b.exclusions(rulesFromDisk(disk.get("exclusions")));
        b.includeOnly(rulesFromDisk(disk.get("include_only")));
        return b.build();
    }

    private static List<ExclusionRule> rulesFromDisk(Object raw) {
        if (!(raw instanceof List<?> list) || list.isEmpty()) {
            return List.of();
        }
        List<ExclusionRule> out = new ArrayList<>();
        for (Object o : list) {
            if (o == null) {
                continue;
            }
            if (o instanceof Map<?, ?> m) {
                Object kind = m.get("kind");
                Object value = m.get("value");
                if (kind != null && value != null) {
                    out.add(ExclusionRule.parse(
                            kind.toString().toLowerCase(Locale.ROOT) + ":" + value));
                }
            } else {
                out.add(ExclusionRule.parse(o.toString()));
            }
        }
        return out;
    }

    private static Map<String, Object> configToMap(CheckoutConfig cfg) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("root", cfg.rootPath());
        m.put("enabled_strategies", cfg.enabledStrategies());
        m.put("band_size", cfg.bandSize());
        m.put("exclusions", rulesToSpecs(cfg.exclusions()));
        m.put("include_only", rulesToSpecs(cfg.includeOnly()));
        m.put("throttle_percent", cfg.throttlePercent());
        m.put("decompile_timeout_seconds", cfg.decompileTimeoutSeconds());
        m.put("analysis_wait_seconds", cfg.analysisWaitSeconds());
        return m;
    }

    private static List<String> rulesToSpecs(List<ExclusionRule> rules) {
        List<String> out = new ArrayList<>(rules.size());
        for (ExclusionRule r : rules) {
            out.add(r.kind().name().toLowerCase(Locale.ROOT) + ":" + r.value());
        }
        return out;
    }

    /**
     * Act on a classified config edit. Narrowing deletes now-excluded bodies
     * immediately (Grep must not hit a lie). Widening / repartitioning mark
     * STALE and never auto-start a sweep — 200 s of work must not begin from a
     * config call.
     */
    private void applyConfigBehaviour(
            Checkout checkout,
            Program live,
            CheckoutConfig old,
            CheckoutConfig updated,
            String change,
            Map<String, Object> out) throws IOException {

        switch (change) {
            case "narrowing" -> {
                if (live == null || live.isClosed()) {
                    throw new IllegalArgumentException(
                            "program is closed; cannot narrow on-disk checkout files");
                }
                ExclusionEvaluator evaluator = ExclusionEvaluator.of(live, updated);
                CheckoutTreeNarrower.NarrowResult nr =
                        CheckoutTreeNarrower.narrow(checkout, live, evaluator);
                out.put("action", "deleted_out_of_scope_functions");
                out.put("functions_removed", nr.functionsRemoved());
                out.put("modules_touched", nr.modulesTouched());
                // Tree now matches the narrower config — keep phase if it was
                // complete; only stamp STALE when there was nothing to remove
                // but the agent still needs a resweep signal (shouldn't happen).
                if (nr.functionsRemoved() > 0) {
                    checkout.setProgress(checkout.progress()
                            .withScope(
                                    checkout.progress().eligibleFunctions(),
                                    nr.functionsRemaining(),
                                    Map.of()));
                    try {
                        CheckoutStatusMd.write(checkout,
                                CheckoutStatusMd.stateForPhase(checkout.progress().phase()),
                                null);
                    } catch (IOException ignored) {
                        // status on disk is best-effort after a successful rewrite
                    }
                }
            }
            case "widening" -> {
                int pending = estimatePendingFunctions(checkout, live, updated);
                checkout.setProgress(checkout.progress()
                        .withPhase(SweepProgress.Phase.STALE)
                        .withLastError("config widened; resweep needed for pending functions"));
                out.put("action", "marked_stale");
                out.put("pending_functions", pending);
                CheckoutStatusMd.write(checkout, "dirty", null);
            }
            case "repartitioning" -> {
                checkout.setProgress(checkout.progress()
                        .withPhase(SweepProgress.Phase.STALE)
                        .withLastError(
                                "config repartitions compartments; /checkout_start will wipe "
                                        + "modules/ and rewrite"));
                out.put("action", "marked_stale_full_resweep");
                out.put("requires_full_resweep", true);
                int pending = estimatePendingFunctions(checkout, live, updated);
                out.put("pending_functions", pending);
                CheckoutStatusMd.write(checkout, "dirty", null);
            }
            case "mixed" -> {
                // Apply the narrow half immediately, then mark STALE for the
                // newly-included remainder — never auto-sweep.
                if (live != null && !live.isClosed()) {
                    ExclusionEvaluator evaluator = ExclusionEvaluator.of(live, updated);
                    CheckoutTreeNarrower.NarrowResult nr =
                            CheckoutTreeNarrower.narrow(checkout, live, evaluator);
                    out.put("functions_removed", nr.functionsRemoved());
                    out.put("modules_touched", nr.modulesTouched());
                }
                int pending = estimatePendingFunctions(checkout, live, updated);
                checkout.setProgress(checkout.progress()
                        .withPhase(SweepProgress.Phase.STALE)
                        .withLastError("config mixed narrow+widen; resweep needed"));
                out.put("action", "narrowed_and_marked_stale");
                out.put("pending_functions", pending);
                CheckoutStatusMd.write(checkout, "dirty", null);
            }
            default -> out.put("action", "none");
        }
    }

    /**
     * How many in-scope functions are missing from the on-disk index. Runs the
     * cascade when PARTITION rules are in play (slugs required); otherwise
     * TAG/RANGE alone are enough. Returns 0 when the program is closed — the
     * agent still gets STALE and must open before starting.
     */
    private int estimatePendingFunctions(
            Checkout checkout, Program live, CheckoutConfig cfg) {
        if (live == null || live.isClosed()) {
            return 0;
        }
        try {
            ExclusionEvaluator evaluator = ExclusionEvaluator.of(live, cfg);
            Set<String> onDisk = loadIndexAddresses(checkout.root().path());

            boolean needsSlugs = hasPartitionRules(cfg);
            int pending = 0;
            if (needsSlugs) {
                List<Partitioner> chain = PartitionCascade.buildChain(
                        cfg.bandSize(), cfg.enabledStrategies());
                if (chain.isEmpty()) {
                    chain = PartitionCascade.buildChain(cfg.bandSize(), List.of("address-band"));
                }
                PartitionContext ctx = new PartitionContext(live);
                PartitionCascade.Result cascade = new PartitionCascade(chain).run(ctx);
                ExclusionEvaluator.FilterResult filtered =
                        evaluator.filterPartitions(cascade.partitions(), ctx.size());
                for (Partition part : filtered.partitions()) {
                    for (Function func : part.members()) {
                        String hex = normalizeHex(func.getEntryPoint().toString(false));
                        if (!onDisk.contains(hex)) {
                            pending++;
                        }
                    }
                }
            } else {
                PartitionContext ctx = new PartitionContext(live);
                for (Function func : ctx.functions()) {
                    if (!evaluator.isInScope(func, null)) {
                        continue;
                    }
                    String hex = normalizeHex(func.getEntryPoint().toString(false));
                    if (!onDisk.contains(hex)) {
                        pending++;
                    }
                }
            }
            return pending;
        } catch (RuntimeException e) {
            // Pending is advisory — a cascade failure must not fail configure.
            return 0;
        }
    }

    private static Set<String> loadIndexAddresses(Path root) {
        Path index = root.resolve(CheckoutLayout.byAddressTsv());
        if (!Files.isRegularFile(index)) {
            return Set.of();
        }
        try {
            Set<String> out = new LinkedHashSet<>();
            for (String line : Files.readAllLines(index, StandardCharsets.UTF_8)) {
                if (line.isBlank() || line.startsWith("address\t")) {
                    continue;
                }
                int tab = line.indexOf('\t');
                if (tab > 0) {
                    out.add(normalizeHex(line.substring(0, tab)));
                }
            }
            return out;
        } catch (IOException e) {
            return Set.of();
        }
    }

    private static String normalizeHex(String hex) {
        return CheckoutTreeNarrower.normalizeHex(hex);
    }

    private static boolean hasRangeRules(CheckoutConfig cfg) {
        for (ExclusionRule r : cfg.exclusions()) {
            if (r.kind() == ExclusionRule.Kind.RANGE) {
                return true;
            }
        }
        for (ExclusionRule r : cfg.includeOnly()) {
            if (r.kind() == ExclusionRule.Kind.RANGE) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasPartitionRules(CheckoutConfig cfg) {
        for (ExclusionRule r : cfg.exclusions()) {
            if (r.kind() == ExclusionRule.Kind.PARTITION) {
                return true;
            }
        }
        for (ExclusionRule r : cfg.includeOnly()) {
            if (r.kind() == ExclusionRule.Kind.PARTITION) {
                return true;
            }
        }
        return false;
    }

    /**
     * Classify a config edit. File deletion / STALE / full-resweep semantics
     * are applied by {@link #applyConfigBehaviour} using this name.
     */
    private static String classifyConfigChange(
            CheckoutConfig old,
            CheckoutConfig updated,
            boolean strategiesTouched,
            boolean bandTouched,
            boolean exclusionsTouched,
            boolean includeTouched) {

        boolean repartitioning = false;
        if (strategiesTouched
                && !old.enabledStrategies().equals(updated.enabledStrategies())) {
            repartitioning = true;
        }
        if (bandTouched && old.bandSize() != updated.bandSize()) {
            repartitioning = true;
        }
        if (partitionRulesChanged(old.exclusions(), updated.exclusions())
                || partitionRulesChanged(old.includeOnly(), updated.includeOnly())) {
            repartitioning = true;
        }
        if (repartitioning) {
            return "repartitioning";
        }

        Set<String> oldEx = new LinkedHashSet<>(rulesToSpecs(old.exclusions()));
        Set<String> newEx = new LinkedHashSet<>(rulesToSpecs(updated.exclusions()));
        Set<String> oldIn = new LinkedHashSet<>(rulesToSpecs(old.includeOnly()));
        Set<String> newIn = new LinkedHashSet<>(rulesToSpecs(updated.includeOnly()));

        boolean narrowing = false;
        boolean widening = false;

        if (exclusionsTouched && !oldEx.equals(newEx)) {
            if (newEx.containsAll(oldEx) && newEx.size() > oldEx.size()) {
                narrowing = true;
            } else if (oldEx.containsAll(newEx) && oldEx.size() > newEx.size()) {
                widening = true;
            } else {
                narrowing = true;
                widening = true;
            }
        }
        if (includeTouched && !oldIn.equals(newIn)) {
            // include_only tightens the set (narrowing) when it gains constraints.
            if (oldIn.isEmpty() && !newIn.isEmpty()) {
                narrowing = true;
            } else if (!oldIn.isEmpty() && newIn.isEmpty()) {
                widening = true;
            } else if (newIn.containsAll(oldIn) && newIn.size() > oldIn.size()) {
                narrowing = true;
            } else if (oldIn.containsAll(newIn) && oldIn.size() > newIn.size()) {
                widening = true;
            } else {
                narrowing = true;
                widening = true;
            }
        }

        if (narrowing && widening) {
            return "mixed";
        }
        if (narrowing) {
            return "narrowing";
        }
        if (widening) {
            return "widening";
        }
        return "none";
    }

    private static boolean partitionRulesChanged(
            List<ExclusionRule> oldRules, List<ExclusionRule> newRules) {
        Set<String> oldP = new LinkedHashSet<>();
        Set<String> newP = new LinkedHashSet<>();
        for (ExclusionRule r : oldRules) {
            if (r.kind() == ExclusionRule.Kind.PARTITION) {
                oldP.add(r.value());
            }
        }
        for (ExclusionRule r : newRules) {
            if (r.kind() == ExclusionRule.Kind.PARTITION) {
                newP.add(r.value());
            }
        }
        return !oldP.equals(newP);
    }

    private static List<ExclusionRule> parseRuleCsv(String csv) {
        List<String> tokens = parseCsvTokens(csv);
        List<ExclusionRule> rules = new ArrayList<>(tokens.size());
        for (String t : tokens) {
            rules.add(ExclusionRule.parse(t));
        }
        return rules;
    }

    private static List<String> parseCsvTokens(String csv) {
        if (csv == null || csv.isBlank()) {
            return List.of();
        }
        List<String> out = new ArrayList<>();
        for (String part : csv.split(",")) {
            String t = part.trim();
            if (!t.isEmpty()) {
                out.add(t);
            }
        }
        return out;
    }

    private static String blankToNull(String s) {
        return s == null || s.isBlank() ? null : s.trim();
    }

    private static int countFiles(Path root) {
        if (!Files.isDirectory(root)) {
            return 0;
        }
        try (Stream<Path> walk = Files.walk(root)) {
            return (int) walk.filter(Files::isRegularFile).count();
        } catch (IOException e) {
            return 0;
        }
    }

    private static String stringField(Map<String, Object> map, String key) {
        Object v = map.get(key);
        return v != null ? v.toString() : null;
    }

    private static Integer intField(Map<String, Object> map, String key) {
        Object v = map.get(key);
        if (v instanceof Number n) {
            return n.intValue();
        }
        if (v instanceof String s && !s.isBlank()) {
            try {
                return Integer.parseInt(s.trim());
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }

    private static Long longField(Map<String, Object> map, String key) {
        Object v = map.get(key);
        if (v instanceof Number n) {
            return n.longValue();
        }
        if (v instanceof String s && !s.isBlank()) {
            try {
                return Long.parseLong(s.trim());
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }

    private record StatusFile(String state, Long sweptAtModificationNumber) {}
}
