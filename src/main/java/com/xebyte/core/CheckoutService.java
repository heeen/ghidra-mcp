package com.xebyte.core;

import com.xebyte.core.checkout.Checkout;
import com.xebyte.core.checkout.CheckoutConfig;
import com.xebyte.core.checkout.CheckoutKey;
import com.xebyte.core.checkout.CheckoutLayout;
import com.xebyte.core.checkout.CheckoutRegistry;
import com.xebyte.core.checkout.CheckoutRoot;
import com.xebyte.core.checkout.CheckoutStatusMd;
import com.xebyte.core.checkout.TreeFiles;
import com.xebyte.core.checkout.DirtyQueue;
import com.xebyte.core.checkout.ExclusionEvaluator;
import com.xebyte.core.checkout.ExclusionRule;
import com.xebyte.core.checkout.ModuleOverrides;
import com.xebyte.core.checkout.SweepJob;
import com.xebyte.core.checkout.SweepProgress;
import com.xebyte.core.checkout.TreeReconciler;
import com.xebyte.core.partition.Partition;
import com.xebyte.core.partition.PartitionCascade;
import com.xebyte.core.partition.PartitionContext;
import com.xebyte.core.partition.Partitioner;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

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
 * planning by construction. Most write paths are host-filesystem only (bridge
 * marks them {@code NONE} for resource invalidation). The exception is
 * {@code /decompile_checkout_pin_module}, which stores placement on the program
 * so it survives resweeps.
 *
 * <p>Sweeps run as {@link SweepJob} on {@link CheckoutRegistry}'s daemon thread —
 * never through {@code ThreadingStrategy}.
 *
 * @since 7.2.0
 */
public class CheckoutService {

    private static final int ADOPT_SCAN_CAP = 64;
    /** One adoption at a time: a create call and the adopt-on-open scan may race for a tree. */
    private static final Object ADOPT_LOCK = new Object();
    private static final String RESOURCE_URI_PREFIX = "ghidra://decompile-checkout/";
    private static final String POLL_PATH = "/decompile_checkout_status";

    private final ProgramProvider programProvider;

    public CheckoutService(ProgramProvider programProvider) {
        this.programProvider = programProvider;
        // Auto-reconcile needs to re-resolve a Program (the observer must never
        // hold one). Only FrontEndProgramProvider registered a lookup, so
        // outside the GUI the dirty queue collected addresses and silently
        // dropped every one. Every mode has a ProgramProvider, so derive it
        // here; the GUI's cache-aware lookup still wins via IfAbsent.
        CheckoutRegistry.getInstance().setProgramLookupIfAbsent(this::lookupViaProvider);
        CheckoutRegistry.getInstance().setAdoptOnOpenIfAbsent(this::adoptOnOpen);
    }

    /**
     * Resolve a checkout's Program by domain path, then by name.
     *
     * <p>Deliberately NOT {@code ProgramProvider.resolveProgram}: a checkout
     * names one specific program (domain path, then name). Reconciling a miss
     * against whatever happens to be active would splice one program's
     * decompilation into another program's tree. A miss must stay a miss
     * ({@code resolveProgram} already returns null on a non-blank miss; this
     * path also skips the blank→current fallback).
     */
    private Program lookupViaProvider(Checkout checkout) {
        if (checkout == null || programProvider == null) {
            return null;
        }
        Program byPath = programProvider.getProgram(checkout.domainPath());
        return byPath != null ? byPath : programProvider.getProgram(checkout.programName());
    }

    // =========================================================================
    // /decompile_checkout_status — READ_ONLY poll target
    // =========================================================================

    @McpTool(path = "/decompile_checkout_status", method = "GET",
        description = "Status, config and root path of a decompilation checkout — poll "
            + "this after decompile_checkout_run(action=start), then Grep the reported root. READ_ONLY, "
            + "so it is safe to call while planning. Reports phase, progress, and freshness "
            + "against the live program. Never errors when the program is closed or the root "
            + "is missing — reports program:\"closed\" / root_present:false instead, because "
            + "that is exactly when you are asking. With no selector, lists every checkout "
            + "plus adoptable trees found on disk.",
        category = "decompile-checkout", access = ToolAccess.READ_ONLY)
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
    // /decompile_checkout_create — WRITE, no sweep
    // =========================================================================

    @McpTool(path = "/decompile_checkout_create", dryRun = false, method = "POST",
        description = "Create a decompilation checkout: a program's decompiled C "
            + "materialised as a file tree you can Grep and Glob. Use this when you need "
            + "corpus-wide search — 'which functions reference this string, constant or "
            + "peripheral' — which is impractical one function at a time. Registers the "
            + "checkout and writes checkout.json / STATUS.md; does NOT sweep (call "
            + "decompile_checkout_run(action=start)). Adopts an existing tree at the root and "
            + "reconciles it against the live program; trees this server created are also "
            + "adopted automatically when their program opens. "
            + "Unrelated to Ghidra version-control checkouts (/server/version_control/*).",
        category = "decompile-checkout", access = ToolAccess.WRITE)
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
            @Param(value = "max_file_bytes", source = ParamSource.BODY, defaultValue = "32768",
                   description = "Read-budget bytes per .c file inside a compartment "
                       + "(floored at 4096). Changing this repartitions file paths.")
            int maxFileBytes,
            @Param(value = "exclusions", source = ParamSource.BODY, defaultValue = "",
                   description = "CSV of tag:/partition:/range: exclusion specs.")
            String exclusions,
            @Param(value = "include_only", source = ParamSource.BODY, defaultValue = "",
                   description = "CSV of tag:/partition:/range: include-only specs.")
            String includeOnly,
            @Param(value = "throttle_percent", source = ParamSource.BODY, defaultValue = "10",
                   description = "Interactive yield 0..90 after each decompiled function.")
            int throttlePercent,
            @Param(value = "disassemble_missing", source = ParamSource.BODY, defaultValue = "true",
                   description = "Before partitioning, disassemble at function entries with "
                       + "no instruction yet (typical for PE .pdata imports).")
            boolean disassembleMissing) {

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
                .maxFileBytes(maxFileBytes)
                .exclusions(exclRules)
                .includeOnly(includeRules)
                .throttlePercent(throttlePercent)
                .disassembleMissing(disassembleMissing)
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

        try {
            synchronized (ADOPT_LOCK) {
                if (!Files.isRegularFile(jsonPath)) {
                    return createFresh(program, domainPath, resolvedName, requested);
                }
                String treeUrl = stringField(JsonHelper.parseJson(
                        Files.readString(jsonPath, StandardCharsets.UTF_8)), "program_url");
                String url = programUrl(program);
                if (treeUrl != null && url != null && !treeUrl.equals(url)) {
                    return Response.err("the tree at " + derivedRoot + " is a checkout of "
                            + treeUrl + ", not of " + url + " (same domain path, another "
                            + "project); pass a different root");
                }
                return adoptExisting(program, domainPath, resolvedName, derivedRoot,
                        jsonPath, requested);
            }
        } catch (IOException e) {
            return Response.err("checkout create failed: " + e.getMessage());
        } catch (IllegalArgumentException e) {
            return Response.err(e.getMessage());
        }
    }

    // =========================================================================
    // /decompile_checkout_configure — WRITE, persist + classify only (no delete/resweep)
    // =========================================================================

    @McpTool(path = "/decompile_checkout_configure", dryRun = false, method = "POST",
        description = "Change a checkout's configuration: exclusions (tag: / partition: / "
            + "range:), enabled strategies, band size, max file bytes, throttle. Exclusions "
            + "are how you keep library code out of the tree — on a driver DLL, excluding two "
            + "CRT compartments took it from 3,230 functions to 2,036. Classifies the change "
            + "and acts on it: narrowing deletes now-out-of-scope bodies immediately (leaving "
            + "them would be a lie a Grep would still hit); widening marks STALE with "
            + "pending_functions; repartitioning sets requires_full_resweep. Never starts a "
            + "sweep.",
        category = "decompile-checkout", access = ToolAccess.WRITE)
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
            @Param(value = "max_file_bytes", source = ParamSource.BODY, defaultValue = "",
                   description = "Read-budget bytes per .c file. Omit to leave unchanged. "
                       + "Changing this repartitions file paths.")
            Integer maxFileBytes,
            @Param(value = "exclusions", source = ParamSource.BODY, defaultValue = "",
                   description = "CSV of exclusion specs. Omit to leave unchanged.")
            String exclusions,
            @Param(value = "include_only", source = ParamSource.BODY, defaultValue = "",
                   description = "CSV of include-only specs. Omit to leave unchanged.")
            String includeOnly,
            @Param(value = "throttle_percent", source = ParamSource.BODY, defaultValue = "",
                   description = "Interactive yield 0..90. Omit to leave unchanged.")
            Integer throttlePercent,
            @Param(value = "disassemble_missing", source = ParamSource.BODY, defaultValue = "",
                   description = "Disassemble at entries without instructions before sweep. "
                       + "Omit to leave unchanged.")
            Boolean disassembleMissing) {

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
                .analysisWaitSeconds(old.analysisWaitSeconds())
                .maxFileBytes(old.maxFileBytes())
                .disassembleMissing(old.disassembleMissing());

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
            if (maxFileBytes != null) {
                b.maxFileBytes(maxFileBytes);
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
            if (disassembleMissing != null) {
                b.disassembleMissing(disassembleMissing);
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
                strategiesTouched, bandSize != null, maxFileBytes != null,
                exclusionsTouched, includeTouched);

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
    // /decompile_checkout_run — WRITE, start or stop the sweep
    // =========================================================================

    @McpTool(path = "/decompile_checkout_run", dryRun = false, method = "POST",
        description = "Start or stop the sweep that fills a checkout's tree. action=start enqueues it "
            + "(then poll decompile_checkout_status): returns in milliseconds with phase queued and "
            + "the resource URI. Sweeps run one at a time JVM-wide and yield to auto-analysis and to "
            + "interactive requests. Measured: ~4 s for a 700-function firmware, ~28 s for a "
            + "3,200-function driver DLL, ~11 min for a 25,000-function static binary. action=stop "
            + "cancels a queued or running sweep and is idempotent: stopping an idle or complete "
            + "checkout is success, not an error. The partial tree is left in place and STATUS.md "
            + "records state: cancelled, so whatever was already written stays safe to Grep.",
        category = "decompile-checkout", access = ToolAccess.WRITE)
    public Response checkoutRun(
            @Param(value = "checkout", source = ParamSource.BODY,
                   description = "Checkout id, program name, or domain path.")
            String checkoutSelector,
            @Param(value = "action", source = ParamSource.BODY,
                   description = "start (enqueue the sweep) or stop (cancel it).")
            String action) {
        String what = action == null ? "" : action.trim().toLowerCase();
        return switch (what) {
            case "start" -> startSweep(checkoutSelector);
            case "stop" -> stopSweep(checkoutSelector);
            default -> Response.err("action must be start or stop");
        };
    }

    // =========================================================================
    // decompile_checkout_run(action=start) — WRITE, enqueue SweepJob
    // =========================================================================

    /** Enqueue the sweep that fills a checkout's tree. */
    private Response startSweep(
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
        try {
            CheckoutRegistry.getInstance().requestSweep(checkout, live);
        } catch (IOException e) {
            return Response.err("failed to update STATUS.md: " + e.getMessage());
        }
        return Response.ok(startResponse(checkout));
    }

    // =========================================================================
    // decompile_checkout_run(action=stop) — WRITE, idempotent
    // =========================================================================

    /** Cancel a queued or running sweep; stopping an idle checkout is success. */
    private Response stopSweep(
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
                    .cancelSweep(checkout.id(), "cancelled by decompile_checkout_run(action=stop)");
            checkout.setProgress(checkout.progress()
                    .withPhase(SweepProgress.Phase.CANCELLED)
                    .withLastError("cancelled by decompile_checkout_run(action=stop)"));
            cancelled = true;
            try {
                CheckoutStatusMd.write(checkout, "cancelled");
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
    // /decompile_checkout_refresh — WRITE, reconcile tree with program
    // =========================================================================

    @McpTool(path = "/decompile_checkout_refresh", dryRun = false, method = "POST",
        description = "Reconcile a checkout tree with the live program. Three primitives "
            + "cover every change: replace (re-decompile a function still in both), insert "
            + "(place a new function by pin or address containment, split the file if over "
            + "budget), remove (drop a deleted function's block and its file if emptied). "
            + "Pass addresses to target a set; omit them for a full index-driven pass that "
            + "compares address sets and input fingerprints and decompiles only mismatches. "
            + "There is no mark_stale — the reconciler is closed under every program change. "
            + "Filesystem-only: does not mutate program state. Bridge-only — the agent never "
            + "calls this; the bridge invokes it after writes so the tree stays current "
            + "without agent reasoning.",
        category = "decompile-checkout", access = ToolAccess.WRITE, internal = true)
    public Response checkoutRefresh(
            @Param(value = "checkout", source = ParamSource.BODY,
                   description = "Checkout id, program name, or domain path.")
            String checkoutSelector,
            @Param(value = "addresses", source = ParamSource.BODY, defaultValue = "",
                   description = "CSV of function entry addresses to reconcile. Empty = "
                       + "full index-driven reconcile (address-set diff + ifp compare).")
            String addresses,
            @Param(value = "program", defaultValue = "",
                   description = "Target program name (omit for the active program).")
            String programName) {

        CheckoutRegistry.ResolveResult resolved =
                CheckoutRegistry.getInstance().resolve(checkoutSelector);
        if (!resolved.isOk()) {
            return Response.err(resolved.error());
        }
        Checkout checkout = resolved.checkout();
        SweepProgress.Phase phase = checkout.progress().phase();
        String phaseName = phase.name().toLowerCase(Locale.ROOT);

        if (phase == SweepProgress.Phase.QUEUED
                || phase == SweepProgress.Phase.WAITING_FOR_ANALYSIS
                || phase == SweepProgress.Phase.PARTITIONING
                || phase == SweepProgress.Phase.DECOMPILING) {
            // Sweep will produce fresh text — racing it would corrupt mid-write files.
            Map<String, Object> busy = TreeReconciler.ReconcileResult.of(
                    List.of(), List.of(), List.of(), List.of(), List.of(),
                    List.of(), List.of(),
                    0, 0, 0, 0L, checkout.progress().splicedSinceSweep())
                    .toMap(checkout.id(), true, phaseName);
            busy.put("reason", "sweep_in_progress");
            return Response.ok(busy);
        }

        List<String> addrList = parseCsvTokens(addresses);

        Program live = findOpenProgram(checkout);
        if (live == null || live.isClosed()) {
            ServiceUtils.ProgramOrError pe =
                    ServiceUtils.getProgramOrError(programProvider, programName);
            if (pe.hasError()) {
                return Response.err("program is closed; cannot refresh checkout");
            }
            live = pe.program();
        }

        // Empty addresses → full reconcile. The old mark_stale path is gone:
        // unbounded edits are just a full pass. A caller's spelling (0x1000, ram:1000)
        // becomes the tree's key, which needs the program to know the default space.
        Set<String> addrSet = null;
        if (!addrList.isEmpty()) {
            addrSet = new LinkedHashSet<>();
            for (String raw : addrList) {
                addrSet.add(AddressKeys.canonical(live, raw));
            }
        }
        try {
            TreeReconciler.ReconcileResult result =
                    TreeReconciler.reconcile(checkout, live, addrSet);
            return Response.ok(result.toMap(
                    checkout.id(), false,
                    checkout.progress().phase().name().toLowerCase(Locale.ROOT)));
        } catch (IOException e) {
            return Response.err("checkout refresh failed: " + e.getMessage());
        }
    }

    // =========================================================================
    // /decompile_checkout_pin_module — WRITE, program property (survives resweep)
    // =========================================================================

    @McpTool(path = "/decompile_checkout_pin_module", dryRun = false, method = "POST",
        description = "Pin a function to a checkout compartment forever. Use this when you "
            + "have learned the real module boundary — e.g. after reading evidence that a "
            + "function belongs with driver code despite the cascade placing it in an "
            + "address band — and you want that placement to stick across resweeps, "
            + "checkout delete/recreate, and every other tool. Stored as a program property "
            + "map (CheckoutModule) at the function entry, not in checkout config. Empty "
            + "module string unpins. Does not rewrite the tree by itself — the next sweep "
            + "(or reconcile) honours the pin ahead of the whole partitioner cascade.",
        category = "decompile-checkout", access = ToolAccess.WRITE)
    public Response checkoutPinModule(
            @Param(value = "function", paramType = Param.FUNCTION_REF, source = ParamSource.BODY,
                   description = "Function name or entry address to pin.")
            String function,
            @Param(value = "module", source = ParamSource.BODY, defaultValue = "",
                   description = "Compartment slug to pin to. Empty string removes the pin.")
            String module,
            @Param(value = "program", defaultValue = "",
                   description = "Target program name (omit for the active program).")
            String programName) {

        ServiceUtils.ProgramOrError pe =
                ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) {
            return pe.error();
        }
        Program program = pe.program();

        if (function == null || function.isBlank()) {
            return Response.err("function is required (name or address)");
        }
        ServiceUtils.FunctionOrError funcLookup = ServiceUtils.getFunctionOrError(program, function.trim());
        if (funcLookup.hasError()) return funcLookup.error();
        Function func = funcLookup.function();

        String slug = module != null ? module.trim() : "";
        boolean unpin = slug.isEmpty();
        try {
            ModuleOverrides.set(program, func.getEntryPoint(), unpin ? null : slug);
        } catch (IllegalArgumentException e) {
            return Response.err(e.getMessage());
        } catch (Exception e) {
            return Response.err("pin_module failed: " + e.getMessage());
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("success", true);
        out.put("function", func.getName());
        out.put("address", AddressKeys.of(func));
        out.put("pinned", !unpin);
        out.put("module", unpin ? null : slug);
        out.put("map", ModuleOverrides.MAP_NAME);
        out.put("note", unpin
                ? "Pin removed; next sweep will reclassify this function."
                : "Pin stored on the program; next sweep places this function in '"
                    + slug + "' with method=pinned (never reclassified). Call save_program "
                    + "to persist.");
        out.put("program", program.getName());
        return Response.ok(out);
    }

    // =========================================================================
    // /decompile_checkout_delete — DESTRUCTIVE
    // =========================================================================

    @McpTool(path = "/decompile_checkout_delete", dryRun = false, method = "POST",
        description = "Deregister a checkout; with delete_files=true also remove its "
            + "on-disk tree (containment-checked). The program itself is untouched — this "
            + "only removes generated files.",
        category = "decompile-checkout", access = ToolAccess.DESTRUCTIVE)
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
        checkout.setProgramUrl(programUrl(program));
        writeCheckoutJson(checkout);
        // Nothing has been swept yet — "dirty" would mean a crash mid-sweep.
        CheckoutStatusMd.write(checkout, "empty");
        // Program is already open — attach now so GUI/script edits reach the tree
        // without waiting for a later getProgram cache hit.
        CheckoutRegistry.getInstance().ensureObserver(program);

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
        checkout.setProgramUrl(programUrl(program));

        StatusFile statusFile = readStatusMd(derivedRoot);
        Long sweptAt = statusFile.sweptAtModificationNumber();
        Long reconciledAt = statusFile.reconciledAtModificationNumber();
        long liveMod = program.getModificationNumber();
        if (existing != null) {
            // Already tracked in this session, but the files may have been replaced under it
            // (measured: a tree copied over a registered root kept the old root in AGENTS.md
            // while status said in_sync). A full reconcile of an intact tree writes nothing
            // and decompiles nothing, so check rather than trust.
            writeCheckoutJson(checkout);
            CheckoutRegistry.getInstance().ensureObserver(program);
            CheckoutRegistry.getInstance().dirtyQueue().markNeedsReconcile(checkout.id());
            Map<String, Object> out = statusMap(checkout);
            out.put("adopted", true);
            out.put("files_on_disk", countFiles(derivedRoot));
            out.put("fresh", Boolean.TRUE.equals(out.get("in_sync")));
            return Response.ok(out);
        }
        // The numbers on disk belong to the session that wrote them. From another open (any
        // server restart) they say nothing about this program, so the tree is rebased onto
        // this session at its current number; the full reconcile queued below then checks
        // every block against the program as it is.
        boolean sameSession = com.xebyte.core.ProgramRevision.epoch(program).equals(statusFile.fields().get("session"));
        if (sweptAt != null && !sameSession) {
            sweptAt = liveMod;
            reconciledAt = liveMod;
        }
        if (sweptAt != null && checkout.progress().sweptAtModification() == null) {
            checkout.setProgress(checkout.progress()
                    .withPhase(SweepProgress.Phase.COMPLETE)
                    .sweptAt(sweptAt)
                    .reconciledAt(reconciledAt,
                            statusFile.count("spliced_since_sweep"),
                            statusFile.count("structural_since_sweep")));
            checkout.noteSession(program);
        }

        // A dirty STATUS.md means the previous writer did not finish (crash /
        // cancel / kill); stale was already known to diverge. Re-derive id finds the
        // same tree across a Ghidra restart; STALE tells the agent Grep results may be
        // incomplete. Otherwise the tree was current when last written, but nothing says
        // the program has not changed since (modification numbers start over each time a
        // program opens): a full reconcile re-checks every block's fingerprint.
        String state = statusFile.state();
        boolean stale = "dirty".equalsIgnoreCase(state) || "stale".equalsIgnoreCase(state);
        if (stale) {
            String why = statusFile.fields().get("last_error");
            checkout.setProgress(checkout.progress()
                    .withPhase(SweepProgress.Phase.STALE)
                    .withLastError(why != null ? why
                            : "previous sweep did not finish (STATUS.md state=" + state + ")"));
        }

        // The tree may have been moved or copied: checkout.json names this checkout from
        // now on, as the derived files will after the reconcile below.
        writeCheckoutJson(checkout);
        CheckoutRegistry.getInstance().ensureObserver(program);
        if (!stale && sweptAt != null) {
            CheckoutRegistry.getInstance().dirtyQueue().markNeedsReconcile(checkout.id());
        }

        int files = countFiles(derivedRoot);
        Map<String, Object> out = statusMap(checkout);
        out.put("adopted", true);
        out.put("files_on_disk", files);
        out.put("swept_at_modification_number", sweptAt);
        out.put("live_modification_number", liveMod);
        out.put("previous_session", !sameSession);
        out.put("fresh", false);
        out.put("reconcile_queued", !stale && sweptAt != null);
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
        out.put("disassembled_on_demand", progress.disassembledOnDemand());
        out.put("disassembly_failed", progress.disassemblyFailed());
        out.put("bodies_recomputed", progress.bodiesRecomputed());
        out.put("body_recompute_failed", progress.bodyRecomputeFailed());
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
        out.put("spliced_since_sweep", progress.splicedSinceSweep());
        out.put("structural_since_sweep", progress.structuralSinceSweep());
        out.put("swept_at_modification_number", progress.sweptAtModification());
        out.put("reconciled_at_modification_number", progress.reconciledAtModification());
        Checkout.Session session = checkout.session();
        if (session != null) {
            Map<String, Object> s = new LinkedHashMap<>();
            s.put("epoch", session.epoch());
            s.put("saved_time", session.savedTime());
            if (session.fileVersion() != null) {
                s.put("file_version", session.fileVersion());
            }
            s.put("includes_unsaved_edits", session.unsavedEdits());
            if (live != null) {
                // The numbers above compare with the live program's only within one open.
                s.put("current", session.epoch().equals(com.xebyte.core.ProgramRevision.epoch(live)));
            }
            out.put("session", s);
        }
        DirtyQueue queue = CheckoutRegistry.getInstance().dirtyQueue();
        boolean pendingFull = queue.pendingNeedsReconcile(checkout.id());
        int pending = queue.pendingAddressCount(checkout.id());
        out.put("pending_dirty", pendingFull ? "full_reconcile" : pending);
        if (live != null) {
            // The one answer an agent needs before trusting a grep: does the tree describe
            // the program as it is right now? Every change the tree shows is queued by the
            // observer, so: swept, not stale, and nothing queued or running. (Modification
            // numbers also move for changes no block shows, so they cannot answer this.)
            out.put("in_sync", progress.phase() != SweepProgress.Phase.STALE
                    && progress.sweptAtModification() != null
                    && !queue.hasPending(checkout.id()));
        }
        out.put("resource_uri", RESOURCE_URI_PREFIX + checkout.id());
        out.put("config", configToMap(checkout.config()));

        if (rootPresent) {
            StatusFile statusFile = readStatusMd(root);
            out.put("status_state", statusFile.state());
        } else {
            out.put("status_state", null);
        }

        return out;
    }

    /**
     * Directories that may hold a checkout: the roots a caller chose (the registry remembers
     * them; first, so the cap can never crowd out a root someone named deliberately), then
     * the default parent's children by name. At most {@link #ADOPT_SCAN_CAP}.
     */
    private static List<Path> candidateRoots() throws IOException {
        List<Path> dirs = new ArrayList<>();
        Path parent = CheckoutRegistry.defaultParent();
        if (Files.isDirectory(parent)) {
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(parent)) {
                for (Path entry : stream) {
                    if (Files.isDirectory(entry)) {
                        dirs.add(entry);
                    }
                }
            }
        }
        dirs.sort(Comparator.comparing(p -> p.getFileName().toString()));
        dirs.addAll(0, CheckoutRegistry.getInstance().knownRoots().list());
        return dirs.size() > ADOPT_SCAN_CAP ? dirs.subList(0, ADOPT_SCAN_CAP) : dirs;
    }

    private static Set<String> registeredRoots() {
        Set<String> roots = new LinkedHashSet<>();
        for (Checkout c : CheckoutRegistry.getInstance().all()) {
            roots.add(c.root().path().toAbsolutePath().normalize().toString());
        }
        return roots;
    }

    /**
     * Adopt every tree of this program found on disk, as {@code decompile_checkout_create}
     * would: register it, observe the program, reconcile. Runs once per open (see
     * {@link CheckoutRegistry#programOpened}). A tree is this program's when its
     * {@code checkout.json} names the same domain path and program URL. A tree from before
     * the URL was recorded is taken only from a root this instance created; one under the
     * default parent, which every server on the machine shares, waits for a create call.
     */
    private void adoptOnOpen(Program program) {
        String domainPath = domainPathOf(program);
        String name = program.getName();
        String url = programUrl(program);
        Path defaultRoot = deriveRootPath(domainPath, name, CheckoutConfig.builder().build());
        try {
            Set<Path> known = new LinkedHashSet<>();
            for (Path p : CheckoutRegistry.getInstance().knownRoots().list()) {
                known.add(p.toAbsolutePath().normalize());
            }
            for (Path dir : candidateRoots()) {
                Path abs = dir.toAbsolutePath().normalize();
                Path json = abs.resolve(CheckoutLayout.checkoutJson());
                if (!Files.isRegularFile(json)) {
                    continue;
                }
                Map<String, Object> disk;
                try {
                    disk = JsonHelper.parseJson(Files.readString(json, StandardCharsets.UTF_8));
                } catch (IOException | RuntimeException e) {
                    continue;
                }
                if (!domainPath.equals(stringField(disk, "domain_path"))) {
                    continue;
                }
                String treeUrl = stringField(disk, "program_url");
                if (treeUrl != null ? !treeUrl.equals(url) : !known.contains(abs)) {
                    continue;
                }
                CheckoutConfig requested = CheckoutConfig.builder()
                        .rootPath(abs.equals(defaultRoot) ? null : abs.toString())
                        .build();
                synchronized (ADOPT_LOCK) {
                    if (program.isClosed() || registeredRoots().contains(abs.toString())) {
                        continue;
                    }
                    Response r = adoptExisting(program, domainPath, name, abs, json, requested);
                    if (r instanceof Response.Ok) {
                        Msg.info(this, "Adopted decompilation checkout of " + domainPath + " at "
                                + abs + " on open");
                    }
                }
            }
        } catch (IOException e) {
            Msg.warn(this, "Scanning for checkouts of " + domainPath + " failed: " + e.getMessage());
        }
    }

    private List<Map<String, Object>> scanAdoptable(Set<String> knownRoots) {
        List<Map<String, Object>> found = new ArrayList<>();
        try {
            for (Path dir : candidateRoots()) {
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
                row.put("program_url", stringField(disk, "program_url"));
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

    /**
     * The program's identity beyond its domain path: the repository URL when it is versioned
     * (the same on every machine and across restarts), else the local project's URL. Null
     * for a program outside any project.
     */
    static String programUrl(Program program) {
        DomainFile df = program.getDomainFile();
        if (df == null) {
            return null;
        }
        try {
            java.net.URL url = df.isVersioned() ? df.getSharedProjectURL(null) : df.getLocalProjectURL(null);
            return url != null ? url.toString() : null;
        } catch (RuntimeException e) {
            return null;
        }
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
        if (checkout.programUrl() != null) {
            payload.put("program_url", checkout.programUrl());
        }
        payload.putAll(configToMap(checkout.config()));
        String json = JsonHelper.toJson(payload) + "\n";
        checkout.root().writeFile(Path.of(CheckoutLayout.checkoutJson()), json);
    }

    private static StatusFile readStatusMd(Path root) {
        Path statusPath = root.resolve(CheckoutLayout.statusMd());
        Map<String, String> fields = new LinkedHashMap<>();
        if (Files.isRegularFile(statusPath)) {
            try {
                for (String line : Files.readString(statusPath, StandardCharsets.UTF_8).split("\n")) {
                    int colon = line.indexOf(':');
                    if (colon > 0 && !line.startsWith("#")) {
                        String value = line.substring(colon + 1).trim();
                        if (!value.isEmpty()) {
                            fields.put(line.substring(0, colon).trim(), value);
                        }
                    }
                }
            } catch (IOException e) {
                // unreadable reads as absent
            }
        }
        return new StatusFile(fields);
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
        Integer maxFile = intField(disk, "max_file_bytes");
        if (maxFile != null) {
            b.maxFileBytes(maxFile);
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
        Boolean disassembleMissing = boolField(disk, "disassemble_missing");
        if (disassembleMissing != null) {
            b.disassembleMissing(disassembleMissing);
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
        m.put("max_file_bytes", cfg.maxFileBytes());
        m.put("exclusions", rulesToSpecs(cfg.exclusions()));
        m.put("include_only", rulesToSpecs(cfg.includeOnly()));
        m.put("throttle_percent", cfg.throttlePercent());
        m.put("decompile_timeout_seconds", cfg.decompileTimeoutSeconds());
        m.put("analysis_wait_seconds", cfg.analysisWaitSeconds());
        m.put("disassemble_missing", cfg.disassembleMissing());
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
                // A full reconcile under the new config: it drops what is now out of scope
                // and re-renders the tree exactly as a sweep with that config would.
                TreeReconciler.ReconcileResult r = TreeReconciler.reconcile(checkout, live, null);
                out.put("action", r.sweepQueued() ? "sweep_queued" : "deleted_out_of_scope_functions");
                out.put("functions_removed", r.removed().size());
            }
            case "widening" -> {
                int pending = estimatePendingFunctions(checkout, live, updated);
                checkout.setProgress(checkout.progress()
                        .withPhase(SweepProgress.Phase.STALE)
                        .withLastError("config widened; resweep needed for pending functions"));
                out.put("action", "marked_stale");
                out.put("pending_functions", pending);
                CheckoutStatusMd.write(checkout, "stale");
            }
            case "repartitioning" -> {
                checkout.setProgress(checkout.progress()
                        .withPhase(SweepProgress.Phase.STALE)
                        .withLastError(
                                "config repartitions compartments; /decompile_checkout_run start will wipe "
                                        + "modules/ and rewrite"));
                out.put("action", "marked_stale_full_resweep");
                out.put("requires_full_resweep", true);
                int pending = estimatePendingFunctions(checkout, live, updated);
                out.put("pending_functions", pending);
                CheckoutStatusMd.write(checkout, "stale");
            }
            case "mixed" -> {
                // Apply the narrow half immediately, then mark STALE for the
                // newly-included remainder — never auto-sweep.
                if (live != null && !live.isClosed()) {
                    out.put("functions_removed",
                            TreeReconciler.reconcile(checkout, live, null).removed().size());
                }
                int pending = estimatePendingFunctions(checkout, live, updated);
                checkout.setProgress(checkout.progress()
                        .withPhase(SweepProgress.Phase.STALE)
                        .withLastError("config mixed narrow+widen; resweep needed"));
                out.put("action", "narrowed_and_marked_stale");
                out.put("pending_functions", pending);
                CheckoutStatusMd.write(checkout, "stale");
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
                        String hex = AddressKeys.of(func);
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
                    String hex = AddressKeys.of(func);
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
                    out.add(AddressKeys.normalize(line.substring(0, tab)));
                }
            }
            return out;
        } catch (IOException e) {
            return Set.of();
        }
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
            boolean maxFileBytesTouched,
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
        // File paths are derived from the byte budget; a change moves every
        // modules/<slug>/*.c name → full resweep, same as band/strategy edits.
        if (maxFileBytesTouched && old.maxFileBytes() != updated.maxFileBytes()) {
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

    private static Boolean boolField(Map<String, Object> map, String key) {
        Object v = map.get(key);
        if (v instanceof Boolean b) {
            return b;
        }
        if (v instanceof String s && !s.isBlank()) {
            return Boolean.parseBoolean(s.trim());
        }
        return null;
    }

    /** STATUS.md's {@code key: value} lines; a blank value reads as absent. */
    private record StatusFile(Map<String, String> fields) {
        String state() {
            return fields.get("state");
        }

        Long number(String key) {
            try {
                return fields.containsKey(key) ? Long.parseLong(fields.get(key)) : null;
            } catch (NumberFormatException e) {
                return null;
            }
        }

        int count(String key) {
            Long n = number(key);
            return n == null ? 0 : n.intValue();
        }

        Long sweptAtModificationNumber() {
            return number("swept_at_modification_number");
        }

        /** What the tree reflects: the last reconcile, else the sweep (older files lack it). */
        Long reconciledAtModificationNumber() {
            Long reconciled = number("reconciled_at_modification_number");
            return reconciled != null ? reconciled : sweptAtModificationNumber();
        }
    }
}
