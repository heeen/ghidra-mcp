package com.xebyte.core;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Hand-authored {@link AnnotationScanner.ToolDescriptor}s for HTTP routes that are
 * registered directly via {@code createContext}/{@code safeContext} in
 * {@link com.xebyte.GhidraMCPPlugin} and/or
 * {@link com.xebyte.headless.GhidraMCPHeadlessServer}, rather than discovered via
 * {@code @McpTool} reflection (utility/server/project/tool routes that predate the
 * annotation-scanner convention). Without this registry these routes are fully live
 * and callable but invisible in {@code /mcp/schema} -- the Python bridge's dynamic
 * tool discovery reads only that schema, so an AI agent connected through the bridge
 * could never see or call them (found via a live-schema-vs-catalog diff, v6.0.0).
 *
 * <p>Path/method/category/description/params are sourced verbatim from
 * {@code tests/endpoints.json}'s hand-registered entries (see
 * {@code RegenerateEndpointsJson}'s "preserved (hand-registered)" merge rule --
 * that file is the existing source of truth for these routes' metadata). The
 * param NAMES come from there and their source is inferred from the route's HTTP
 * method (GET -&gt; query, POST -&gt; body); the catalog does not track per-param
 * type/required detail for hand-registered routes, and every one of these handlers
 * already parses its own params permissively, so marking them optional-string is
 * accurate enough for tool discovery without overclaiming precision the source
 * data doesn't have.
 *
 * <p>The param DESCRIPTIONS, by contrast, are written here against what the
 * handlers actually do, because there is nowhere else for them to come from: an
 * {@code @McpTool} method gets them from {@code @Param(description = ...)}, and a
 * hand-registered route has no annotation at all. Several of these parameters are
 * mode-dependent (the GUI plugin drives the already-open project and ignores the
 * repository selector; the headless server holds a real server connection and
 * reads it) or accepted and never read, and the descriptions say which.
 *
 * <p>{@code ManualToolDescriptorsParityTest} enforces that every path a server
 * registers manually has an entry here, so a future added route can't silently
 * repeat this gap.
 */
public final class ManualToolDescriptors {

    private ManualToolDescriptors() {}

    /**
     * Every hand-coded route the GUI plugin registers on <em>all</em> transports
     * (see {@code GhidraMCPPlugin.registerHandCodedRoutes}).
     *
     * <p>Named once because two scanners have to advertise the same set: the plugin's
     * for TCP and {@link ServerManager}'s for the Unix socket. ServerManager built its
     * own list and had none of these, so a bridge on UDS could not see them even after
     * the routes themselves were shared.
     */
    public static final List<String> SHARED_ROUTES = List.of(
        "/batch_apply_documentation",
        "/check_connection",
        "/mcp/health",
        "/mcp/schema",
        "/open_project",
        "/tool/goto_address",
        "/tool/launch_codebrowser",
        "/tool/running_tools"
    );


    private static AnnotationScanner.ParamDescriptor p(String name, String source, String description) {
        return new AnnotationScanner.ParamDescriptor(name, "string", source, true, null, description, "", false);
    }

    /**
     * Build a descriptor list from alternating name/description pairs.
     *
     * <p>Pairs, not bare names, on purpose: a hand-registered route's parameters
     * reach {@code /mcp/schema} through here and nowhere else, so a parameter
     * added without a description lands in every client's {@code inputSchema}
     * with nothing to say. The odd-count guard makes forgetting one a build-time
     * failure rather than a silent blank.
     *
     * @throws IllegalArgumentException if the varargs are not name/description pairs
     */
    private static List<AnnotationScanner.ParamDescriptor> params(String method, String... nameThenDescription) {
        if (nameThenDescription.length % 2 != 0) {
            throw new IllegalArgumentException("ManualToolDescriptors.params() takes alternating"
                + " name/description pairs; got an odd argument count ("
                + nameThenDescription.length + "). Every hand-registered parameter needs a description.");
        }
        String source = "GET".equalsIgnoreCase(method) ? "query" : "body";
        List<AnnotationScanner.ParamDescriptor> out = new java.util.ArrayList<>();
        for (int i = 0; i < nameThenDescription.length; i += 2) {
            out.add(p(nameThenDescription[i], source, nameThenDescription[i + 1]));
        }
        return out;
    }

    private static void add(Map<String, AnnotationScanner.ToolDescriptor> m,
            String path, String method, String category, String description,
            ToolAccess access, String... paramPairs) {
        m.put(path, new AnnotationScanner.ToolDescriptor(
            path, method, description, category, "", access, false, params(method, paramPairs)));
    }

    /** Keyed by path. Built once; entries never mutate after class init. */
    private static final Map<String, AnnotationScanner.ToolDescriptor> ALL = buildAll();

    private static Map<String, AnnotationScanner.ToolDescriptor> buildAll() {
        Map<String, AnnotationScanner.ToolDescriptor> m = new LinkedHashMap<>();
        add(m, "/batch_apply_documentation", "POST", "analysis",
            "Apply all documentation to a function in one call", ToolAccess.WRITE,
            "address", "Function entry address, as 0x<hex> or <space>:<hex>. Required: every step below is applied to the function at this address.",
            "name", "New function name. Omit or leave empty to skip the rename step.",
            "prototype", "Full C signature. Applied BEFORE the comment step on purpose, because setting a prototype wipes the plate comment.",
            "calling_convention", "Convention for the prototype step, e.g. __stdcall. Read only when prototype is also given.",
            "variable_types", "Object mapping variable name to new type. Each is applied on its own; the step reports set/failed counts plus per-variable errors.",
            "variable_renames", "Object mapping each variable's CURRENT name to its new name.",
            "plate_comment", "Plate comment for the function. Pass real multi-line text: an escaped newline sequence is stored as those two literal characters, not as a line break.",
            "decompiler_comments", "Array of {address, comment} objects setting PRE comments. Each entry carries its own address; the top-level address is the function entry only.",
            "disassembly_comments", "Array of {address, comment} objects setting EOL comments. Each entry carries its own address.",
            "goto", "True navigates the CodeBrowser to address before anything else. Must be a JSON boolean: any other type is read as FALSE. Default false.",
            "score", "True (the default) appends a compact completeness score. Must be a JSON boolean: any other type falls back to the default and is read as TRUE, so the string false does not switch it off.",
            "program", "Accepted but not read by this route: every step runs against the active program. Use the individual tools when you need to target a specific one.");
        add(m, "/check_connection", "GET", "utility",
            "Liveness probe: {status, server_kind (gui/headless), version, program when one is current}. Cheap and\n"
            + " token-less, unlike the fuller /mcp/health; both servers answer it identically.",
            ToolAccess.READ_ONLY);
        add(m, "/mcp/health", "GET", "utility", "Server health: kind (gui/headless), build, current program, uptime, HTTP pool, memory, endpoint count", ToolAccess.READ_ONLY);
        add(m, "/mcp/schema", "GET", "utility", "Machine-readable API schema with endpoint metadata", ToolAccess.READ_ONLY);
        // /move_file and /move_folder used to live here: manually routed in the
        // headless server, absent from the GUI/FrontEnd server entirely, and so
        // present in tests/endpoints.json but missing from the live /mcp/schema
        // that the bridge discovers from. They are now @McpTool methods on
        // ProgramScriptService.{moveFile,moveFolder}, which registers them in
        // every mode. Do not re-add them here -- double registration throws
        // "cannot add context to list" on headless startup (see #180).
        add(m, "/open_project", "POST", "headless",
            "Open a Ghidra project: local .gpr/directory, or ghidra://host[:port]/repo "
            + "(persistent shared project; does not auto-open repo files — max ~5 shared "
            + "programs). GUI mode adds optional `headless` (default true) and `program`; "
            + "the headless server ignores those. Local tree mirrors YOUR working copy.",
            ToolAccess.WRITE,
            "path", "Path to the project: its .gpr file or the project directory holding it.",
            "headless", "GUI mode only. True (the default) loads the project into the FrontEnd tool without opening a CodeBrowser window; false launches one for `program`. The headless server ignores it.",
            "program", "GUI mode only, and only when headless=false: the DomainFile path to open in the launched CodeBrowser.");
        add(m, "/tool/goto_address", "POST", "utility", "Navigate CodeBrowser listing and decompiler to a specific address", ToolAccess.WRITE,
            "address", "Address to navigate to, as 0x<hex> or <space>:<hex>. GUI mode only — it moves a CodeBrowser window.");
        add(m, "/tool/launch_codebrowser", "POST", "utility", "Open a file in CodeBrowser, launching a new one if needed", ToolAccess.WRITE,
            "path", "DomainFile path of the program to open, e.g. /Vanilla/1.13c/D2Common.dll. GUI mode only.");
        add(m, "/tool/running_tools", "GET", "utility", "List all running Ghidra tool windows", ToolAccess.READ_ONLY);
        return m;
    }

    /**
     * Add the descriptor for each requested path to {@code scanner}'s schema output.
     * Fails loudly (not silently) if a path has no registered descriptor -- that means
     * either this registry drifted from a server's actual createContext/safeContext
     * calls, or a new manual route was added without a matching entry here.
     *
     * @throws IllegalStateException if any path is not present in {@link #ALL}
     */
    public static void addAll(AnnotationScanner scanner, String... paths) {
        addAll(scanner, java.util.Arrays.asList(paths));
    }

    public static void addAll(AnnotationScanner scanner, java.util.Collection<String> paths) {
        for (String path : paths) {
            AnnotationScanner.ToolDescriptor td = ALL.get(path);
            if (td == null) {
                throw new IllegalStateException("No ManualToolDescriptors entry for \"" + path
                    + "\" -- add one to ManualToolDescriptors.buildAll(), or remove the"
                    + " createContext/safeContext call if the route no longer exists.");
            }
            scanner.addManualDescriptor(td);
        }
    }

    /** Every path this registry knows a descriptor for (for parity tests). */
    public static java.util.Set<String> knownPaths() {
        return java.util.Collections.unmodifiableSet(ALL.keySet());
    }

    /**
     * Every descriptor, keyed by path (for parity tests). These categories are
     * published in {@code /mcp/schema} exactly like the annotation-scanned ones,
     * so they are the runtime tool group for these routes and
     * {@code tests/endpoints.json} must agree with them.
     */
    public static Map<String, AnnotationScanner.ToolDescriptor> descriptors() {
        return java.util.Collections.unmodifiableMap(ALL);
    }
}
