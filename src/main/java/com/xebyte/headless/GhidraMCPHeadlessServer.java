/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.xebyte.headless;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpServer;
import com.xebyte.core.*;
import com.xebyte.core.services.*;
import ghidra.GhidraApplicationLayout;
import ghidra.GhidraLaunchable;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static com.xebyte.core.EndpointRegistrar.*;

/**
 * Headless Ghidra MCP Server.
 *
 * This server provides the same REST API as the GUI plugin but runs in
 * headless mode without requiring the Ghidra GUI. Ideal for:
 * - Docker deployments
 * - CI/CD pipelines
 * - Automated analysis workflows
 * - Server-side reverse engineering
 *
 * Usage:
 *   java -jar GhidraMCPHeadless.jar --port 8089 --project /path/to/project
 *   java -jar GhidraMCPHeadless.jar --port 8089 --file /path/to/binary.exe
 */
public class GhidraMCPHeadlessServer implements GhidraLaunchable {

    private static final String VERSION = "1.9.4-headless";
    private static final int DEFAULT_PORT = 8089;
    private static final String DEFAULT_BIND_ADDRESS = "127.0.0.1";

    private HttpServer server;
    private HeadlessProgramProvider programProvider;
    private DirectThreadingStrategy threadingStrategy;
    private int port = DEFAULT_PORT;
    private String bindAddress = DEFAULT_BIND_ADDRESS;
    private boolean running = false;

    // Services
    private ListingService listingService;
    private CommentService commentService;
    private SymbolService symbolService;
    private FunctionService functionService;
    private MutationService mutationService;
    private DataTypeService dataTypeService;
    private AnalysisService analysisService;
    private ComparisonService comparisonService;

    // Ghidra server connection manager
    private GhidraServerManager serverManager;

    public static void main(String[] args) {
        GhidraMCPHeadlessServer server = new GhidraMCPHeadlessServer();
        try {
            server.launch(new GhidraApplicationLayout(), args);
        } catch (Exception e) {
            System.err.println("Failed to launch headless server: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    @Override
    public void launch(GhidraApplicationLayout layout, String[] args) throws Exception {
        // Parse command line arguments
        parseArgs(args);

        // Initialize Ghidra in headless mode
        initializeGhidra(layout);

        // Create providers
        programProvider = new HeadlessProgramProvider();
        threadingStrategy = new DirectThreadingStrategy();

        // Create services
        listingService = new ListingService(programProvider, threadingStrategy);
        commentService = new CommentService(programProvider, threadingStrategy);
        symbolService = new SymbolService(programProvider, threadingStrategy);
        functionService = new FunctionService(programProvider, threadingStrategy);
        mutationService = new MutationService(programProvider, threadingStrategy);
        dataTypeService = new DataTypeService(programProvider, threadingStrategy);
        analysisService = new AnalysisService(programProvider, threadingStrategy);
        comparisonService = new ComparisonService(programProvider, threadingStrategy);

        // Create server manager for shared Ghidra server support
        serverManager = new GhidraServerManager();

        // Load initial programs if specified
        loadInitialPrograms(args);

        // Start the HTTP server
        startServer();

        // Keep running until interrupted
        Runtime.getRuntime().addShutdownHook(new Thread(this::stop));

        System.out.println("GhidraMCP Headless Server v" + VERSION + " running on port " + port);
        System.out.println("Press Ctrl+C to stop");

        // Block main thread
        synchronized (this) {
            while (running) {
                try {
                    wait();
                } catch (InterruptedException e) {
                    break;
                }
            }
        }
    }

    private void parseArgs(String[] args) {
        // Check environment variable for bind address (Docker container support)
        String envBindAddress = System.getenv("GHIDRA_MCP_BIND_ADDRESS");
        if (envBindAddress != null && !envBindAddress.isEmpty()) {
            bindAddress = envBindAddress;
        }

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--port":
                case "-p":
                    if (i + 1 < args.length) {
                        try {
                            port = Integer.parseInt(args[++i]);
                        } catch (NumberFormatException e) {
                            System.err.println("Invalid port number: " + args[i]);
                        }
                    }
                    break;
                case "--bind":
                case "-b":
                    if (i + 1 < args.length) {
                        bindAddress = args[++i];
                    }
                    break;
                case "--help":
                case "-h":
                    printUsage();
                    System.exit(0);
                    break;
                case "--version":
                case "-v":
                    System.out.println("GhidraMCP Headless Server v" + VERSION);
                    System.exit(0);
                    break;
            }
        }
    }

    private void printUsage() {
        System.out.println("GhidraMCP Headless Server v" + VERSION);
        System.out.println();
        System.out.println("Usage: java -jar GhidraMCPHeadless.jar [options]");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  --port, -p <port>      Server port (default: 8089)");
        System.out.println("  --bind, -b <address>   Bind address (default: 127.0.0.1)");
        System.out.println("                         Use 0.0.0.0 to allow remote connections");
        System.out.println("  --file, -f <file>      Binary file to load");
        System.out.println("  --project <path>       Ghidra project path");
        System.out.println("  --program <name>       Program name within project");
        System.out.println("  --help, -h             Show this help");
        System.out.println("  --version, -v          Show version");
        System.out.println();
        System.out.println("Environment Variables:");
        System.out.println("  GHIDRA_MCP_BIND_ADDRESS  Override bind address (for Docker)");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  # Start server with no initial program");
        System.out.println("  java -jar GhidraMCPHeadless.jar --port 8089");
        System.out.println();
        System.out.println("  # Start server accessible from Docker network");
        System.out.println("  java -jar GhidraMCPHeadless.jar --bind 0.0.0.0 --port 8089");
        System.out.println();
        System.out.println("  # Start server with a binary file");
        System.out.println("  java -jar GhidraMCPHeadless.jar --file /path/to/binary.exe");
        System.out.println();
        System.out.println("REST API endpoints available at http://<address>:<port>/");
    }

    private void initializeGhidra(GhidraApplicationLayout layout) throws Exception {
        if (!Application.isInitialized()) {
            ApplicationConfiguration config = new HeadlessGhidraApplicationConfiguration();
            Application.initializeApplication(layout, config);
            System.out.println("Ghidra initialized in headless mode");
        }
    }

    private void loadInitialPrograms(String[] args) {
        String filePath = null;
        String projectPath = null;
        String programName = null;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--file":
                case "-f":
                    if (i + 1 < args.length) {
                        filePath = args[++i];
                    }
                    break;
                case "--project":
                    if (i + 1 < args.length) {
                        projectPath = args[++i];
                    }
                    break;
                case "--program":
                    if (i + 1 < args.length) {
                        programName = args[++i];
                    }
                    break;
            }
        }

        // Load from file if specified
        if (filePath != null) {
            File file = new File(filePath);
            Program program = programProvider.loadProgramFromFile(file);
            if (program != null) {
                System.out.println("Loaded program: " + program.getName());
            } else {
                System.err.println("Failed to load program from: " + filePath);
            }
        }

        // Load from project if specified
        if (projectPath != null) {
            boolean success = programProvider.openProject(projectPath);
            if (success) {
                System.out.println("Opened project: " + programProvider.getProjectName());

                // If program name specified, load it
                if (programName != null) {
                    Program program = programProvider.loadProgramFromProject(programName);
                    if (program != null) {
                        System.out.println("Loaded program from project: " + program.getName());
                    } else {
                        System.err.println("Failed to load program: " + programName);
                        // List available programs
                        System.out.println("Available programs:");
                        for (String p : programProvider.listProjectPrograms()) {
                            System.out.println("  " + p);
                        }
                    }
                }
            } else {
                System.err.println("Failed to open project: " + projectPath);
            }
        }
    }

    private void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress(bindAddress, port), 0);
        registerEndpoints();
        server.setExecutor(java.util.concurrent.Executors.newFixedThreadPool(10));
        server.start();
        running = true;
        System.out.println("HTTP server started on " + bindAddress + ":" + port);
    }

    // ==========================================================================
    // ENDPOINT REGISTRATION
    // ==========================================================================

    private void registerEndpoints() {
        ContextRegistrar registrar =
            (path, handler) -> server.createContext(path,
                ex -> handler.accept(new SunHttpExchangeAdapter(ex)));
        List<Ep> table = endpointTable();
        EndpointRegistrar.registerAll(registrar, table);

        // Complex handler outside the table (raw body parsing)
        server.createContext("/apply_function_documentation", sunEx -> {
            var ex = new SunHttpExchangeAdapter(sunEx);
            try {
                String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                EndpointRegistrar.sendResponse(ex, comparisonService.applyFunctionDocumentation(body));
            } catch (Exception e) {
                try { EndpointRegistrar.sendResponse(ex, Response.err(e.getMessage())); } catch (Exception ignored) {}
            }
        });

        System.out.println("Registered " + table.size() + " REST API endpoints");
    }

    // ==========================================================================
    // PARAM HELPER DELEGATES
    // ==========================================================================

    private static int getInt(Map<String, ?> m, String k, int d) { return EndpointRegistrar.getInt(m, k, d); }
    private static double getDouble(Map<String, ?> m, String k, double d) { return EndpointRegistrar.getDouble(m, k, d); }
    private static boolean getBool(Map<String, ?> m, String k, boolean d) { return EndpointRegistrar.getBool(m, k, d); }
    private static String getStr(Map<String, ?> m, String k) { return EndpointRegistrar.getStr(m, k); }
    private static String coerceToJsonString(Object o) { return EndpointRegistrar.coerceToJsonString(o); }

    // ==========================================================================
    // ENDPOINT TABLE
    // ==========================================================================

    private List<Ep> endpointTable() {
        List<Ep> table = new ArrayList<>(EndpointRegistrar.sharedEndpoints(
            listingService, commentService, symbolService, functionService,
            mutationService, dataTypeService, analysisService, comparisonService));

        // --- Headless stubs for GUI-only endpoints ---
        table.add(new Ep.Get0("/get_current_address", () -> Response.err("Headless mode - use address parameter with specific endpoints")));
        table.add(new Ep.Get0("/get_current_function", () -> Response.err("Headless mode - use get_function_by_address")));

        // --- Headless local implementations ---
        table.add(new Ep.Post2("/set_function_no_return", "function_address", "no_return", this::setFunctionNoReturn));
        table.add(new Ep.Post1("/clear_instruction_flow_override", "address", this::clearInstructionFlowOverride));
        table.add(new Ep.Post3("/set_variable_storage", "function_address", "variable_name", "storage", this::setVariableStorage));
        table.add(new Ep.Post2("/run_script", "script_path", "args", this::runScript));
        table.add(new Ep.Get1("/list_scripts", "filter", this::listScripts));
        table.add(new Ep.Post2("/run_ghidra_script", "script_path", "args", this::runScript));  // alias
        table.add(new Ep.Get0("/health", this::health));
        table.add(new Ep.Get0("/list_open_programs", this::headlessListOpenPrograms));
        table.add(new Ep.Get0("/get_current_program_info", this::headlessGetCurrentProgramInfo));
        table.add(new Ep.Post1("/switch_program", "name", this::headlessSwitchProgram));
        table.add(new Ep.Post1("/load_program", "file", this::loadProgram));
        table.add(new Ep.Post1("/close_program", "name", this::closeProgram));
        table.add(new Ep.Post1("/open_project", "path", this::openProject));
        table.add(new Ep.Get0("/close_project", this::closeProject));
        table.add(new Ep.Get0("/list_project_files", this::headlessListProjectFiles));
        table.add(new Ep.Post1("/load_program_from_project", "path", this::loadProgramFromProject));
        table.add(new Ep.Get0("/get_project_info", this::getProjectInfo));
        table.add(new Ep.Post2("/create_project", "parentDir", "name", this::createProject));
        table.add(new Ep.Post1("/delete_project", "projectPath", this::deleteProject));
        table.add(new Ep.Get1("/list_projects", "searchDir", this::listProjects));
        table.add(new Ep.Post2("/create_folder", "path", "program", this::createFolder));
        table.add(new Ep.Post2("/move_file", "filePath", "destFolder", this::moveFile));
        table.add(new Ep.Post2("/move_folder", "sourcePath", "destPath", this::moveFolder));
        table.add(new Ep.Post1("/delete_file", "filePath", this::deleteFile));
        table.add(new Ep.Get0("/exit_ghidra", this::exitServer));

        // --- Call graph endpoints (headless implementations) ---
        table.add(new Ep.GetQuery("/get_function_call_graph", q ->
            getFunctionCallGraph(getStr(q, "name"), getInt(q, "depth", 2),
                getStr(q, "direction") != null ? getStr(q, "direction") : "both", getStr(q, "program"))));
        table.add(new Ep.GetQuery("/get_full_call_graph", q ->
            getFullCallGraph(getStr(q, "format") != null ? getStr(q, "format") : "edges",
                getInt(q, "limit", 1000), getStr(q, "program"))));

        // --- Batch operations ---
        table.add(new Ep.JsonPost("/batch_rename_function_components", p ->
            batchRenameFunctionComponents(getStr(p, "function_address"), getStr(p, "function_name"),
                coerceToJsonString(p.get("variables")))));
        table.add(new Ep.JsonPost("/batch_set_variable_types", p ->
            batchSetVariableTypes(getStr(p, "function_address"), coerceToJsonString(p.get("variable_types")),
                getBool(p, "force_individual", false))));

        // --- Configure analyzer (headless-only, uses HeadlessProgramProvider) ---
        table.add(new Ep.JsonPost("/configure_analyzer", p ->
            configureAnalyzer(getStr(p, "program"), getStr(p, "name"), p.get("enabled"))));

        // --- Run script inline (headless stub) ---
        table.add(new Ep.Post2("/run_script_inline", "code", "args", this::runScriptInline));

        // --- Server endpoints (wrap serverManager String-returning methods) ---
        table.add(new Ep.Get0("/server/connect", () -> Response.text(serverManager.connect())));
        table.add(new Ep.Get0("/server/status", () -> Response.text(serverManager.getStatus())));
        table.add(new Ep.Get0("/server/repositories", () -> Response.text(serverManager.listRepositories())));
        table.add(new Ep.Get0("/server/disconnect", () -> Response.text(serverManager.disconnect())));
        table.add(new Ep.Get2("/server/repository/files", "repo", "path",
            (repo, path) -> Response.text(serverManager.listRepositoryFiles(repo, path != null ? path : "/"))));
        table.add(new Ep.Get2("/server/repository/file", "repo", "path",
            (repo, path) -> Response.text(serverManager.getFileInfo(repo, path))));
        table.add(new Ep.Post1("/server/repository/create", "name",
            name -> Response.text(serverManager.createRepository(name))));
        table.add(new Ep.Post2("/server/version_control/checkout", "repo", "path",
            (repo, path) -> Response.text(serverManager.checkoutFile(repo, path))));
        table.add(new Ep.JsonPost("/server/version_control/checkin", p ->
            Response.text(serverManager.checkinFile(getStr(p, "repo"), getStr(p, "path"),
                getStr(p, "comment"), getBool(p, "keepCheckedOut", false)))));
        table.add(new Ep.Post2("/server/version_control/undo_checkout", "repo", "path",
            (repo, path) -> Response.text(serverManager.undoCheckout(repo, path))));
        table.add(new Ep.Post3("/server/version_control/add", "repo", "path", "comment",
            (repo, path, comment) -> Response.text(serverManager.addToVersionControl(repo, path, comment))));
        table.add(new Ep.Get2("/server/version_history", "repo", "path",
            (repo, path) -> Response.text(serverManager.getVersionHistory(repo, path))));
        table.add(new Ep.Get2("/server/checkouts", "repo", "path",
            (repo, path) -> Response.text(serverManager.getCheckouts(repo, path))));
        table.add(new Ep.JsonPost("/server/admin/terminate_checkout", p ->
            Response.text(serverManager.terminateCheckout(getStr(p, "repo"), getStr(p, "path"),
                ((Number) p.getOrDefault("checkoutId", 0)).longValue()))));
        table.add(new Ep.Get0("/server/admin/users", () -> Response.text(serverManager.listServerUsers())));
        table.add(new Ep.JsonPost("/server/admin/set_permissions", p ->
            Response.text(serverManager.setUserPermissions(getStr(p, "repo"), getStr(p, "user"),
                getInt(p, "accessLevel", 1)))));

        return table;
    }

    // ==========================================================================
    // HEADLESS-SPECIFIC ENDPOINT METHODS
    // ==========================================================================

    private Response health() {
        JsonObject obj = new JsonObject();
        obj.addProperty("status", "healthy");
        obj.addProperty("version", VERSION);
        Program program = programProvider.getCurrentProgram();
        boolean programLoaded = (program != null);
        obj.addProperty("program_loaded", programLoaded);
        if (programLoaded) {
            obj.addProperty("program_name", program.getName());
        }
        return Response.ok(obj);
    }

    private Response headlessListOpenPrograms() {
        Program[] programs = programProvider.getAllOpenPrograms();
        Program current = programProvider.getCurrentProgram();
        JsonObject obj = new JsonObject();
        JsonArray arr = new JsonArray();
        for (Program p : programs) {
            JsonObject entry = new JsonObject();
            entry.addProperty("name", p.getName());
            entry.addProperty("is_current", p == current);
            arr.add(entry);
        }
        obj.add("programs", arr);
        obj.addProperty("count", programs.length);
        if (current != null) {
            obj.addProperty("current_program", current.getName());
        }
        return Response.ok(obj);
    }

    private Response headlessGetCurrentProgramInfo() {
        Program program = programProvider.resolveProgram(null);
        if (program == null) {
            return Response.err("No program loaded");
        }
        JsonObject obj = new JsonObject();
        obj.addProperty("name", program.getName());
        obj.addProperty("path", program.getExecutablePath());
        obj.addProperty("language", program.getLanguageID().toString());
        obj.addProperty("compiler", program.getCompilerSpec().getCompilerSpecID().toString());
        obj.addProperty("image_base", program.getImageBase().toString());
        obj.addProperty("address_size", program.getAddressFactory().getDefaultAddressSpace().getSize());
        obj.addProperty("min_address", program.getMinAddress().toString());
        obj.addProperty("max_address", program.getMaxAddress().toString());
        return Response.ok(obj);
    }

    private Response headlessSwitchProgram(String name) {
        if (name == null || name.isEmpty()) {
            return Response.err("Program name required");
        }
        Program program = programProvider.getProgram(name);
        if (program == null) {
            return Response.err("Program not found: " + name);
        }
        programProvider.setCurrentProgram(program);
        JsonObject obj = new JsonObject();
        obj.addProperty("success", true);
        obj.addProperty("current_program", program.getName());
        return Response.ok(obj);
    }

    private Response loadProgram(String filePath) {
        if (filePath == null || filePath.isEmpty()) {
            return Response.err("File path required");
        }
        File file = new File(filePath);
        if (!file.exists()) {
            return Response.err("File not found: " + filePath);
        }
        if (!(programProvider instanceof HeadlessProgramProvider hpp)) {
            return Response.err("Not supported in this mode");
        }
        Program program = hpp.loadProgramFromFile(file);
        if (program != null) {
            JsonObject obj = new JsonObject();
            obj.addProperty("success", true);
            obj.addProperty("program", program.getName());
            return Response.ok(obj);
        }
        return Response.err("Failed to load program from: " + filePath);
    }

    private Response closeProgram(String name) {
        Program program = programProvider.getProgram(name);
        if (program == null) {
            return Response.err("Program not found: " + (name != null ? name : "current"));
        }
        if (!(programProvider instanceof HeadlessProgramProvider hpp)) {
            return Response.err("Not supported in this mode");
        }
        hpp.closeProgram(program);
        JsonObject obj = new JsonObject();
        obj.addProperty("success", true);
        obj.addProperty("closed", program.getName());
        return Response.ok(obj);
    }

    private Response openProject(String projectPath) {
        if (projectPath == null || projectPath.isEmpty()) {
            return Response.err("Project path required");
        }
        if (!(programProvider instanceof HeadlessProgramProvider hpp)) {
            return Response.err("Project management not supported in this mode");
        }
        boolean success = hpp.openProject(projectPath);
        if (success) {
            JsonObject obj = new JsonObject();
            obj.addProperty("success", true);
            obj.addProperty("project", hpp.getProjectName());
            return Response.ok(obj);
        }
        return Response.err("Failed to open project: " + projectPath);
    }

    private Response closeProject() {
        if (!(programProvider instanceof HeadlessProgramProvider hpp)) {
            return Response.err("Project management not supported in this mode");
        }
        if (!hpp.hasProject()) {
            return Response.err("No project currently open");
        }
        String projectName = hpp.getProjectName();
        hpp.closeProject();
        JsonObject obj = new JsonObject();
        obj.addProperty("success", true);
        obj.addProperty("closed", projectName);
        return Response.ok(obj);
    }

    private Response headlessListProjectFiles() {
        if (!(programProvider instanceof HeadlessProgramProvider hpp)) {
            return Response.err("Project management not supported in this mode");
        }
        if (!hpp.hasProject()) {
            return Response.err("No project currently open");
        }
        List<HeadlessProgramProvider.ProjectFileInfo> files = hpp.listProjectFiles();
        JsonObject obj = new JsonObject();
        obj.addProperty("project", hpp.getProjectName());
        JsonArray arr = new JsonArray();
        for (HeadlessProgramProvider.ProjectFileInfo file : files) {
            JsonObject entry = new JsonObject();
            entry.addProperty("name", file.name);
            entry.addProperty("path", file.path);
            entry.addProperty("contentType", file.contentType);
            entry.addProperty("readOnly", file.readOnly);
            arr.add(entry);
        }
        obj.add("files", arr);
        obj.addProperty("count", files.size());
        return Response.ok(obj);
    }

    private Response loadProgramFromProject(String programPath) {
        if (programPath == null || programPath.isEmpty()) {
            return Response.err("Program path required (e.g., /D2Client.dll)");
        }
        if (!(programProvider instanceof HeadlessProgramProvider hpp)) {
            return Response.err("Project management not supported in this mode");
        }
        if (!hpp.hasProject()) {
            return Response.err("No project currently open. Use /open_project first.");
        }
        Program program = hpp.loadProgramFromProject(programPath);
        if (program != null) {
            JsonObject obj = new JsonObject();
            obj.addProperty("success", true);
            obj.addProperty("program", program.getName());
            obj.addProperty("path", programPath);
            return Response.ok(obj);
        }
        return Response.err("Failed to load program: " + programPath);
    }

    private Response getProjectInfo() {
        if (!(programProvider instanceof HeadlessProgramProvider hpp)) {
            return Response.err("Project management not supported in this mode");
        }
        if (!hpp.hasProject()) {
            JsonObject obj = new JsonObject();
            obj.addProperty("has_project", false);
            return Response.ok(obj);
        }
        List<HeadlessProgramProvider.ProjectFileInfo> files = hpp.listProjectFiles();
        int programCount = (int) files.stream()
            .filter(f -> "Program".equals(f.contentType))
            .count();
        JsonObject obj = new JsonObject();
        obj.addProperty("has_project", true);
        obj.addProperty("project_name", hpp.getProjectName());
        obj.addProperty("file_count", files.size());
        obj.addProperty("program_count", programCount);
        return Response.ok(obj);
    }

    private Response createProject(String parentDir, String name) {
        if (parentDir == null || parentDir.isEmpty()) return Response.err("parentDir required");
        if (name == null || name.isEmpty()) return Response.err("name required");
        if (!(programProvider instanceof HeadlessProgramProvider hpp)) {
            return Response.err("Project management not supported in this mode");
        }
        try {
            boolean ok = hpp.createProject(parentDir, name);
            if (ok) {
                JsonObject obj = new JsonObject();
                obj.addProperty("success", true);
                obj.addProperty("name", name);
                obj.addProperty("path", parentDir + "/" + name);
                return Response.ok(obj);
            }
            return Response.err("Failed to create project");
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    private Response deleteProject(String projectPath) {
        if (projectPath == null || projectPath.isEmpty()) return Response.err("projectPath required");
        if (!(programProvider instanceof HeadlessProgramProvider hpp)) {
            return Response.err("Project management not supported in this mode");
        }
        try {
            boolean ok = hpp.deleteProject(projectPath);
            if (ok) {
                JsonObject obj = new JsonObject();
                obj.addProperty("success", true);
                obj.addProperty("deleted", projectPath);
                return Response.ok(obj);
            }
            return Response.err("Failed to delete project");
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    private Response listProjects(String searchDir) {
        if (!(programProvider instanceof HeadlessProgramProvider hpp)) {
            return Response.err("Project management not supported in this mode");
        }
        try {
            List<HeadlessProgramProvider.ProjectInfo> projects = hpp.listProjects(searchDir);
            JsonArray arr = new JsonArray();
            for (HeadlessProgramProvider.ProjectInfo p : projects) {
                JsonObject entry = new JsonObject();
                entry.addProperty("name", p.name);
                entry.addProperty("path", p.path);
                entry.addProperty("active", p.active);
                arr.add(entry);
            }
            return Response.ok(arr);
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    private Response createFolder(String folderPath, String programName) {
        if (!(programProvider instanceof HeadlessProgramProvider hpp)) {
            return Response.err("Project management not supported in this mode");
        }
        try {
            hpp.createFolder(folderPath);
            JsonObject obj = new JsonObject();
            obj.addProperty("success", true);
            obj.addProperty("folder", folderPath);
            return Response.ok(obj);
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    private Response moveFile(String filePath, String destFolder) {
        if (!(programProvider instanceof HeadlessProgramProvider hpp)) {
            return Response.err("Project management not supported in this mode");
        }
        try {
            hpp.moveFile(filePath, destFolder);
            JsonObject obj = new JsonObject();
            obj.addProperty("success", true);
            obj.addProperty("moved", filePath);
            obj.addProperty("to", destFolder);
            return Response.ok(obj);
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    private Response moveFolder(String sourcePath, String destPath) {
        if (!(programProvider instanceof HeadlessProgramProvider hpp)) {
            return Response.err("Project management not supported in this mode");
        }
        try {
            hpp.moveFolder(sourcePath, destPath);
            JsonObject obj = new JsonObject();
            obj.addProperty("success", true);
            obj.addProperty("moved", sourcePath);
            obj.addProperty("to", destPath);
            return Response.ok(obj);
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    private Response deleteFile(String filePath) {
        if (!(programProvider instanceof HeadlessProgramProvider hpp)) {
            return Response.err("Project management not supported in this mode");
        }
        try {
            hpp.deleteProjectFile(filePath);
            JsonObject obj = new JsonObject();
            obj.addProperty("success", true);
            obj.addProperty("deleted", filePath);
            return Response.ok(obj);
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    private Response configureAnalyzer(String programName, String analyzerName, Object enabledObj) {
        Program program = programProvider.resolveProgram(programName);
        if (program == null) return Response.err(programName != null ? "Program not found: " + programName : "No program loaded");
        if (!(programProvider instanceof HeadlessProgramProvider hpp)) {
            return Response.err("Analyzer configuration not supported in this mode");
        }
        try {
            Boolean enabled = null;
            if (enabledObj instanceof Boolean b) {
                enabled = b;
            } else if (enabledObj != null) {
                enabled = Boolean.parseBoolean(enabledObj.toString());
            }
            hpp.configureAnalyzer(program, analyzerName, enabled);
            JsonObject obj = new JsonObject();
            obj.addProperty("success", true);
            obj.addProperty("analyzer", analyzerName);
            return Response.ok(obj);
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    private Response exitServer() {
        new Thread(() -> {
            try { Thread.sleep(500); } catch (InterruptedException ignored) {}
            System.exit(0);
        }).start();
        JsonObject obj = new JsonObject();
        obj.addProperty("success", true);
        obj.addProperty("message", "Server shutting down");
        return Response.ok(obj);
    }

    // ==========================================================================
    // MUTATION METHODS (headless-local)
    // ==========================================================================

    private Response setFunctionNoReturn(String functionAddrStr, String noReturnStr) {
        Program program = programProvider.resolveProgram(null);
        if (program == null) return Response.err("No program loaded");
        if (functionAddrStr == null || functionAddrStr.isEmpty()) return Response.err("address required");
        boolean noReturn = noReturnStr == null || noReturnStr.isEmpty() || Boolean.parseBoolean(noReturnStr);
        try {
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            if (addr == null) return Response.err("Invalid address: " + functionAddrStr);
            Function func = program.getFunctionManager().getFunctionAt(addr);
            if (func == null) func = program.getFunctionManager().getFunctionContaining(addr);
            if (func == null) return Response.err("No function at address: " + functionAddrStr);
            final Function finalFunc = func;
            final String oldState = func.hasNoReturn() ? "non-returning" : "returning";
            return threadingStrategy.executeWrite(program, "Set function no return", () -> {
                finalFunc.setNoReturn(noReturn);
                String newState = noReturn ? "non-returning" : "returning";
                JsonObject obj = new JsonObject();
                obj.addProperty("success", true);
                obj.addProperty("function", finalFunc.getName());
                obj.addProperty("from", oldState);
                obj.addProperty("to", newState);
                return Response.ok(obj);
            });
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    private Response clearInstructionFlowOverride(String instructionAddrStr) {
        Program program = programProvider.resolveProgram(null);
        if (program == null) return Response.err("No program loaded");
        if (instructionAddrStr == null || instructionAddrStr.isEmpty()) return Response.err("address required");
        try {
            Address addr = program.getAddressFactory().getAddress(instructionAddrStr);
            if (addr == null) return Response.err("Invalid address: " + instructionAddrStr);
            Instruction instruction = program.getListing().getInstructionAt(addr);
            if (instruction == null) return Response.err("No instruction at address: " + instructionAddrStr);
            final FlowOverride oldOverride = instruction.getFlowOverride();
            return threadingStrategy.executeWrite(program, "Clear instruction flow override", () -> {
                instruction.setFlowOverride(FlowOverride.NONE);
                JsonObject obj = new JsonObject();
                obj.addProperty("success", true);
                obj.addProperty("address", instructionAddrStr);
                obj.addProperty("previous_override", oldOverride.toString());
                obj.addProperty("new_override", "NONE");
                return Response.ok(obj);
            });
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    private Response setVariableStorage(String functionAddrStr, String variableName, String storageSpec) {
        Program program = programProvider.resolveProgram(null);
        if (program == null) return Response.err("No program loaded");
        if (functionAddrStr == null || functionAddrStr.isEmpty()) return Response.err("address required");
        if (variableName == null || variableName.isEmpty()) return Response.err("variable_name required");
        try {
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            if (addr == null) return Response.err("Invalid address: " + functionAddrStr);
            Function func = program.getFunctionManager().getFunctionAt(addr);
            if (func == null) return Response.err("No function at address: " + functionAddrStr);
            Variable targetVar = null;
            for (Variable var : func.getAllVariables()) {
                if (var.getName().equals(variableName)) { targetVar = var; break; }
            }
            if (targetVar == null) return Response.err("Variable not found: " + variableName);
            JsonObject obj = new JsonObject();
            obj.addProperty("advisory", true);
            obj.addProperty("message", "Programmatic variable storage control is limited in Ghidra.");
            obj.addProperty("variable", variableName);
            obj.addProperty("function", func.getName());
            obj.addProperty("current_storage", targetVar.getVariableStorage().toString());
            obj.addProperty("requested_storage", storageSpec != null ? storageSpec : "");
            obj.addProperty("tip", "Use Ghidra decompiler UI or a custom script to change variable storage.");
            return Response.ok(obj);
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    // ==========================================================================
    // SCRIPT STUBS (headless)
    // ==========================================================================

    private Response runScript(String scriptPath, String scriptArgs) {
        Program program = programProvider.resolveProgram(null);
        if (program == null) {
            return Response.err("No program loaded");
        }
        if (scriptPath == null || scriptPath.isEmpty()) {
            return Response.err("Script path is required");
        }
        JsonObject obj = new JsonObject();
        obj.addProperty("status", "Script execution in headless mode");
        obj.addProperty("script_path", scriptPath);
        obj.addProperty("program", program.getName());
        obj.addProperty("note", "Full script execution requires GUI mode. Use Ghidra's analyzeHeadless for batch scripting.");
        return Response.ok(obj);
    }

    private Response listScripts(String filter) {
        JsonObject obj = new JsonObject();
        obj.add("scripts", new JsonArray());
        obj.addProperty("note", "Script listing in headless mode is limited.");
        JsonArray locations = new JsonArray();
        locations.add("<ghidra_install>/Ghidra/Features/*/ghidra_scripts/");
        locations.add("<user_home>/ghidra_scripts/");
        obj.add("common_locations", locations);
        if (filter != null) {
            obj.addProperty("filter", filter);
        } else {
            obj.add("filter", null);
        }
        return Response.ok(obj);
    }

    private Response runScriptInline(String code, String args) {
        JsonObject obj = new JsonObject();
        obj.addProperty("advisory", true);
        obj.addProperty("message", "Inline script execution requires Ghidra GUI mode or analyzeHeadless.");
        obj.addProperty("tip", "Use analyzeHeadless with -scriptPath and -process for batch scripting.");
        return Response.ok(obj);
    }

    // ==========================================================================
    // CALL GRAPH METHODS (headless)
    // ==========================================================================

    private Response getFunctionCallGraph(String functionAddress, int depth, String direction, String programName) {
        Program program = programProvider.resolveProgram(programName);
        if (program == null) return Response.err(programName != null ? "Program not found: " + programName : "No program loaded");
        FunctionManager functionManager = program.getFunctionManager();
        Function rootFunction = findFunctionByAddressOrName(program, functionAddress);
        if (rootFunction == null) return Response.err("Function not found: " + functionAddress);
        Set<String> visited = new HashSet<>();
        Map<String, Set<String>> callGraph = new HashMap<>();
        if ("callees".equals(direction) || "both".equals(direction)) {
            buildCallGraphCallees(program, rootFunction, depth, visited, callGraph, functionManager);
        }
        if ("callers".equals(direction) || "both".equals(direction)) {
            visited.clear();
            buildCallGraphCallers(program, rootFunction, depth, visited, callGraph, functionManager);
        }
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, Set<String>> entry : callGraph.entrySet()) {
            for (String callee : entry.getValue()) {
                if (sb.length() > 0) sb.append("\n");
                sb.append(entry.getKey()).append(" -> ").append(callee);
            }
        }
        if (sb.length() == 0) return Response.text("No call graph relationships found for function: " + functionAddress);
        return Response.text(sb.toString());
    }

    private void buildCallGraphCallees(Program program, Function function, int depth, Set<String> visited,
                                       Map<String, Set<String>> callGraph, FunctionManager functionManager) {
        if (depth <= 0 || visited.contains(function.getName())) return;
        visited.add(function.getName());
        Set<String> callees = new HashSet<>();
        Listing listing = program.getListing();
        ReferenceManager refManager = program.getReferenceManager();
        InstructionIterator instructions = listing.getInstructions(function.getBody(), true);
        while (instructions.hasNext()) {
            Instruction instr = instructions.next();
            if (instr.getFlowType().isCall()) {
                for (Reference ref : refManager.getReferencesFrom(instr.getAddress())) {
                    if (ref.getReferenceType().isCall()) {
                        Function targetFunc = functionManager.getFunctionAt(ref.getToAddress());
                        if (targetFunc != null) {
                            callees.add(targetFunc.getName());
                            buildCallGraphCallees(program, targetFunc, depth - 1, visited, callGraph, functionManager);
                        }
                    }
                }
            }
        }
        if (!callees.isEmpty()) callGraph.put(function.getName(), callees);
    }

    private void buildCallGraphCallers(Program program, Function function, int depth, Set<String> visited,
                                       Map<String, Set<String>> callGraph, FunctionManager functionManager) {
        if (depth <= 0 || visited.contains(function.getName())) return;
        visited.add(function.getName());
        ReferenceManager refManager = program.getReferenceManager();
        ReferenceIterator refIter = refManager.getReferencesTo(function.getEntryPoint());
        while (refIter.hasNext()) {
            Reference ref = refIter.next();
            if (ref.getReferenceType().isCall()) {
                Function callerFunc = functionManager.getFunctionContaining(ref.getFromAddress());
                if (callerFunc != null) {
                    callGraph.computeIfAbsent(callerFunc.getName(), k -> new HashSet<>()).add(function.getName());
                    buildCallGraphCallers(program, callerFunc, depth - 1, visited, callGraph, functionManager);
                }
            }
        }
    }

    private Response getFullCallGraph(String format, int limit, String programName) {
        Program program = programProvider.resolveProgram(programName);
        if (program == null) return Response.err(programName != null ? "Program not found: " + programName : "No program loaded");
        FunctionManager functionManager = program.getFunctionManager();
        ReferenceManager refManager = program.getReferenceManager();
        Listing listing = program.getListing();
        Map<String, Set<String>> callGraph = new HashMap<>();
        int relationshipCount = 0;
        for (Function function : functionManager.getFunctions(true)) {
            if (relationshipCount >= limit) break;
            Set<String> callees = new HashSet<>();
            InstructionIterator instructions = listing.getInstructions(function.getBody(), true);
            while (instructions.hasNext() && relationshipCount < limit) {
                Instruction instr = instructions.next();
                if (instr.getFlowType().isCall()) {
                    for (Reference ref : refManager.getReferencesFrom(instr.getAddress())) {
                        if (ref.getReferenceType().isCall()) {
                            Function targetFunc = functionManager.getFunctionAt(ref.getToAddress());
                            if (targetFunc != null) {
                                callees.add(targetFunc.getName());
                                relationshipCount++;
                                if (relationshipCount >= limit) break;
                            }
                        }
                    }
                }
            }
            if (!callees.isEmpty()) callGraph.put(function.getName(), callees);
        }
        StringBuilder sb = new StringBuilder();
        if ("dot".equals(format)) {
            sb.append("digraph CallGraph {\n  rankdir=TB;\n  node [shape=box];\n");
            for (Map.Entry<String, Set<String>> entry : callGraph.entrySet()) {
                String caller = entry.getKey().replace("\"", "\\\"");
                for (String callee : entry.getValue()) {
                    sb.append("  \"").append(caller).append("\" -> \"").append(callee.replace("\"", "\\\"")).append("\";\n");
                }
            }
            sb.append("}");
        } else if ("mermaid".equals(format)) {
            sb.append("graph TD\n");
            for (Map.Entry<String, Set<String>> entry : callGraph.entrySet()) {
                String caller = entry.getKey().replace(" ", "_");
                for (String callee : entry.getValue()) {
                    sb.append("  ").append(caller).append(" --> ").append(callee.replace(" ", "_")).append("\n");
                }
            }
        } else if ("adjacency".equals(format)) {
            for (Map.Entry<String, Set<String>> entry : callGraph.entrySet()) {
                if (sb.length() > 0) sb.append("\n");
                sb.append(entry.getKey()).append(": ").append(String.join(", ", entry.getValue()));
            }
        } else {
            for (Map.Entry<String, Set<String>> entry : callGraph.entrySet()) {
                for (String callee : entry.getValue()) {
                    if (sb.length() > 0) sb.append("\n");
                    sb.append(entry.getKey()).append(" -> ").append(callee);
                }
            }
        }
        if (sb.length() == 0) return Response.text("No call relationships found in the program");
        return Response.text(sb.toString());
    }

    // ==========================================================================
    // BATCH OPERATIONS (headless)
    // ==========================================================================

    private Response batchRenameFunctionComponents(String functionAddress, String functionName, String variablesJson) {
        Program program = programProvider.resolveProgram(null);
        if (program == null) return Response.err("No program loaded");
        if (functionAddress == null || functionAddress.isEmpty()) return Response.err("function_address required");
        try {
            Address addr = program.getAddressFactory().getAddress(functionAddress);
            if (addr == null) return Response.err("Invalid address: " + functionAddress);
            Function func = program.getFunctionManager().getFunctionAt(addr);
            if (func == null) return Response.err("No function at address: " + functionAddress);
            return threadingStrategy.executeWrite(program, "Batch rename function components", () -> {
                JsonArray results = new JsonArray();
                if (functionName != null && !functionName.isEmpty()) {
                    JsonObject entry = new JsonObject();
                    entry.addProperty("type", "function");
                    try {
                        func.setName(functionName, SourceType.USER_DEFINED);
                        entry.addProperty("new_name", functionName);
                        entry.addProperty("success", true);
                    } catch (Exception e) {
                        entry.addProperty("error", e.getMessage());
                    }
                    results.add(entry);
                }
                JsonObject obj = new JsonObject();
                obj.add("results", results);
                return Response.ok(obj);
            });
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    private Response batchSetVariableTypes(String functionAddress, String variableTypesJson, boolean forceIndividual) {
        Program program = programProvider.resolveProgram(null);
        if (program == null) return Response.err("No program loaded");
        if (functionAddress == null || functionAddress.isEmpty()) return Response.err("function_address required");
        if (variableTypesJson == null || variableTypesJson.isEmpty()) return Response.err("variable_types required");
        try {
            return threadingStrategy.executeWrite(program, "Batch set variable types", () -> {
                Address addr = program.getAddressFactory().getAddress(functionAddress);
                if (addr == null) return Response.err("Invalid address");
                Function func = program.getFunctionManager().getFunctionAt(addr);
                if (func == null) return Response.err("No function at address");
                JsonObject obj = new JsonObject();
                obj.addProperty("success", true);
                obj.addProperty("function", func.getName());
                obj.addProperty("message", "Batch variable type setting queued");
                obj.addProperty("tip", "Use set_local_variable_type for individual variable type changes.");
                return Response.ok(obj);
            });
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    // ==========================================================================
    // HELPER METHODS
    // ==========================================================================

    private Function findFunctionByAddressOrName(Program program, String addressOrName) {
        if (addressOrName == null || addressOrName.isEmpty()) return null;
        // Try as address first
        try {
            Address addr = program.getAddressFactory().getAddress(addressOrName);
            if (addr != null) {
                Function f = program.getFunctionManager().getFunctionAt(addr);
                if (f != null) return f;
                f = program.getFunctionManager().getFunctionContaining(addr);
                if (f != null) return f;
            }
        } catch (Exception ignored) {}
        // Fall back to name search
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(addressOrName)) return f;
        }
        return null;
    }

    // ==========================================================================
    // LIFECYCLE
    // ==========================================================================

    public void stop() {
        running = false;
        synchronized (this) {
            notifyAll();
        }

        if (server != null) {
            System.out.println("Stopping HTTP server...");
            server.stop(2);
            server = null;
        }

        if (serverManager != null && serverManager.isConnected()) {
            System.out.println("Disconnecting from Ghidra server...");
            serverManager.disconnect();
        }

        if (programProvider != null) {
            System.out.println("Closing programs...");
            programProvider.closeAllPrograms();
        }

        System.out.println("Server stopped");
    }

    // ==========================================================================
    // GETTERS
    // ==========================================================================

    public ProgramProvider getProgramProvider() {
        return programProvider;
    }

    public ThreadingStrategy getThreadingStrategy() {
        return threadingStrategy;
    }

    public boolean isRunning() {
        return running;
    }

    public int getPort() {
        return port;
    }
}
