package com.xebyte.core;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.io.IOException;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Static singleton that owns the UDS HTTP server, service instances, and
 * tool registry. Shared across all CodeBrowser windows in one JVM.
 */
public class ServerManager {

    private static ServerManager instance;

    public static synchronized ServerManager getInstance() {
        if (instance == null) instance = new ServerManager();
        return instance;
    }

    private final Map<String, PluginTool> tools = new ConcurrentHashMap<>();
    private final AtomicReference<String> activeToolId = new AtomicReference<>();
    /** Request threads for GUI transports; see {@link McpHttpServer.Config#workers()}. */
    public static final int GUI_WORKERS = 3;

    private MultiToolProgramProvider programProvider;
    private McpHttpServer server;
    // Bound TCP port for the legacy HTTP transport when the plugin picked
    // a port-range fallback (issue #175). -1 means "TCP not running or
    // port unknown". Surfaced via /mcp/instance_info so the bridge can
    // connect to the actual bound port without hard-coding 8089.
    private volatile int boundTcpPort = -1;

    public void setBoundTcpPort(int port) {
        this.boundTcpPort = port;
    }

    public int getBoundTcpPort() {
        return boundTcpPort;
    }

    private ServerManager() {}

    public synchronized void registerTool(PluginTool tool,
            java.util.function.Consumer<McpHttpServer> guiEndpoints) throws IOException {
        String toolId = String.valueOf(System.identityHashCode(tool));
        tools.put(toolId, tool);
        activeToolId.compareAndSet(null, toolId);
        Msg.info(this, "Registered tool " + toolId + " (total: " + tools.size() + ")");


        if (server == null) {
            programProvider = new MultiToolProgramProvider(tools, activeToolId);
            com.xebyte.core.ThreadingStrategy ts = new com.xebyte.core.SwingThreadingStrategy();

            ListingService listingService = new ListingService(programProvider);
            CommentService commentService = new CommentService(programProvider, ts);
            SymbolLabelService symbolLabelService = new SymbolLabelService(programProvider, ts);
            FunctionService functionService = new FunctionService(programProvider, ts);
            XrefCallGraphService xrefCallGraphService = new XrefCallGraphService(programProvider, ts);
            DataTypeService dataTypeService = new DataTypeService(programProvider, ts);
            DocumentationHashService documentationHashService = new DocumentationHashService(programProvider, ts, new BinaryComparisonService());
            documentationHashService.setFunctionService(functionService);
            AnalysisService analysisService = new AnalysisService(programProvider, ts, functionService);
            MalwareSecurityService malwareSecurityService = new MalwareSecurityService(programProvider, ts);
            ProgramScriptService programScriptService = new ProgramScriptService(programProvider, ts);
            FunctionBundleService functionBundleService = new FunctionBundleService(programProvider, ts, functionService);
            TypeReferenceService typeReferenceService = new TypeReferenceService(programProvider);
            ChangeTokenService changeTokenService = new ChangeTokenService(programProvider);
            PartitionService partitionService = new PartitionService(programProvider);
            CheckoutService checkoutService = new CheckoutService(programProvider);
            // These three existed only on GhidraMCPPlugin's own legacy server, which
            // nothing starts by default — so P-code emulation, the debugger and the
            // modal-prompt policy were unreachable over UDS *and* over the TCP port
            // this manager binds, i.e. on both transports the bridge uses. Measured:
            // 21 of the 67 catalog endpoints missing from a live GUI instance.
            // DebuggerService needs a PluginTool for TraceRmi; the tool that first
            // registered is the same one the plugin would have handed it.
            EmulationService emulationService = new EmulationService(programProvider, ts);
            DebuggerService debuggerService = new DebuggerService(programProvider, ts, tool);
            PromptPolicyService promptPolicyService = new PromptPolicyService();

            AnnotationScanner scanner = new AnnotationScanner(programProvider, ts,
                listingService, functionService, commentService, symbolLabelService,
                xrefCallGraphService, dataTypeService, analysisService,
                documentationHashService, malwareSecurityService, programScriptService,
                functionBundleService, typeReferenceService, changeTokenService, partitionService,
                checkoutService, emulationService, debuggerService, promptPolicyService);

            startServer(scanner, guiEndpoints);
        }
    }

    public synchronized void deregisterTool(PluginTool tool) {
        String toolId = String.valueOf(System.identityHashCode(tool));
        tools.remove(toolId);
        if (toolId.equals(activeToolId.get())) {
            var iter = tools.keySet().iterator();
            activeToolId.set(iter.hasNext() ? iter.next() : null);
        }
        Msg.info(this, "Deregistered tool " + toolId + " (remaining: " + tools.size() + ")");

        if (tools.isEmpty()) {
            stopServer();
            instance = null;
        }
    }

    public PluginTool getActiveTool() {
        return programProvider != null ? programProvider.getActiveTool() : null;
    }

    public MultiToolProgramProvider getProgramProvider() { return programProvider; }

    public boolean isRunning() { return server != null; }

    /** Stop the UDS server without deregistering tools. Use for manual stop/restart. */
    public synchronized void stopUdsServer() {
        stopServer();
    }

    public Path getSocketPath() {
        return server != null ? server.socketPath() : null;
    }

    private void startServer(AnnotationScanner scanner,
            java.util.function.Consumer<McpHttpServer> guiEndpoints) throws IOException {
        server = new McpHttpServer(this::buildInstanceInfo);
        server.endpoints(scanner);
        // Advertise the plugin's hand-coded routes too -- a route missing from the
        // schema is a route the bridge's dynamic discovery never offers. Only when a
        // registrar was supplied, so the schema never promises a path we don't serve.
        if (guiEndpoints != null) {
            ManualToolDescriptors.addAll(scanner, ManualToolDescriptors.SHARED_ROUTES);
            guiEndpoints.accept(server);
        }
        server.start(new McpHttpServer.Config(true, false, null, 0, 0, GUI_WORKERS));
    }

    public Map<String, Object> buildInstanceInfo() {
        PluginTool activeTool = getActiveTool();
        ghidra.framework.model.Project proj = activeTool != null ? activeTool.getProject() : null;

        var openNames = new java.util.HashSet<String>();
        if (proj != null) {
            try {
                ghidra.framework.model.ToolManager tm = proj.getToolManager();
                if (tm != null) {
                    for (PluginTool runningTool : tm.getRunningTools()) {
                        ghidra.app.services.ProgramManager pm = runningTool.getService(ghidra.app.services.ProgramManager.class);
                        if (pm != null) {
                            for (Program p : pm.getAllOpenPrograms()) {
                                openNames.add(p.getName());
                            }
                        }
                    }
                }
            } catch (Exception e) {
                Msg.warn(this, "Failed to query running tools: " + e.getMessage());
            }
        }
        Map<String, Object> info = instanceInfo(proj, openNames);
        // The TCP listener is the plugin's own McpHttpServer, not this one.
        info.put("tcp_port", boundTcpPort);
        info.put("tools", tools.size());
        return info;
    }

    /**
     * The project half of the /mcp/instance_info payload the bridge's discovery
     * reads, shared by the GUI plugin and the headless server.
     */
    public static Map<String, Object> instanceInfo(ghidra.framework.model.Project proj,
            java.util.Set<String> openNames) {
        var programs = new java.util.ArrayList<Map<String, Object>>();
        if (proj != null) {
            collectPrograms(proj.getProjectData().getRootFolder(), openNames, programs);
        }
        var info = new LinkedHashMap<String, Object>();
        info.put("pid", ProcessHandle.current().pid());
        info.put("project", proj != null ? proj.getName() : "unknown");
        info.put("project_path", proj != null ? proj.getProjectLocator().toString() : "");
        info.put("programs", programs);
        return info;
    }

    private void stopServer() {
        if (server != null) {
            server.stop();
            server = null;
        }
    }

    private static void collectPrograms(ghidra.framework.model.DomainFolder folder,
            java.util.Set<String> openNames, java.util.List<Map<String, Object>> out) {
        for (ghidra.framework.model.DomainFile df : folder.getFiles()) {
            var entry = new LinkedHashMap<String, Object>();
            entry.put("name", df.getName());
            entry.put("path", df.getPathname());
            entry.put("open", openNames.contains(df.getName()));
            out.add(entry);
        }
        for (ghidra.framework.model.DomainFolder sub : folder.getFolders()) {
            collectPrograms(sub, openNames, out);
        }
    }
}
