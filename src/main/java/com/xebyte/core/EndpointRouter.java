package com.xebyte.core;

import com.google.gson.JsonObject;
import com.xebyte.VersionInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ProgramManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import com.xebyte.core.services.CommentService;
import com.xebyte.core.services.FunctionService;
import com.xebyte.core.services.ListingService;
import com.xebyte.core.services.AnalysisService;
import com.xebyte.core.services.ComparisonService;
import com.xebyte.core.services.DataTypeService;
import com.xebyte.core.services.MutationService;
import com.xebyte.core.services.SymbolService;
import com.sun.net.httpserver.Headers;
import javax.swing.SwingUtilities;
import java.io.*;
import java.lang.reflect.InvocationTargetException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;
import java.util.function.Supplier;

/**
 * Owns all HTTP endpoint registrations and handler methods.
 * Created by ServerManager; has no lifecycle logic of its own.
 */
public class EndpointRouter {

    private final MultiToolProgramProvider programProvider;
    private final Supplier<PluginTool> activeToolSupplier;
    private final ListingService listingService;
    private final CommentService commentService;
    private final SymbolService symbolService;
    private final FunctionService functionService;
    private final MutationService mutationService;
    private final DataTypeService dataTypeService;
    private final AnalysisService analysisService;
    private final ComparisonService comparisonService;

    private static final int MAX_STRUCT_FIELDS = 256;
    private static final int DECOMPILE_TIMEOUT_SECONDS = 60;  // Increased from 30s to 60s for large functions
    private static final int MAX_FIELD_OFFSET = 65536;

    public EndpointRouter(
            MultiToolProgramProvider programProvider,
            Supplier<PluginTool> activeToolSupplier,
            ListingService listingService,
            CommentService commentService,
            SymbolService symbolService,
            FunctionService functionService,
            MutationService mutationService,
            DataTypeService dataTypeService,
            AnalysisService analysisService,
            ComparisonService comparisonService) {
        this.programProvider = programProvider;
        this.activeToolSupplier = activeToolSupplier;
        this.listingService = listingService;
        this.commentService = commentService;
        this.symbolService = symbolService;
        this.functionService = functionService;
        this.mutationService = mutationService;
        this.dataTypeService = dataTypeService;
        this.analysisService = analysisService;
        this.comparisonService = comparisonService;
    }

    private PluginTool getActiveTool() {
        return activeToolSupplier.get();
    }

    public Program getCurrentProgram() {
        return programProvider.getCurrentProgram();
    }

    public Program getProgram(String programName) {
        return programProvider.getProgram(programName);
    }

    // Import static helpers from EndpointRegistrar for use in endpointTable lambdas
    private static int getInt(Map<String, ?> m, String k, int d) { return EndpointRegistrar.getInt(m, k, d); }
    private static double getDouble(Map<String, ?> m, String k, double d) { return EndpointRegistrar.getDouble(m, k, d); }
    private static boolean getBool(Map<String, ?> m, String k, boolean d) { return EndpointRegistrar.getBool(m, k, d); }
    private static String getStr(Map<String, ?> m, String k) { return EndpointRegistrar.getStr(m, k); }
    private static String coerceToJsonString(Object o) { return EndpointRegistrar.coerceToJsonString(o); }

    public void registerAll(UdsHttpServer server) {
        EndpointRegistrar.ContextRegistrar registrar =
            (path, handler) -> server.createContext(path, handler::accept);
        EndpointRegistrar.registerAll(registrar, endpointTable());

        // Complex handlers that don't fit any Ep pattern
        server.createContext("/run_script_inline", safeHandler(exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String code = (String) params.get("code");
            String scriptArgs = (String) params.get("args");

            if (code == null || code.isEmpty()) {
                sendResponse(exchange, errorJson("code parameter is required"));
                return;
            }

            // Generate a unique class name per invocation to avoid OSGi class cache collisions
            String uid = Long.toHexString(System.nanoTime());
            String userClass = null;
            java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("public\\s+class\\s+(\\w+)").matcher(code);
            if (m.find()) {
                userClass = m.group(1);
            }
            String className = "Mcp_" + uid;
            String rewrittenCode = userClass != null
                ? code.replace("class " + userClass, "class " + className)
                : "import ghidra.app.script.GhidraScript;\npublic class " + className
                  + " extends GhidraScript {\n  public void run() throws Exception {\n"
                  + code + "\n  }\n}\n";

            File scriptDir = new File(System.getProperty("user.home"), "ghidra_scripts");
            scriptDir.mkdirs();
            File tempScript = new File(scriptDir, className + ".java");
            try {
                java.nio.file.Files.writeString(tempScript.toPath(), rewrittenCode);
                sendResponse(exchange, runGhidraScript(tempScript.getAbsolutePath(), scriptArgs));
            } finally {
                if (!tempScript.delete()) tempScript.deleteOnExit();
                File classFile = new File(scriptDir, className + ".class");
                if (classFile.exists() && !classFile.delete()) classFile.deleteOnExit();
            }
        }));

        server.createContext("/analyze_function_completeness", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String functionAddress = qparams.get("function_address");

            Program program = getCurrentProgram();
            if (program != null && functionAddress != null && !functionAddress.isEmpty()) {
                try {
                    Address addr = program.getAddressFactory().getAddress(functionAddress);
                    if (addr != null) {
                        Function func = program.getFunctionManager().getFunctionAt(addr);
                        if (func != null) {
                            DecompInterface tempDecomp = new DecompInterface();
                            tempDecomp.openProgram(program);
                            tempDecomp.flushCache();
                            tempDecomp.decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS, new ConsoleTaskMonitor());
                            tempDecomp.dispose();
                            Msg.info(this, "Refreshed decompiler cache before completeness analysis for " + func.getName());
                        }
                    }
                } catch (Exception e) {
                    Msg.warn(this, "Failed to refresh cache before completeness analysis: " + e.getMessage());
                }
            }
            sendResponse(exchange, analysisService.analyzeFunctionCompleteness(functionAddress));
        }));

        server.createContext("/exit_ghidra", safeHandler(exchange -> {
            saveCurrentProgram();
            sendResponse(exchange, Response.ok(Map.of("success", true, "message", "Saving and exiting Ghidra")));
            new Thread(() -> {
                try { Thread.sleep(500); } catch (InterruptedException ignored) {}
                SwingUtilities.invokeLater(() -> {
                    PluginTool t = getActiveTool();
                    if (t != null) t.close();
                });
            }).start();
        }));

        server.createContext("/apply_function_documentation", safeHandler(checked(exchange -> {
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            sendResponse(exchange, comparisonService.applyFunctionDocumentation(body));
        })));
    }

    private List<Ep> endpointTable() {
        List<Ep> table = new ArrayList<>(EndpointRegistrar.sharedEndpoints(
            listingService, commentService, symbolService, functionService,
            mutationService, dataTypeService, analysisService, comparisonService));

        // GUI-specific endpoints (need PluginTool, CodeViewerService, SwingUtilities)
        table.add(new Ep.Get0("/get_current_address", this::getCurrentAddress));
        table.add(new Ep.Get0("/get_current_function", this::getCurrentFunction));
        table.add(new Ep.Post2("/set_function_no_return", "function_address", "no_return", this::setFunctionNoReturn));
        table.add(new Ep.Post1("/clear_instruction_flow_override", "address", this::clearInstructionFlowOverride));
        table.add(new Ep.Post3("/set_variable_storage", "function_address", "variable_name", "storage", this::setVariableStorage));
        table.add(new Ep.Post2("/run_script", "script_path", "args", this::runGhidraScript));
        table.add(new Ep.Get1("/list_scripts", "filter", this::listGhidraScripts));
        table.add(new Ep.Get0("/list_open_programs", this::listOpenPrograms));
        table.add(new Ep.Get0("/get_current_program_info", this::getCurrentProgramInfo));
        table.add(new Ep.Get1("/switch_program", "name", this::switchProgram));
        table.add(new Ep.Get1("/list_project_files", "folder", this::listProjectFiles));
        table.add(new Ep.Get1("/open_program", "path", this::openProgramFromProject));

        // Call graph (local implementations using Swing thread)
        table.add(new Ep.GetQuery("/get_function_call_graph", q ->
            getFunctionCallGraph(getStr(q, "name"), getInt(q, "depth", 2),
                getStr(q, "direction") != null ? getStr(q, "direction") : "both", getStr(q, "program"))));
        table.add(new Ep.GetQuery("/get_full_call_graph", q ->
            getFullCallGraph(getStr(q, "format") != null ? getStr(q, "format") : "edges",
                getInt(q, "limit", 1000), getStr(q, "program"))));
        table.add(new Ep.GetQuery("/analyze_call_graph", q ->
            analyzeCallGraph(getStr(q, "start_function"), getStr(q, "end_function"),
                getStr(q, "analysis_type") != null ? getStr(q, "analysis_type") : "summary", getStr(q, "program"))));

        // Batch operations (local implementations)
        table.add(new Ep.JsonPost("/batch_rename_function_components", p -> {
            @SuppressWarnings("unchecked")
            Map<String, String> paramRenames = (Map<String, String>) p.get("parameter_renames");
            @SuppressWarnings("unchecked")
            Map<String, String> localRenames = (Map<String, String>) p.get("local_renames");
            return batchRenameFunctionComponents(getStr(p, "function_address"), getStr(p, "function_name"),
                paramRenames, localRenames, getStr(p, "return_type"));
        }));
        table.add(new Ep.JsonPost("/batch_set_variable_types", p -> {
            @SuppressWarnings("unchecked")
            Map<String, String> variableTypes = p.get("variable_types") instanceof Map
                ? (Map<String, String>) p.get("variable_types") : new HashMap<>();
            return batchSetVariableTypesOptimized(getStr(p, "function_address"), variableTypes);
        }));

        // Script execution (GUI-specific)
        table.add(new Ep.JsonPost("/run_ghidra_script", p ->
            runGhidraScriptWithCapture(getStr(p, "script_name"), getStr(p, "args"),
                getInt(p, "timeout_seconds", 300), getBool(p, "capture_output", true))));

        return table;
    }


    /**
     * Get current address selected in Ghidra GUI
     */
    private Response getCurrentAddress() {
        CodeViewerService service = getActiveTool().getService(CodeViewerService.class);
        if (service == null) return errorJson("Code viewer service not available");

        ProgramLocation location = service.getCurrentLocation();
        if (location == null) return errorJson("No current location");
        JsonObject _jo1 = new JsonObject();
        _jo1.addProperty("address", location.getAddress().toString());
        return new Response.Ok(_jo1);
    }

    /**
     * Get current function selected in Ghidra GUI
     */
    private Response getCurrentFunction() {
        CodeViewerService service = getActiveTool().getService(CodeViewerService.class);
        if (service == null) return errorJson("Code viewer service not available");

        ProgramLocation location = service.getCurrentLocation();
        if (location == null) return errorJson("No current location");

        Program program = getCurrentProgram();
        if (program == null) return errorJson("No program loaded");

        Function func = program.getFunctionManager().getFunctionContaining(location.getAddress());
        if (func == null) return errorJson("No function at current location: " + location.getAddress());

        JsonObject _jo2 = new JsonObject();
        _jo2.addProperty("name", func.getName());
        _jo2.addProperty("address", func.getEntryPoint().toString());
        _jo2.addProperty("signature", func.getSignature().toString());
        return new Response.Ok(_jo2);
    }

    /**
     * Gets a function at the given address or containing the address
     * @return the function or null if not found
     */
    private Function getFunctionForAddress(Program program, Address addr) {
        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            func = program.getFunctionManager().getFunctionContaining(addr);
        }
        return func;
    }

    /**
     * Set a local variable's type using HighFunctionDBUtil.updateDBVariable
     */
    private Response setLocalVariableType(String functionAddrStr, String variableName, String newType) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return Response.err("Function address is required");
        }

        if (variableName == null || variableName.isEmpty()) {
            return Response.err("Variable name is required");
        }

        if (newType == null || newType.isEmpty()) {
            return Response.err("New type is required");
        }

        final StringBuilder resultMsg = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    // Find the function
                    Address addr = program.getAddressFactory().getAddress(functionAddrStr);
                    if (addr == null) {
                        resultMsg.append("Error: Invalid address: ").append(functionAddrStr);
                        return;
                    }

                    Function func = getFunctionForAddress(program, addr);
                    if (func == null) {
                        resultMsg.append("Error: No function found at address ").append(functionAddrStr);
                        return;
                    }

                    DecompileResults results = decompileFunction(func, program);
                    if (results == null || !results.decompileCompleted()) {
                        resultMsg.append("Error: Decompilation failed for function at ").append(functionAddrStr);
                        return;
                    }

                    ghidra.program.model.pcode.HighFunction highFunction = results.getHighFunction();
                    if (highFunction == null) {
                        resultMsg.append("Error: No high function available");
                        return;
                    }

                    // Find the symbol by name
                    HighSymbol symbol = findSymbolByName(highFunction, variableName);
                    if (symbol == null) {
                        // PRIORITY 2 FIX: Provide helpful diagnostic information
                        resultMsg.append("Error: Variable '").append(variableName)
                                .append("' not found in decompiled function. ");

                        // List available variables for user guidance
                        List<String> availableNames = new ArrayList<>();
                        Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
                        while (symbols.hasNext()) {
                            availableNames.add(symbols.next().getName());
                        }

                        if (!availableNames.isEmpty()) {
                            resultMsg.append("Available variables: ")
                                    .append(String.join(", ", availableNames))
                                    .append(". ");
                        }

                        // Check if variable exists in low-level API but not high-level (phantom variable)
                        Variable[] lowLevelVars = func.getLocalVariables();
                        boolean isPhantomVariable = false;
                        for (Variable v : lowLevelVars) {
                            if (v.getName().equals(variableName)) {
                                isPhantomVariable = true;
                                break;
                            }
                        }

                        if (isPhantomVariable) {
                            resultMsg.append("NOTE: Variable '").append(variableName)
                                    .append("' exists in stack frame but not in decompiled code. ")
                                    .append("This is a phantom variable created by Ghidra's stack analysis ")
                                    .append("that was optimized away during decompilation. ")
                                    .append("You cannot set the type of phantom variables. ")
                                    .append("Only variables visible in the decompiled code can be typed.");
                        }

                        return;
                    }

                    // Get high variable
                    HighVariable highVar = symbol.getHighVariable();
                    if (highVar == null) {
                        resultMsg.append("Error: No HighVariable found for symbol: ").append(variableName);
                        return;
                    }

                    String oldType = highVar.getDataType().getName();

                    // Find the data type
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType dataType = dataTypeService.resolveDataType(dtm, newType);

                    if (dataType == null) {
                        resultMsg.append("Error: Could not resolve data type: ").append(newType);
                        return;
                    }

                    // Apply the type change in a transaction
                    StringBuilder errorDetails = new StringBuilder();
                    if (updateVariableType(program, symbol, dataType, success, errorDetails)) {
                        resultMsg.append("Success: Changed type of variable '").append(variableName)
                                .append("' from '").append(oldType).append("' to '")
                                .append(dataType.getName()).append("'");
                    } else {
                        // Provide detailed error message including storage location
                        String storageInfo = "unknown";
                        try {
                            storageInfo = symbol.getStorage().toString();
                        } catch (Exception e) {
                            // If we can't get storage, continue without it
                        }

                        resultMsg.append("Error: Failed to update variable type for '").append(variableName).append("'");
                        resultMsg.append(" (Storage: ").append(storageInfo).append(")");

                        if (errorDetails.length() > 0) {
                            resultMsg.append(". Details: ").append(errorDetails.toString());
                        }

                        // Add helpful guidance for known limitations
                        if (storageInfo.startsWith("Stack[-") && storageInfo.contains(":4")) {
                            resultMsg.append(". Note: Stack-based local variables with 4-byte size may have type-setting limitations in Ghidra's API");
                        }
                    }

                } catch (Exception e) {
                    resultMsg.append("Error: ").append(e.getMessage());
                    Msg.error(this, "Error setting variable type", e);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            resultMsg.append("Error: Failed to execute on Swing thread: ").append(e.getMessage());
            Msg.error(this, "Failed to execute set variable type on Swing thread", e);
        }

        return Response.text(resultMsg.length() > 0 ? resultMsg.toString() : "Error: Unknown failure");
    }

    /**
     * Find a high symbol by name in the given high function
     */
    private HighSymbol findSymbolByName(ghidra.program.model.pcode.HighFunction highFunction, String variableName) {
        Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol s = symbols.next();
            if (s.getName().equals(variableName)) {
                return s;
            }
        }
        return null;
    }

    /**
     * Decompile a function and return the results (with retry logic)
     */
    private DecompileResults decompileFunction(Function func, Program program) {
        return decompileFunctionWithRetry(func, program, 3);  // 3 retries for stability
    }

    /**
     * Decompile function with retry logic for stability (FIX #3)
     * Complex functions with SEH + alloca may fail initially but succeed on retry
     * @param func Function to decompile
     * @param program Current program
     * @param maxRetries Maximum number of retry attempts
     * @return Decompilation results or null if all retries exhausted
     */
    private DecompileResults decompileFunctionWithRetry(Function func, Program program, int maxRetries) {
        DecompInterface decomp = null;

        for (int attempt = 1; attempt <= maxRetries; attempt++) {
            try {
                decomp = new DecompInterface();
                decomp.openProgram(program);
                decomp.setSimplificationStyle("decompile");

                // On retry attempts, flush cache first and increase timeout
                if (attempt > 1) {
                    Msg.info(this, "Decompilation attempt " + attempt + " for function " + func.getName());
                    decomp.flushCache();

                    // Increase timeout on retries for complex functions
                    int timeoutSeconds = DECOMPILE_TIMEOUT_SECONDS * attempt;
                    DecompileResults results = decomp.decompileFunction(func, timeoutSeconds, new ConsoleTaskMonitor());

                    if (results != null && results.decompileCompleted()) {
                        Msg.info(this, "Decompilation succeeded on attempt " + attempt);
                        return results;
                    }

                    String errorMsg = (results != null) ? results.getErrorMessage() : "Unknown error";
                    Msg.warn(this, "Decompilation attempt " + attempt + " failed: " + errorMsg);
                } else {
                    // First attempt - use normal timeout
                    DecompileResults results = decomp.decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS, new ConsoleTaskMonitor());

                    if (results != null && results.decompileCompleted()) {
                        return results;
                    }

                    String errorMsg = (results != null) ? results.getErrorMessage() : "Unknown error";
                    Msg.warn(this, "Decompilation attempt " + attempt + " failed: " + errorMsg);
                }

            } catch (Exception e) {
                Msg.warn(this, "Decompilation attempt " + attempt + " threw exception: " + e.getMessage());
            } finally {
                if (decomp != null) {
                    decomp.dispose();
                    decomp = null;
                }
            }

            // Small delay between retries to allow Ghidra to stabilize
            if (attempt < maxRetries) {
                try {
                    Thread.sleep(100);  // 100ms delay
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                }
            }
        }

        Msg.error(this, "Could not decompile function after " + maxRetries + " attempts: " + func.getName());
        return null;
    }

    /**
     * Apply the type update in a transaction
     */
    private boolean updateVariableType(Program program, HighSymbol symbol, DataType dataType,
                                       AtomicBoolean success, StringBuilder errorDetails) {
        int tx = program.startTransaction("Set variable type");
        boolean result = false;
        String storageInfo = "unknown";

        try {
            // Get storage information for detailed logging
            try {
                storageInfo = symbol.getStorage().toString();
            } catch (Exception e) {
                // If we can't get storage, continue without it
            }

            // Log variable storage information for debugging
            Msg.info(this, "Attempting to set type for variable: " + symbol.getName() +
                          ", storage: " + storageInfo + ", new type: " + dataType.getName());

            // Use HighFunctionDBUtil to update the variable with the new type
            HighFunctionDBUtil.updateDBVariable(
                symbol,                // The high symbol to modify
                symbol.getName(),      // Keep original name
                dataType,              // The new data type
                SourceType.USER_DEFINED // Mark as user-defined
            );

            success.set(true);
            result = true;
            Msg.info(this, "Successfully set variable type using HighFunctionDBUtil");

        } catch (ghidra.util.exception.DuplicateNameException e) {
            String msg = "Variable name conflict: " + e.getMessage();
            Msg.error(this, msg, e);
            if (errorDetails != null) {
                errorDetails.append(msg).append(" (Storage: ").append(storageInfo).append(")");
            }
        } catch (ghidra.util.exception.InvalidInputException e) {
            String msg;

            // FIX: Detect register-based storage and provide helpful error message
            if (storageInfo.contains("ESP:") || storageInfo.contains("EDI:") ||
                storageInfo.contains("EAX:") || storageInfo.contains("EBX:") ||
                storageInfo.contains("ECX:") || storageInfo.contains("EDX:") ||
                storageInfo.contains("ESI:") || storageInfo.contains("EBP:")) {

                msg = "Cannot set type for register-based variable '" + symbol.getName() +
                      "' at storage location: " + storageInfo + ". " +
                      "Register variables (ESP/EDI/EAX/etc) are decompiler temporaries and cannot have types set via API. " +
                      "Workaround: Manually retype this variable in Ghidra's decompiler UI (right-click → Retype Variable). " +
                      "Ghidra limitation: " + e.getMessage();
            } else {
                msg = "Invalid input for variable type update: " + e.getMessage() +
                      " (Storage: " + storageInfo + ")";
            }

            Msg.error(this, msg, e);
            if (errorDetails != null) {
                errorDetails.append(msg);
            }
        } catch (IllegalArgumentException e) {
            String msg = "Illegal argument: " + e.getMessage();
            Msg.error(this, msg, e);
            if (errorDetails != null) {
                errorDetails.append(msg).append(" (Storage: ").append(storageInfo).append(")");
            }
        } catch (Exception e) {
            // Generic catch-all for unexpected exceptions
            String msg = "Unexpected error setting variable type: " + e.getClass().getName() + ": " + e.getMessage();
            Msg.error(this, msg, e);
            e.printStackTrace();  // Full stack trace for debugging
            if (errorDetails != null) {
                errorDetails.append(msg).append(" (Storage: ").append(storageInfo).append(")");
            }
        } finally {
            program.endTransaction(tx, success.get());
        }
        return result;
    }

    /**
     * Set a function's "No Return" attribute
     *
     * This method controls whether Ghidra treats a function as non-returning (like exit(), abort(), etc.).
     * When a function is marked as non-returning:
     * - Call sites are treated as terminators (CALL_TERMINATOR)
     * - Decompiler doesn't show code execution continuing after the call
     * - Control flow analysis treats the call like a RET instruction
     *
     * @param functionAddrStr The function address in hex format (e.g., "0x401000")
     * @param noReturn true to mark as non-returning, false to mark as returning
     * @return Success or error message
     */
    private Response setFunctionNoReturn(String functionAddrStr, String noReturnStr) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return Response.err("Function address is required");
        }
        boolean noReturn = noReturnStr != null && Boolean.parseBoolean(noReturnStr);

        final StringBuilder resultMsg = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Set function no return");
                try {
                    Address addr = program.getAddressFactory().getAddress(functionAddrStr);
                    if (addr == null) {
                        resultMsg.append("Error: Invalid address: ").append(functionAddrStr);
                        return;
                    }

                    Function func = getFunctionForAddress(program, addr);
                    if (func == null) {
                        resultMsg.append("Error: No function found at address ").append(functionAddrStr);
                        return;
                    }

                    String oldState = func.hasNoReturn() ? "non-returning" : "returning";

                    // Set the no-return attribute
                    func.setNoReturn(noReturn);

                    String newState = noReturn ? "non-returning" : "returning";
                    success.set(true);

                    resultMsg.append("Success: Set function '").append(func.getName())
                            .append("' at ").append(functionAddrStr)
                            .append(" from ").append(oldState)
                            .append(" to ").append(newState);

                    Msg.info(this, "Set no-return=" + noReturn + " for function " + func.getName() + " at " + functionAddrStr);

                } catch (Exception e) {
                    resultMsg.append("Error: ").append(e.getMessage());
                    Msg.error(this, "Error setting function no-return attribute", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            resultMsg.append("Error: Failed to execute on Swing thread: ").append(e.getMessage());
            Msg.error(this, "Failed to execute set no-return on Swing thread", e);
        }

        return Response.text(resultMsg.length() > 0 ? resultMsg.toString() : "Error: Unknown failure");
    }

    /**
     * Clear instruction-level flow override at a specific address
     *
     * This method clears flow overrides that are set on individual instructions (like CALL_TERMINATOR).
     * Flow overrides can be set at:
     * 1. Function level (via setNoReturn) - affects all call sites globally
     * 2. Instruction level (per call site) - takes precedence over function-level settings
     *
     * Use this method to:
     * - Clear CALL_TERMINATOR overrides on specific CALL instructions
     * - Remove incorrect flow analysis overrides
     * - Allow execution to continue after a call that was marked as non-returning
     *
     * After clearing the override, Ghidra will re-analyze the instruction using default flow rules.
     *
     * @param instructionAddrStr The instruction address in hex format (e.g., "0x6fb5c8b9")
     * @return Success or error message
     */
    private Response clearInstructionFlowOverride(String instructionAddrStr) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

        if (instructionAddrStr == null || instructionAddrStr.isEmpty()) {
            return Response.err("Instruction address is required");
        }

        final StringBuilder resultMsg = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Clear instruction flow override");
                try {
                    Address addr = program.getAddressFactory().getAddress(instructionAddrStr);
                    if (addr == null) {
                        resultMsg.append("Error: Invalid address: ").append(instructionAddrStr);
                        return;
                    }

                    // Get the instruction at the address
                    Listing listing = program.getListing();
                    ghidra.program.model.listing.Instruction instruction = listing.getInstructionAt(addr);

                    if (instruction == null) {
                        resultMsg.append("Error: No instruction found at address ").append(instructionAddrStr);
                        return;
                    }

                    // Get the current flow override type (if any)
                    ghidra.program.model.listing.FlowOverride oldOverride = instruction.getFlowOverride();

                    // Clear the flow override by setting to NONE
                    instruction.setFlowOverride(ghidra.program.model.listing.FlowOverride.NONE);

                    success.set(true);
                    resultMsg.append("Success: Cleared flow override at ").append(instructionAddrStr);
                    resultMsg.append(" (was: ").append(oldOverride.toString()).append(", now: NONE)");

                    // Get the instruction's mnemonic for logging
                    String mnemonic = instruction.getMnemonicString();
                    Msg.info(this, "Cleared flow override for instruction '" + mnemonic + "' at " + instructionAddrStr +
                             " (previous override: " + oldOverride + ")");

                } catch (Exception e) {
                    resultMsg.append("Error: ").append(e.getMessage());
                    Msg.error(this, "Error clearing instruction flow override", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            resultMsg.append("Error: Failed to execute on Swing thread: ").append(e.getMessage());
            Msg.error(this, "Failed to execute clear flow override on Swing thread", e);
        }

        return Response.text(resultMsg.length() > 0 ? resultMsg.toString() : "Error: Unknown failure");
    }

    /**
     * Set custom storage for a local variable or parameter (v1.7.0)
     *
     * This allows overriding Ghidra's automatic variable storage detection.
     * Useful for cases where registers are reused or compiler optimizations confuse the decompiler.
     *
     * @param functionAddrStr Function address containing the variable
     * @param variableName Name of the variable to modify
     * @param storageSpec Storage specification (e.g., "Stack[-0x10]:4", "EBP:4", "EAX:4")
     * @return Success or error message
     */
    private Response setVariableStorage(String functionAddrStr, String variableName, String storageSpec) {
        Program program = getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return Response.err("Function address is required");
        }
        if (variableName == null || variableName.isEmpty()) {
            return Response.err("Variable name is required");
        }
        if (storageSpec == null || storageSpec.isEmpty()) {
            return Response.err("Storage specification is required");
        }

        final StringBuilder resultMsg = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Set variable storage");
                try {
                    Address addr = program.getAddressFactory().getAddress(functionAddrStr);
                    if (addr == null) {
                        resultMsg.append("Error: Invalid function address: ").append(functionAddrStr);
                        return;
                    }

                    Function func = program.getFunctionManager().getFunctionAt(addr);
                    if (func == null) {
                        resultMsg.append("Error: No function found at address ").append(functionAddrStr);
                        return;
                    }

                    // Find the variable
                    Variable targetVar = null;
                    for (Variable var : func.getAllVariables()) {
                        if (var.getName().equals(variableName)) {
                            targetVar = var;
                            break;
                        }
                    }

                    if (targetVar == null) {
                        resultMsg.append("Error: Variable '").append(variableName).append("' not found in function ").append(func.getName());
                        return;
                    }

                    String oldStorage = targetVar.getVariableStorage().toString();

                    // Ghidra's variable storage API has limited programmatic access
                    // The proper way to change variable storage is through the decompiler UI
                    resultMsg.append("Note: Programmatic variable storage control is limited in Ghidra.\n\n");
                    resultMsg.append("Current variable information:\n");
                    resultMsg.append("  Variable: ").append(variableName).append("\n");
                    resultMsg.append("  Function: ").append(func.getName()).append(" @ ").append(functionAddrStr).append("\n");
                    resultMsg.append("  Current storage: ").append(oldStorage).append("\n");
                    resultMsg.append("  Requested storage: ").append(storageSpec).append("\n\n");
                    resultMsg.append("To change variable storage:\n");
                    resultMsg.append("1. Open the function in Ghidra's Decompiler window\n");
                    resultMsg.append("2. Right-click on the variable '").append(variableName).append("'\n");
                    resultMsg.append("3. Select 'Edit Data Type' or 'Retype Variable'\n");
                    resultMsg.append("4. Manually adjust the storage location\n\n");
                    resultMsg.append("Alternative approach:\n");
                    resultMsg.append("- Use run_script() to execute a custom Ghidra script\n");
                    resultMsg.append("- The script can use high-level Pcode/HighVariable API\n");
                    resultMsg.append("- See FixEBPRegisterReuse.java for an example\n");

                    success.set(true);
                    Msg.info(this, "Variable storage query for: " + variableName + " in " + func.getName() +
                             " (current: " + oldStorage + ", requested: " + storageSpec + ")");

                } catch (Exception e) {
                    resultMsg.append("Error: ").append(e.getMessage());
                    Msg.error(this, "Error setting variable storage", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            resultMsg.append("Error: Failed to execute on Swing thread: ").append(e.getMessage());
            Msg.error(this, "Failed to execute set variable storage on Swing thread", e);
        }

        return Response.text(resultMsg.length() > 0 ? resultMsg.toString() : "Error: Unknown failure");
    }

    /**
     * Run a Ghidra script programmatically (v1.7.0, fixed v2.0.1)
     *
     * Fixes: Issue #1 (args support via setScriptArgs), Issue #2 (OSGi path
     * resolution by copying to ~/ghidra_scripts/), Issue #5 (timeout protection).
     *
     * @param scriptPath Path to the script file (.java or .py), or just a filename
     * @param scriptArgs Optional space-separated arguments for the script
     * @return Script output or error message
     */
    private Response runGhidraScript(String scriptPath, String scriptArgs) {
        Program program = getCurrentProgram();
        if (program == null) {
            return errorJson("No program loaded");
        }

        final var result = new LinkedHashMap<String, Object>();
        final var scriptOutput = new StringBuilder();
        final var consoleOutput = new ByteArrayOutputStream();
        final var errorInfo = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);
        final PrintStream originalOut = System.out;
        final PrintStream originalErr = System.err;
        final File[] copiedScript = {null};

        result.put("script", scriptPath);
        result.put("program", program.getName());

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    PrintStream captureStream = new PrintStream(consoleOutput);
                    System.setOut(captureStream);
                    System.setErr(captureStream);

                    // Resolve script file — search standard locations
                    File ghidraScriptsDir = new File(System.getProperty("user.home"), "ghidra_scripts");
                    String[] possiblePaths = {
                        scriptPath,
                        new File(ghidraScriptsDir, scriptPath).getPath(),
                        new File(ghidraScriptsDir, new File(scriptPath).getName()).getPath(),
                        "./ghidra_scripts/" + scriptPath,
                        "./ghidra_scripts/" + new File(scriptPath).getName()
                    };

                    File resolvedFile = null;
                    for (String path : possiblePaths) {
                        try {
                            File candidate = new File(path);
                            if (candidate.exists() && candidate.isFile()) {
                                resolvedFile = candidate;
                                break;
                            }
                        } catch (Exception e) {
                            // Continue
                        }
                    }

                    if (resolvedFile == null) {
                        errorInfo.append("Script file not found. Searched: ")
                            .append(Arrays.toString(possiblePaths));
                        return;
                    }

                    // Issue #2 fix: If the script is NOT already in ~/ghidra_scripts/,
                    // copy it there so Ghidra's OSGi class loader can find the source bundle.
                    File scriptFileForExecution = resolvedFile;
                    try {
                        ghidraScriptsDir.mkdirs();
                        String canonicalScriptsDir = ghidraScriptsDir.getCanonicalPath();
                        String canonicalResolved = resolvedFile.getCanonicalPath();
                        if (!canonicalResolved.startsWith(canonicalScriptsDir + File.separator)) {
                            File dest = new File(ghidraScriptsDir, resolvedFile.getName());
                            java.nio.file.Files.copy(resolvedFile.toPath(), dest.toPath(),
                                java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                            scriptFileForExecution = dest;
                            copiedScript[0] = dest;
                        }
                    } catch (Exception e) {
                        // Non-fatal, script may still run from original location
                    }

                    generic.jar.ResourceFile scriptFile = new generic.jar.ResourceFile(scriptFileForExecution);
                    result.put("resolved_path", scriptFile.getAbsolutePath());

                    ghidra.app.script.GhidraScriptProvider provider = ghidra.app.script.GhidraScriptUtil.getProvider(scriptFile);
                    if (provider == null) {
                        errorInfo.append("No script provider found for: ").append(scriptFile.getName());
                        return;
                    }

                    StringWriter scriptWriter = new StringWriter();
                    PrintWriter scriptPrintWriter = new PrintWriter(scriptWriter);

                    ghidra.app.script.GhidraScript script = provider.getScriptInstance(scriptFile, scriptPrintWriter);
                    if (script == null) {
                        errorInfo.append("Failed to create script instance");
                        return;
                    }

                    ghidra.program.util.ProgramLocation location = new ghidra.program.util.ProgramLocation(program, program.getMinAddress());
                    ghidra.framework.plugintool.PluginTool pluginTool = EndpointRouter.this.getActiveTool();
                    ghidra.app.script.GhidraState scriptState = new ghidra.app.script.GhidraState(pluginTool, pluginTool.getProject(), program, location, null, null);

                    ghidra.util.task.TaskMonitor scriptMonitor = new ghidra.util.task.ConsoleTaskMonitor();
                    script.set(scriptState, scriptMonitor, scriptPrintWriter);

                    // Issue #1 + #5 fix: Parse and set script args BEFORE execution
                    String[] args = new String[0];
                    if (scriptArgs != null && !scriptArgs.trim().isEmpty()) {
                        args = scriptArgs.trim().split("\\s+");
                        script.setScriptArgs(args);
                        result.put("args", args);
                    }

                    script.runScript(scriptFile.getName(), args);

                    String output = scriptWriter.toString();
                    if (!output.isEmpty()) {
                        scriptOutput.append(output);
                    }

                    success.set(true);

                } catch (Exception e) {
                    errorInfo.append(e.getClass().getSimpleName()).append(": ").append(e.getMessage());
                    StringWriter sw = new StringWriter();
                    e.printStackTrace(new PrintWriter(sw));
                    result.put("stack_trace", sw.toString());
                    Msg.error(this, "Script execution failed: " + scriptPath, e);
                } finally {
                    System.setOut(originalOut);
                    System.setErr(originalErr);
                    if (copiedScript[0] != null) {
                        if (!copiedScript[0].delete()) {
                            copiedScript[0].deleteOnExit();
                        }
                    }
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            errorInfo.append("Failed to execute on Swing thread: ").append(e.getMessage());
            Msg.error(this, "Failed to execute on Swing thread", e);
        }

        result.put("success", success.get());
        if (scriptOutput.length() > 0) result.put("output", scriptOutput.toString());
        String captured = consoleOutput.toString();
        if (!captured.isEmpty()) result.put("console_output", captured);
        if (errorInfo.length() > 0) result.put("error", errorInfo.toString());

        return Response.ok(result);
    }

    /**
     * List available Ghidra scripts (v1.7.0)
     *
     * @param filter Optional filter string to match script names
     * @return JSON list of available scripts
     */
    private Response listGhidraScripts(String filter) {
        var response = new java.util.LinkedHashMap<String, Object>();
        response.put("note", "Script listing requires Ghidra GUI access");
        response.put("filter", filter != null ? filter : "none");
        response.put("instructions", List.of(
                "To view available scripts:",
                "1. Open Ghidra's Script Manager (Window -> Script Manager)",
                "2. Browse scripts by category",
                "3. Use the search filter at the top"
        ));
        response.put("common_script_locations", List.of(
                "<ghidra_install>/Ghidra/Features/*/ghidra_scripts/",
                "<user_home>/ghidra_scripts/"
        ));
        return Response.ok(response);
    }

    /**
     * Run a Ghidra script with enhanced output capture and timing.
     */
    private Response runGhidraScriptWithCapture(String scriptName, String scriptArgs, int timeoutSeconds, boolean captureOutput) throws Exception {
        if (scriptName == null || scriptName.isEmpty()) {
            return Response.err("Script name is required");
        }

        Program program = getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

        // Locate the script file
        File scriptFile = null;
        String filename = scriptName;
        boolean hasExtension = scriptName.contains(".");

        String[] searchDirs = {
            System.getProperty("user.home") + "/ghidra_scripts",
            System.getProperty("user.dir") + "/ghidra_scripts",
            "./ghidra_scripts"
        };

        String[] extensions = hasExtension ? new String[]{""} : new String[]{".java", ".py", ""};

        for (String dirPath : searchDirs) {
            if (dirPath == null) continue;
            for (String ext : extensions) {
                File candidate = new File(dirPath, filename + ext);
                if (candidate.exists()) {
                    scriptFile = candidate;
                    break;
                }
            }
            if (scriptFile != null) break;
        }

        if (scriptFile == null) {
            File candidate = new File(scriptName);
            if (candidate.exists()) {
                scriptFile = candidate;
            }
        }

        if (scriptFile == null) {
            StringBuilder searched = new StringBuilder();
            for (String dir : searchDirs) {
                if (dir != null) searched.append(dir).append(", ");
            }
            JsonObject jo = new JsonObject();
            jo.addProperty("success", false);
            jo.addProperty("error", "Script '" + filename + "' not found. Searched: " + searched);
            return new Response.Ok(jo);
        }

        long startTime = System.currentTimeMillis();
        Response scriptResponse = runGhidraScript(scriptFile.getAbsolutePath(), scriptArgs);
        double executionTime = (System.currentTimeMillis() - startTime) / 1000.0;

        @SuppressWarnings("unchecked")
        Map<String, Object> scriptResult = scriptResponse instanceof Response.Ok ok
                ? (Map<String, Object>) ok.data() : Map.of();
        String output = scriptResult.getOrDefault("output", "").toString();
        boolean succeeded = Boolean.TRUE.equals(scriptResult.get("success"));
        JsonObject jo = new JsonObject();
        jo.addProperty("success", succeeded);
        jo.addProperty("script_name", scriptName);
        jo.addProperty("script_path", scriptFile.getAbsolutePath());
        jo.addProperty("execution_time_seconds", String.format("%.2f", executionTime));
        jo.addProperty("console_output", output);
        return new Response.Ok(jo);
    }

    /**
     * Force decompiler reanalysis for a function (v1.7.0)
     *
     * Clears cached decompilation results and forces a fresh analysis.
    /**
     * Maps common C type names to Ghidra built-in DataType instances.
     * These types exist as Java classes but may not be in the per-program DTM.
     */
    private DataType resolveWellKnownType(String typeName) {
        switch (typeName.toLowerCase()) {
            case "int":        return ghidra.program.model.data.IntegerDataType.dataType;
            case "uint":       return ghidra.program.model.data.UnsignedIntegerDataType.dataType;
            case "short":      return ghidra.program.model.data.ShortDataType.dataType;
            case "ushort":     return ghidra.program.model.data.UnsignedShortDataType.dataType;
            case "long":       return ghidra.program.model.data.LongDataType.dataType;
            case "ulong":      return ghidra.program.model.data.UnsignedLongDataType.dataType;
            case "longlong":
            case "long long":  return ghidra.program.model.data.LongLongDataType.dataType;
            case "char":       return ghidra.program.model.data.CharDataType.dataType;
            case "uchar":      return ghidra.program.model.data.UnsignedCharDataType.dataType;
            case "float":      return ghidra.program.model.data.FloatDataType.dataType;
            case "double":     return ghidra.program.model.data.DoubleDataType.dataType;
            case "bool":
            case "boolean":    return ghidra.program.model.data.BooleanDataType.dataType;
            case "void":       return ghidra.program.model.data.VoidDataType.dataType;
            case "byte":       return ghidra.program.model.data.ByteDataType.dataType;
            case "sbyte":      return ghidra.program.model.data.SignedByteDataType.dataType;
            case "word":       return ghidra.program.model.data.WordDataType.dataType;
            case "dword":      return ghidra.program.model.data.DWordDataType.dataType;
            case "qword":      return ghidra.program.model.data.QWordDataType.dataType;
            case "int8_t":
            case "int8":       return ghidra.program.model.data.SignedByteDataType.dataType;
            case "uint8_t":
            case "uint8":      return ghidra.program.model.data.ByteDataType.dataType;
            case "int16_t":
            case "int16":      return ghidra.program.model.data.ShortDataType.dataType;
            case "uint16_t":
            case "uint16":     return ghidra.program.model.data.UnsignedShortDataType.dataType;
            case "int32_t":
            case "int32":      return ghidra.program.model.data.IntegerDataType.dataType;
            case "uint32_t":
            case "uint32":     return ghidra.program.model.data.UnsignedIntegerDataType.dataType;
            case "int64_t":
            case "int64":      return ghidra.program.model.data.LongLongDataType.dataType;
            case "uint64_t":
            case "uint64":     return ghidra.program.model.data.UnsignedLongLongDataType.dataType;
            case "size_t":     return ghidra.program.model.data.UnsignedIntegerDataType.dataType;
            case "unsigned int": return ghidra.program.model.data.UnsignedIntegerDataType.dataType;
            case "unsigned short": return ghidra.program.model.data.UnsignedShortDataType.dataType;
            case "unsigned long": return ghidra.program.model.data.UnsignedLongDataType.dataType;
            case "unsigned char": return ghidra.program.model.data.UnsignedCharDataType.dataType;
            case "signed char": return ghidra.program.model.data.SignedByteDataType.dataType;
            default:           return null;
        }
    }

    /**
     * Resolves a data type by name, handling common types and pointer types
     * @param dtm The data type manager
     * @param typeName The type name to resolve
     * @return The resolved DataType, or null if not found
     */
    private DataType resolveDataType(DataTypeManager dtm, String typeName) {
        // ZERO: Map common C type names to Ghidra built-in DataType instances
        // These types exist as Java classes but may not be registered in the per-program DTM
        DataType wellKnown = resolveWellKnownType(typeName);
        if (wellKnown != null) {
            Msg.info(this, "Resolved well-known type: " + typeName + " -> " + wellKnown.getName());
            return wellKnown;
        }

        // FIRST: Try Ghidra builtin types in root category (prioritize over Windows types)
        // This ensures we use lowercase builtin types (uint, ushort, byte) instead of
        // Windows SDK types (UINT, USHORT, BYTE) when the type name matches
        DataType builtinType = dtm.getDataType("/" + typeName);
        if (builtinType != null) {
            Msg.info(this, "Found builtin data type: " + builtinType.getPathName());
            return builtinType;
        }

        // SECOND: Try lowercase version of builtin types (handles "UINT" → "/uint")
        DataType builtinTypeLower = dtm.getDataType("/" + typeName.toLowerCase());
        if (builtinTypeLower != null) {
            Msg.info(this, "Found builtin data type (lowercase): " + builtinTypeLower.getPathName());
            return builtinTypeLower;
        }

        // THIRD: Search all categories as fallback (for Windows types, custom types, etc.)
        DataType dataType = dataTypeService.findDataTypeByName(dtm, typeName);
        if (dataType != null) {
            Msg.info(this, "Found data type in categories: " + dataType.getPathName());
            return dataType;
        }

        // Check for array syntax: "type[count]"
        if (typeName.contains("[") && typeName.endsWith("]")) {
            int bracketPos = typeName.indexOf('[');
            String baseTypeName = typeName.substring(0, bracketPos);
            String countStr = typeName.substring(bracketPos + 1, typeName.length() - 1);

            try {
                int count = Integer.parseInt(countStr);
                DataType baseType = dataTypeService.resolveDataType(dtm, baseTypeName);  // Recursive call

                if (baseType != null && count > 0) {
                    // Create array type on-the-fly
                    ArrayDataType arrayType = new ArrayDataType(baseType, count, baseType.getLength());
                    Msg.info(this, "Auto-created array type: " + typeName +
                            " (base: " + baseType.getName() + ", count: " + count +
                            ", total size: " + arrayType.getLength() + " bytes)");
                    return arrayType;
                } else if (baseType == null) {
                    Msg.error(this, "Cannot create array: base type '" + baseTypeName + "' not found");
                    return null;
                }
            } catch (NumberFormatException e) {
                Msg.error(this, "Invalid array count in type: " + typeName);
                return null;
            }
        }

        // Check for C-style pointer types (type*)
        if (typeName.endsWith("*")) {
            String baseTypeName = typeName.substring(0, typeName.length() - 1).trim();

            // Special case for void*
            if (baseTypeName.equals("void") || baseTypeName.isEmpty()) {
                Msg.info(this, "Creating void* pointer type");
                return new PointerDataType(dtm.getDataType("/void"));
            }

            // Try to resolve the base type recursively (handles nested types)
            DataType baseType = dataTypeService.resolveDataType(dtm, baseTypeName);
            if (baseType != null) {
                Msg.info(this, "Creating pointer type: " + typeName +
                        " (base: " + baseType.getName() + ")");
                return new PointerDataType(baseType);
            }

            // If base type not found, warn and default to void*
            Msg.warn(this, "Base type not found for " + typeName + ", defaulting to void*");
            return new PointerDataType(dtm.getDataType("/void"));
        }

        // Check for Windows-style pointer types (PXXX)
        if (typeName.startsWith("P") && typeName.length() > 1) {
            String baseTypeName = typeName.substring(1);

            // Special case for PVOID
            if (baseTypeName.equals("VOID")) {
                return new PointerDataType(dtm.getDataType("/void"));
            }

            // Try to find the base type
            DataType baseType = dataTypeService.findDataTypeByName(dtm, baseTypeName);
            if (baseType != null) {
                return new PointerDataType(baseType);
            }

            Msg.warn(this, "Base type not found for " + typeName + ", defaulting to void*");
            return new PointerDataType(dtm.getDataType("/void"));
        }

        // Handle common built-in types
        switch (typeName.toLowerCase()) {
            case "int":
            case "long":
                return dtm.getDataType("/int");
            case "uint":
            case "unsigned int":
            case "unsigned long":
            case "dword":
                return dtm.getDataType("/uint");
            case "short":
                return dtm.getDataType("/short");
            case "ushort":
            case "unsigned short":
            case "word":
                return dtm.getDataType("/ushort");
            case "char":
            case "byte":
                return dtm.getDataType("/char");
            case "uchar":
            case "unsigned char":
                return dtm.getDataType("/uchar");
            case "longlong":
            case "__int64":
                return dtm.getDataType("/longlong");
            case "ulonglong":
            case "unsigned __int64":
                return dtm.getDataType("/ulonglong");
            case "bool":
            case "boolean":
                return dtm.getDataType("/bool");
            case "float":
                return dtm.getDataType("/dword");  // Use dword as 4-byte float substitute
            case "double":
                return dtm.getDataType("/double");
            case "void":
                return dtm.getDataType("/void");
            default:
                // Try as a direct path
                DataType directType = dtm.getDataType("/" + typeName);
                if (directType != null) {
                    return directType;
                }

                // Return null if type not found - let caller handle error
                Msg.error(this, "Unknown type: " + typeName);
                return null;
        }
    }
    
    /**
     * Find a data type by name in all categories/folders of the data type manager
     * This searches through all categories rather than just the root
     */
    private DataType findDataTypeByNameInAllCategories(DataTypeManager dtm, String typeName) {
        // Try exact match first
        DataType result = searchByNameInAllCategories(dtm, typeName);
        if (result != null) {
            return result;
        }

        // Try lowercase
        return searchByNameInAllCategories(dtm, typeName.toLowerCase());
    }

    /**
     * Helper method to search for a data type by name in all categories
     */
    private DataType searchByNameInAllCategories(DataTypeManager dtm, String name) {
        // Get all data types from the manager
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            // Check if the name matches exactly (case-sensitive) 
            if (dt.getName().equals(name)) {
                return dt;
            }
            // For case-insensitive, we want an exact match except for case
            if (dt.getName().equalsIgnoreCase(name)) {
                return dt;
            }
        }
        return null;
    }

    private Map<String, String> parseQueryParams(HttpExchange exchange) {
        return EndpointRegistrar.parseQueryParams(exchange);
    }

    private Map<String, String> parsePostParams(HttpExchange exchange) throws IOException {
        return EndpointRegistrar.parsePostParams(exchange);
    }

    private Map<String, Object> parseJsonParams(HttpExchange exchange) throws IOException {
        return EndpointRegistrar.parseJsonParams(exchange);
    }
    

    private List<Map<String, String>> convertToMapList(Object obj) {
        return EndpointRegistrar.convertToMapList(obj);
    }

    private int parseIntOrDefault(String val, int defaultValue) {
        return EndpointRegistrar.parseIntOrDefault(val, defaultValue);
    }

    private String objectToCommaSeparated(Object obj) {
        return EndpointRegistrar.objectToCommaSeparated(obj);
    }

    private String paginateList(List<String> items, int offset, int limit) {
        int start = Math.max(0, offset);
        int end   = Math.min(items.size(), offset + limit);
        if (start >= items.size()) return "";
        return String.join("\n", items.subList(start, end));
    }

    @FunctionalInterface interface CheckedHandler { void handle(HttpExchange ex) throws Exception; }
    private UdsHttpServer.Handler checked(CheckedHandler h) {
        return ex -> { try { h.handle(ex); } catch (IOException e) { throw e; } catch (Exception e) { throw new IOException(e); } };
    }


    /**
     * Get a program by name with error message if not found.
     * Returns a JSON error string if the program cannot be found.
     * 
     * @param programName The name of the program to find
     * @return A 2-element array: [0] = Program (or null), [1] = error message (or null if found)
     */
    public Object[] getProgramOrError(String programName) {
        Program program = getProgram(programName);
        
        if (program == null && programName != null && !programName.trim().isEmpty()) {
            var available = new ArrayList<String>();
            for (Program p : programProvider.getAllOpenPrograms()) available.add(p.getName());
            var err = new LinkedHashMap<String, Object>();
            err.put("error", "Program not found: " + programName);
            err.put("available_programs", available);
            return new Object[] { null, Response.ok(err) };
        }

        if (program == null) {
            return new Object[] { null, errorJson("No program currently loaded") };
        }
        
        return new Object[] { program, null };
    }

    /**
     * List all currently open programs in Ghidra
     */
    private Response saveCurrentProgram() {
        Program program = getCurrentProgram();
        if (program == null) {
            return errorJson("No program loaded");
        }

        final AtomicReference<Response> result = new AtomicReference<>();
        final AtomicReference<String> errorMsg = new AtomicReference<>();

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    ghidra.framework.model.DomainFile df = program.getDomainFile();
                    if (df == null) {
                        errorMsg.set("Program has no domain file");
                        return;
                    }
                    df.save(new ConsoleTaskMonitor());
                    final var name = program.getName();
                    JsonObject _jo4 = new JsonObject();
                    _jo4.addProperty("success", true);
                    _jo4.addProperty("program_name", name);
                    _jo4.addProperty("message", "Program saved successfully");
                    result.set(new Response.Ok(_jo4));
                } catch (Throwable e) {
                    String msg = e.getMessage() != null ? e.getMessage() : e.toString();
                    errorMsg.set(msg);
                    Msg.error(this, "Error saving program", e);
                }
            });

            if (errorMsg.get() != null) {
                return errorJson(errorMsg.get());
            }
        } catch (Throwable e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.toString();
            return errorJson(msg);
        }

        return result.get() != null ? result.get() : errorJson("Unknown failure");
    }

    private Response listOpenPrograms() {
        Program[] programs = programProvider.getAllOpenPrograms();
        Program currentProgram = programProvider.getCurrentProgram();

        var list = new ArrayList<>();
        for (Program prog : programs) {
            final var name = prog.getName();
            final var path = prog.getDomainFile().getPathname();
            final var isCurrent = prog == currentProgram;
            final var execPath = prog.getExecutablePath() != null ? prog.getExecutablePath() : "";
            final var language = prog.getLanguageID().getIdAsString();
            final var compiler = prog.getCompilerSpec().getCompilerSpecID().getIdAsString();
            final var imageBase = prog.getImageBase().toString();
            final var memSize = prog.getMemory().getSize();
            final var funcCount = prog.getFunctionManager().getFunctionCount();
            JsonObject _jo5 = new JsonObject();
            _jo5.addProperty("prog_name", name);
            _jo5.addProperty("prog_path", path);
            _jo5.addProperty("is_current", isCurrent);
            _jo5.addProperty("executable_path", execPath);
            _jo5.addProperty("language_id", language);
            _jo5.addProperty("compiler_id", compiler);
            _jo5.addProperty("image_base", imageBase);
            _jo5.addProperty("memory_size", memSize);
            _jo5.addProperty("function_count", funcCount);
            list.add(_jo5);
        }

        final var progList = list;
        final var count = programs.length;
        final var currentName = currentProgram != null ? currentProgram.getName() : "";
        JsonObject _jo6 = new JsonObject();
        _jo6.add("program_list", JsonHelper.gson().toJsonTree(progList));
        _jo6.addProperty("program_count", count);
        _jo6.addProperty("current_program", currentName);
        return new Response.Ok(_jo6);
    }

    /**
     * Get detailed information about the currently active program
     */
    private Response getCurrentProgramInfo() {
        Program program = getCurrentProgram();
        if (program == null) {
            return errorJson("No program currently loaded");
        }

        final var name = program.getName();
        final var path = program.getDomainFile().getPathname();
        final var execPath = program.getExecutablePath() != null ? program.getExecutablePath() : "";
        final var execFormat = program.getExecutableFormat();
        final var language = program.getLanguageID().getIdAsString();
        final var compiler = program.getCompilerSpec().getCompilerSpecID().getIdAsString();
        final var addrSize = program.getAddressFactory().getDefaultAddressSpace().getSize();
        final var imageBase = program.getImageBase().toString();
        final var minAddr = program.getMinAddress() != null ? program.getMinAddress().toString() : "null";
        final var maxAddr = program.getMaxAddress() != null ? program.getMaxAddress().toString() : "null";
        final var memSize = program.getMemory().getSize();
        final var funcCount = program.getFunctionManager().getFunctionCount();
        final var symCount = program.getSymbolTable().getNumSymbols();
        final var dtCount = program.getDataTypeManager().getDataTypeCount(true);
        final var creationDate = program.getCreationDate() != null ? program.getCreationDate().toString() : "unknown";
        final var memBlockCount = program.getMemory().getBlocks().length;

        JsonObject _jo7 = new JsonObject();
        _jo7.addProperty("prog_name", name);
        _jo7.addProperty("prog_path", path);
        _jo7.addProperty("executable_path", execPath);
        _jo7.addProperty("executable_format", execFormat);
        _jo7.addProperty("language_id", language);
        _jo7.addProperty("compiler_id", compiler);
        _jo7.addProperty("address_size", addrSize);
        _jo7.addProperty("image_base", imageBase);
        _jo7.addProperty("min_address", minAddr);
        _jo7.addProperty("max_address", maxAddr);
        _jo7.addProperty("memory_size", memSize);
        _jo7.addProperty("function_count", funcCount);
        _jo7.addProperty("symbol_count", symCount);
        _jo7.addProperty("data_type_count", dtCount);
        _jo7.addProperty("creation_date", creationDate);
        _jo7.addProperty("memory_block_count", memBlockCount);
        return new Response.Ok(_jo7);
    }

    /**
     * Switch MCP context to a different open program by name
     */
    private Response switchProgram(String programName) {
        if (programName == null || programName.trim().isEmpty()) {
            return errorJson("Program name is required");
        }

        // Use MultiToolProgramProvider which searches across all CodeBrowser windows
        Program targetProgram = programProvider.getProgram(programName);

        if (targetProgram == null) {
            var available = new ArrayList<String>();
            for (Program prog : programProvider.getAllOpenPrograms()) {
                available.add(prog.getName());
            }
            final var requestedName = programName;
            final var availableList = available;
            JsonObject _jo8 = new JsonObject();
            _jo8.addProperty("error", "Program not found: " + requestedName);
            _jo8.add("available_programs", JsonHelper.gson().toJsonTree(availableList));
            return new Response.Ok(_jo8);
        }

        // Switch to the target program (finds owning tool and sets it there)
        programProvider.setCurrentProgram(targetProgram);

        final var switchedTo = targetProgram.getName();
        final var switchedPath = targetProgram.getDomainFile().getPathname();
        JsonObject _jo9 = new JsonObject();
        _jo9.addProperty("success", true);
        _jo9.addProperty("switched_to", switchedTo);
        _jo9.addProperty("path", switchedPath);
        return new Response.Ok(_jo9);
    }

    /**
     * List all files in the current Ghidra project
     */
    private Response listProjectFiles(String folderPath) {
        ghidra.framework.model.Project project = getActiveTool().getProject();
        if (project == null) {
            return errorJson("No project is currently open");
        }

        ghidra.framework.model.ProjectData projectData = project.getProjectData();
        ghidra.framework.model.DomainFolder rootFolder = projectData.getRootFolder();

        // If folder path specified, navigate to it
        ghidra.framework.model.DomainFolder targetFolder = rootFolder;
        if (folderPath != null && !folderPath.trim().isEmpty() && !folderPath.equals("/")) {
            // Navigate through path segments (handles nested folders like "LoD/1.07")
            String cleanPath = folderPath.startsWith("/") ? folderPath.substring(1) : folderPath;
            String[] pathParts = cleanPath.split("/");
            for (String part : pathParts) {
                if (part.isEmpty()) continue;
                ghidra.framework.model.DomainFolder nextFolder = targetFolder.getFolder(part);
                if (nextFolder == null) {
                    return errorJson("Folder not found: " + folderPath);
                }
                targetFolder = nextFolder;
            }
        }

        // List subfolders
        var folderNames = new ArrayList<String>();
        for (ghidra.framework.model.DomainFolder sub : targetFolder.getFolders()) {
            folderNames.add(sub.getName());
        }

        // List files in folder
        var fileList = new ArrayList<>();
        for (ghidra.framework.model.DomainFile file : targetFolder.getFiles()) {
            final var fname = file.getName();
            final var fpath = file.getPathname();
            final var ftype = file.getContentType();
            final var fver = file.getVersion();
            final var fro = file.isReadOnly();
            final var fversioned = file.isVersioned();
            JsonObject _jo10 = new JsonObject();
            _jo10.addProperty("name", fname);
            _jo10.addProperty("path", fpath);
            _jo10.addProperty("content_type", ftype);
            _jo10.addProperty("version", fver);
            _jo10.addProperty("is_read_only", fro);
            _jo10.addProperty("is_versioned", fversioned);
            fileList.add(_jo10);
        }

        final var projName = project.getName();
        final var currFolder = targetFolder.getPathname();
        final var folders = folderNames;
        final var files = fileList;
        JsonObject _jo11 = new JsonObject();
        _jo11.addProperty("project_name", projName);
        _jo11.addProperty("current_folder", currFolder);
        _jo11.add("sub_folders", JsonHelper.gson().toJsonTree(folders));
        _jo11.add("project_files", JsonHelper.gson().toJsonTree(files));
        return new Response.Ok(_jo11);
    }

    /**
     * Open a program from the current project by path
     */
    private Response openProgramFromProject(String path) {
        if (path == null || path.trim().isEmpty()) {
            return errorJson("Program path is required");
        }

        ghidra.framework.model.Project project = getActiveTool().getProject();
        if (project == null) {
            return errorJson("No project is currently open");
        }

        ghidra.framework.model.ProjectData projectData = project.getProjectData();
        ghidra.framework.model.DomainFile domainFile = projectData.getFile(path);

        if (domainFile == null) {
            return errorJson("File not found in project: " + path);
        }

        // Check if already open across all tools
        for (Program prog : programProvider.getAllOpenPrograms()) {
            if (prog.getDomainFile().getPathname().equals(path)) {
                // Already open, just switch to it
                programProvider.setCurrentProgram(prog);
                final var alreadyName = prog.getName();
                final var alreadyPath = path;
                JsonObject _jo12 = new JsonObject();
                _jo12.addProperty("success", true);
                _jo12.addProperty("message", "Program already open, switched to it");
                _jo12.addProperty("name", alreadyName);
                _jo12.addProperty("prog_path", alreadyPath);
                return new Response.Ok(_jo12);
            }
        }

        // Need a ProgramManager to open new programs — find one from any tool
        ProgramManager pm = programProvider.findProgramManager();
        if (pm == null) {
            return errorJson("No CodeBrowser window available to open programs");
        }

        // Open via DomainFile overload — OPEN_CURRENT makes it the active program.
        // This bypasses the manual getDomainObject + openProgram(Program) path and
        // lets ProgramManagerPlugin handle the open lifecycle properly.
        try {
            Program program = pm.openProgram(domainFile, ProgramManager.OPEN_CURRENT);
            if (program == null) {
                return errorJson("Failed to open program: " + path);
            }

            // Auto-analyze silently if not yet analyzed, suppressing the "Analyze?" dialog
            ghidra.app.plugin.core.analysis.AutoAnalysisManager mgr =
                ghidra.app.plugin.core.analysis.AutoAnalysisManager.getAnalysisManager(program);
            if (mgr != null && !mgr.isAnalyzing()) {
                mgr.initializeOptions();
                mgr.reAnalyzeAll(program.getMemory());
                mgr.startAnalysis(ghidra.util.task.TaskMonitor.DUMMY);
            }

            final var openedName = program.getName();
            final var openedPath = path;
            final var funcCount = program.getFunctionManager().getFunctionCount();
            JsonObject _jo13 = new JsonObject();
            _jo13.addProperty("success", true);
            _jo13.addProperty("message", "Program opened successfully");
            _jo13.addProperty("name", openedName);
            _jo13.addProperty("prog_path", openedPath);
            _jo13.addProperty("function_count", funcCount);
            return new Response.Ok(_jo13);
        } catch (Exception e) {
            return errorJson("Failed to open program: " + e.getMessage());
        }
    }

    /** Builds a JSON error response body. Delegates to JsonHelper for consistent format. */
    private static Response.Err errorJson(String message) {
        return new Response.Err(message != null ? message : "Unknown error");
    }

    /**
     * Wraps an HttpHandler so that any Throwable is caught and returned as a JSON error response.
     * This prevents uncaught exceptions from crashing the HTTP server and dropping connections.
     */
    private UdsHttpServer.Handler safeHandler(UdsHttpServer.Handler handler) {
        return exchange -> {
            try {
                handler.handle(exchange);
            } catch (Throwable e) {
                try {
                    String msg = e.getMessage() != null ? e.getMessage() : e.toString();
                    EndpointRegistrar.sendResponse(exchange, new Response.Err(msg));
                } catch (Throwable ignored) {
                    Msg.error(this, "Failed to send error response", ignored);
                }
            }
        };
    }

    private void sendResponse(HttpExchange exchange, Response response) throws IOException {
        EndpointRegistrar.sendResponse(exchange, response);
    }
    /**
     * Get a call graph subgraph centered on the specified function
     */
    public Response getFunctionCallGraph(String functionName, int depth, String direction, String programName) {
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) return (Response) programResult[1];

        FunctionManager functionManager = program.getFunctionManager();

        Function rootFunction = null;
        for (Function f : functionManager.getFunctions(true)) {
            if (f.getName().equals(functionName)) {
                rootFunction = f;
                break;
            }
        }

        if (rootFunction == null) {
            return errorJson("Function not found: " + functionName);
        }

        Set<String> visited = new HashSet<>();
        Map<String, Set<String>> callGraph = new HashMap<>();

        if ("callees".equals(direction) || "both".equals(direction)) {
            buildCallGraphCallees(rootFunction, depth, visited, callGraph, functionManager);
        }

        if ("callers".equals(direction) || "both".equals(direction)) {
            visited.clear();
            buildCallGraphCallers(rootFunction, depth, visited, callGraph, functionManager);
        }

        var edges = new ArrayList<>();
        for (Map.Entry<String, Set<String>> entry : callGraph.entrySet()) {
            final var caller = entry.getKey();
            for (String callee : entry.getValue()) {
                final var calleeName = callee;
                JsonObject _jo28 = new JsonObject();
                _jo28.addProperty("from", caller);
                _jo28.addProperty("to", calleeName);
                edges.add(_jo28);
            }
        }

        final var edgeList = edges;
        JsonObject _jo29 = new JsonObject();
        _jo29.add("call_edges", JsonHelper.gson().toJsonTree(edgeList));
        return new Response.Ok(_jo29);
    }

    /**
     * Helper method to build call graph for callees (what this function calls)
     */
    private void buildCallGraphCallees(Function function, int depth, Set<String> visited, 
                                     Map<String, Set<String>> callGraph, FunctionManager functionManager) {
        if (depth <= 0 || visited.contains(function.getName())) {
            return;
        }
        
        visited.add(function.getName());
        Set<String> callees = new HashSet<>();
        
        // Find callees of this function
        AddressSetView functionBody = function.getBody();
        Listing listing = getCurrentProgram().getListing();
        ReferenceManager refManager = getCurrentProgram().getReferenceManager();
        
        InstructionIterator instructions = listing.getInstructions(functionBody, true);
        while (instructions.hasNext()) {
            Instruction instr = instructions.next();
            
            if (instr.getFlowType().isCall()) {
                Reference[] references = refManager.getReferencesFrom(instr.getAddress());
                for (Reference ref : references) {
                    if (ref.getReferenceType().isCall()) {
                        Address targetAddr = ref.getToAddress();
                        Function targetFunc = functionManager.getFunctionAt(targetAddr);
                        if (targetFunc != null) {
                            callees.add(targetFunc.getName());
                            // Recursively build graph for callees
                            buildCallGraphCallees(targetFunc, depth - 1, visited, callGraph, functionManager);
                        }
                    }
                }
            }
        }
        
        if (!callees.isEmpty()) {
            callGraph.put(function.getName(), callees);
        }
    }

    /**
     * Helper method to build call graph for callers (what calls this function)
     */
    private void buildCallGraphCallers(Function function, int depth, Set<String> visited, 
                                     Map<String, Set<String>> callGraph, FunctionManager functionManager) {
        if (depth <= 0 || visited.contains(function.getName())) {
            return;
        }
        
        visited.add(function.getName());
        ReferenceManager refManager = getCurrentProgram().getReferenceManager();
        
        // Find callers of this function
        ReferenceIterator refIter = refManager.getReferencesTo(function.getEntryPoint());
        while (refIter.hasNext()) {
            Reference ref = refIter.next();
            if (ref.getReferenceType().isCall()) {
                Address fromAddr = ref.getFromAddress();
                Function callerFunc = functionManager.getFunctionContaining(fromAddr);
                if (callerFunc != null) {
                    String callerName = callerFunc.getName();
                    callGraph.computeIfAbsent(callerName, k -> new HashSet<>()).add(function.getName());
                    // Recursively build graph for callers
                    buildCallGraphCallers(callerFunc, depth - 1, visited, callGraph, functionManager);
                }
            }
        }
    }

    /**
     * Get the complete call graph for the entire program
     */
    public Response getFullCallGraph(String format, int limit, String programName) {
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) return (Response) programResult[1];

        FunctionManager functionManager = program.getFunctionManager();
        ReferenceManager refManager = program.getReferenceManager();
        Listing listing = program.getListing();

        Map<String, Set<String>> callGraph = new HashMap<>();
        int relationshipCount = 0;

        for (Function function : functionManager.getFunctions(true)) {
            if (relationshipCount >= limit) break;

            String functionName = function.getName();
            Set<String> callees = new HashSet<>();

            AddressSetView functionBody = function.getBody();
            InstructionIterator instructions = listing.getInstructions(functionBody, true);

            while (instructions.hasNext() && relationshipCount < limit) {
                Instruction instr = instructions.next();
                if (instr.getFlowType().isCall()) {
                    for (Reference ref : refManager.getReferencesFrom(instr.getAddress())) {
                        if (ref.getReferenceType().isCall()) {
                            Function targetFunc = functionManager.getFunctionAt(ref.getToAddress());
                            if (targetFunc != null) {
                                callees.add(targetFunc.getName());
                                if (++relationshipCount >= limit) break;
                            }
                        }
                    }
                }
            }

            if (!callees.isEmpty()) {
                callGraph.put(functionName, callees);
            }
        }

        if (callGraph.isEmpty()) {
            return errorJson("No call relationships found in the program");
        }

        // Text formats: return as raw string (sent verbatim by sendResponse)
        if ("dot".equals(format)) {
            StringBuilder sb = new StringBuilder();
            sb.append("digraph CallGraph {\n");
            sb.append("  rankdir=TB;\n");
            sb.append("  node [shape=box];\n");
            for (Map.Entry<String, Set<String>> entry : callGraph.entrySet()) {
                String caller = entry.getKey().replace("\"", "\\\"");
                for (String callee : entry.getValue()) {
                    sb.append("  \"").append(caller).append("\" -> \"")
                      .append(callee.replace("\"", "\\\"")).append("\";\n");
                }
            }
            sb.append("}");
            return Response.text(sb.toString());
        } else if ("mermaid".equals(format)) {
            StringBuilder sb = new StringBuilder();
            sb.append("graph TD\n");
            for (Map.Entry<String, Set<String>> entry : callGraph.entrySet()) {
                String caller = entry.getKey().replace(" ", "_");
                for (String callee : entry.getValue()) {
                    sb.append("  ").append(caller).append(" --> ")
                      .append(callee.replace(" ", "_")).append("\n");
                }
            }
            return Response.text(sb.toString());
        } else if ("adjacency".equals(format)) {
            StringBuilder sb = new StringBuilder();
            for (Map.Entry<String, Set<String>> entry : callGraph.entrySet()) {
                if (sb.length() > 0) sb.append("\n");
                sb.append(entry.getKey()).append(": ").append(String.join(", ", entry.getValue()));
            }
            return Response.text(sb.toString());
        } else {
            // Default "edges" format: return structured object
            var edges = new ArrayList<>();
            for (Map.Entry<String, Set<String>> entry : callGraph.entrySet()) {
                final var caller = entry.getKey();
                for (String callee : entry.getValue()) {
                    final var calleeName = callee;
                    JsonObject _jo30 = new JsonObject();
                    _jo30.addProperty("from", caller);
                    _jo30.addProperty("to", calleeName);
                    edges.add(_jo30);
                }
            }
            final var edgeList = edges;
            JsonObject _jo31 = new JsonObject();
            _jo31.add("call_edges", JsonHelper.gson().toJsonTree(edgeList));
            return new Response.Ok(_jo31);
        }
    }

    /**
     * Enhanced call graph analysis with cycle detection and path finding
     * Provides advanced graph algorithms for understanding function relationships
     */
    public Response analyzeCallGraph(String startFunction, String endFunction, String analysisType, String programName) {
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) return (Response) programResult[1];

        try {
            FunctionManager functionManager = program.getFunctionManager();
            ReferenceManager refManager = program.getReferenceManager();

            Map<String, Set<String>> callGraph = new LinkedHashMap<>();
            Map<String, String> functionAddresses = new LinkedHashMap<>();

            for (Function func : functionManager.getFunctions(true)) {
                if (func.isThunk()) continue;

                String funcName = func.getName();
                functionAddresses.put(funcName, func.getEntryPoint().toString());
                Set<String> callees = new HashSet<>();

                Listing listing = program.getListing();
                InstructionIterator instrIter = listing.getInstructions(func.getBody(), true);

                while (instrIter.hasNext()) {
                    Instruction instr = instrIter.next();
                    if (instr.getFlowType().isCall()) {
                        for (Reference ref : refManager.getReferencesFrom(instr.getAddress())) {
                            if (ref.getReferenceType().isCall()) {
                                Function calledFunc = functionManager.getFunctionAt(ref.getToAddress());
                                if (calledFunc != null && !calledFunc.isThunk()) {
                                    callees.add(calledFunc.getName());
                                }
                            }
                        }
                    }
                }

                if (!callees.isEmpty()) {
                    callGraph.put(funcName, callees);
                }
            }

            if ("cycles".equals(analysisType)) {
                List<List<String>> cycles = findCycles(callGraph);
                var cycleObjs = new ArrayList<>();
                for (int i = 0; i < Math.min(cycles.size(), 20); i++) {
                    final var path = List.copyOf(cycles.get(i));
                    JsonObject _jo32 = new JsonObject();
                    _jo32.addProperty("length", path.size());
                    _jo32.add("path_nodes", JsonHelper.gson().toJsonTree(path));
                    cycleObjs.add(_jo32);
                }
                if (cycles.size() > 20) {
                    final var note = (cycles.size() - 20) + " additional cycles omitted";
                    JsonObject _jo33 = new JsonObject();
                    _jo33.addProperty("note_message", note);
                    cycleObjs.add(_jo33);
                }
                final int total = cycles.size();
                final var cycleList = cycleObjs;
                JsonObject _jo34 = new JsonObject();
                _jo34.addProperty("analysis_type", "cycle_detection");
                _jo34.addProperty("cycles_found", total);
                _jo34.add("cycles", JsonHelper.gson().toJsonTree(cycleList));
                return new Response.Ok(_jo34);

            } else if ("path".equals(analysisType) && startFunction != null && endFunction != null) {
                List<String> path = findShortestPath(callGraph, startFunction, endFunction);
                final var start = startFunction;
                final var end = endFunction;
                if (path != null) {
                    final int pathLen = path.size() - 1;
                    final var pathList = List.copyOf(path);
                    JsonObject _jo35 = new JsonObject();
                    _jo35.addProperty("analysis_type", "path_finding");
                    _jo35.addProperty("start_function", start);
                    _jo35.addProperty("end_function", end);
                    _jo35.addProperty("path_found", true);
                    _jo35.addProperty("path_length", pathLen);
                    _jo35.add("path_nodes", JsonHelper.gson().toJsonTree(pathList));
                    return new Response.Ok(_jo35);
                } else {
                    JsonObject _jo36 = new JsonObject();
                    _jo36.addProperty("analysis_type", "path_finding");
                    _jo36.addProperty("start_function", start);
                    _jo36.addProperty("end_function", end);
                    _jo36.addProperty("path_found", false);
                    _jo36.addProperty("message", "No path exists between the specified functions");
                    return new Response.Ok(_jo36);
                }

            } else if ("strongly_connected".equals(analysisType)) {
                List<Set<String>> sccs = findStronglyConnectedComponents(callGraph);
                List<Set<String>> nonTrivialSCCs = new ArrayList<>();
                for (Set<String> scc : sccs) {
                    if (scc.size() > 1) nonTrivialSCCs.add(scc);
                }
                var components = new ArrayList<>();
                for (int i = 0; i < Math.min(nonTrivialSCCs.size(), 20); i++) {
                    Set<String> scc = nonTrivialSCCs.get(i);
                    final int sz = scc.size();
                    List<String> funcs = new ArrayList<>();
                    int j = 0;
                    for (String fn : scc) {
                        if (j++ >= 10) break;
                        funcs.add(fn);
                    }
                    if (sz > 10) funcs.add("..." + (sz - 10) + " more");
                    final var funcList = List.copyOf(funcs);
                    JsonObject _jo37 = new JsonObject();
                    _jo37.addProperty("size", sz);
                    _jo37.add("functions", JsonHelper.gson().toJsonTree(funcList));
                    components.add(_jo37);
                }
                final int totalSccs = sccs.size();
                final int nonTrivial = nonTrivialSCCs.size();
                final var compList = components;
                JsonObject _jo38 = new JsonObject();
                _jo38.addProperty("analysis_type", "strongly_connected_components");
                _jo38.addProperty("total_sccs", totalSccs);
                _jo38.addProperty("non_trivial_sccs", nonTrivial);
                _jo38.add("components", JsonHelper.gson().toJsonTree(compList));
                return new Response.Ok(_jo38);

            } else if ("entry_points".equals(analysisType)) {
                Set<String> allFunctions = new HashSet<>(functionAddresses.keySet());
                Set<String> calledFunctions = new HashSet<>();
                for (Set<String> callees : callGraph.values()) calledFunctions.addAll(callees);
                Set<String> entryPoints = new HashSet<>(allFunctions);
                entryPoints.removeAll(calledFunctions);

                var epObjs = new ArrayList<>();
                int idx = 0;
                for (String ep : entryPoints) {
                    if (idx++ >= 50) {
                        final var note = (entryPoints.size() - 50) + " more entry points";
                        JsonObject _jo39 = new JsonObject();
                        _jo39.addProperty("note_message", note);
                        epObjs.add(_jo39);
                        break;
                    }
                    final var name = ep;
                    final var addr = functionAddresses.getOrDefault(ep, "unknown");
                    JsonObject _jo40 = new JsonObject();
                    _jo40.addProperty("function_name", name);
                    _jo40.addProperty("address", addr);
                    epObjs.add(_jo40);
                }
                final int totalFuncs = allFunctions.size();
                final int epCount = entryPoints.size();
                final var epList = epObjs;
                JsonObject _jo41 = new JsonObject();
                _jo41.addProperty("analysis_type", "entry_point_detection");
                _jo41.addProperty("total_functions", totalFuncs);
                _jo41.addProperty("entry_points_found", epCount);
                _jo41.add("entry_points", JsonHelper.gson().toJsonTree(epList));
                return new Response.Ok(_jo41);

            } else if ("leaf_functions".equals(analysisType)) {
                Set<String> leafFunctions = new HashSet<>(functionAddresses.keySet());
                leafFunctions.removeAll(callGraph.keySet());

                var lfObjs = new ArrayList<>();
                int idx = 0;
                for (String lf : leafFunctions) {
                    if (idx++ >= 50) {
                        final var note = (leafFunctions.size() - 50) + " more leaf functions";
                        JsonObject _jo42 = new JsonObject();
                        _jo42.addProperty("note_message", note);
                        lfObjs.add(_jo42);
                        break;
                    }
                    final var name = lf;
                    final var addr = functionAddresses.getOrDefault(lf, "unknown");
                    JsonObject _jo43 = new JsonObject();
                    _jo43.addProperty("function_name", name);
                    _jo43.addProperty("address", addr);
                    lfObjs.add(_jo43);
                }
                final int lfCount = leafFunctions.size();
                final var lfList = lfObjs;
                JsonObject _jo44 = new JsonObject();
                _jo44.addProperty("analysis_type", "leaf_function_detection");
                _jo44.addProperty("leaf_functions_found", lfCount);
                _jo44.add("leaf_functions", JsonHelper.gson().toJsonTree(lfList));
                return new Response.Ok(_jo44);

            } else {
                // Default: summary statistics
                int totalEdges = 0;
                int maxOutDegree = 0;
                String maxOutDegreeFunc = "";
                Map<String, Integer> inDegree = new HashMap<>();

                for (Map.Entry<String, Set<String>> entry : callGraph.entrySet()) {
                    totalEdges += entry.getValue().size();
                    if (entry.getValue().size() > maxOutDegree) {
                        maxOutDegree = entry.getValue().size();
                        maxOutDegreeFunc = entry.getKey();
                    }
                    for (String callee : entry.getValue()) {
                        inDegree.put(callee, inDegree.getOrDefault(callee, 0) + 1);
                    }
                }

                int maxInDegree = 0;
                String maxInDegreeFunc = "";
                for (Map.Entry<String, Integer> entry : inDegree.entrySet()) {
                    if (entry.getValue() > maxInDegree) {
                        maxInDegree = entry.getValue();
                        maxInDegreeFunc = entry.getKey();
                    }
                }

                final int totFuncs = functionAddresses.size();
                final int funcsWithCalls = callGraph.size();
                final int totEdges = totalEdges;
                final var maxOutFunc = maxOutDegreeFunc;
                final int maxOut = maxOutDegree;
                final var maxInFunc = maxInDegreeFunc;
                final int maxIn = maxInDegree;
                JsonObject _jo_maxOut = new JsonObject();
                _jo_maxOut.addProperty("function", maxOutFunc);
                _jo_maxOut.addProperty("calls", maxOut);
                JsonObject _jo_maxIn = new JsonObject();
                _jo_maxIn.addProperty("function", maxInFunc);
                _jo_maxIn.addProperty("called_by", maxIn);
                JsonObject _jo_summary = new JsonObject();
                _jo_summary.addProperty("analysis_type", "summary");
                _jo_summary.addProperty("total_functions", totFuncs);
                _jo_summary.addProperty("functions_with_calls", funcsWithCalls);
                _jo_summary.addProperty("total_call_edges", totEdges);
                _jo_summary.add("max_out_degree", _jo_maxOut);
                _jo_summary.add("max_in_degree", _jo_maxIn);
                _jo_summary.add("available_analyses", JsonHelper.gson().toJsonTree(List.of(
                    "cycles", "path", "strongly_connected", "entry_points", "leaf_functions")));
                return new Response.Ok(_jo_summary);
            }

        } catch (Exception e) {
            return errorJson(e.getMessage());
        }
    }
    
    /**
     * Find cycles in directed graph using DFS
     */
    private List<List<String>> findCycles(Map<String, Set<String>> graph) {
        List<List<String>> cycles = new ArrayList<>();
        Set<String> visited = new HashSet<>();
        Set<String> recStack = new HashSet<>();
        Map<String, String> parent = new HashMap<>();
        
        for (String node : graph.keySet()) {
            if (!visited.contains(node)) {
                findCyclesDFS(node, graph, visited, recStack, parent, cycles);
            }
        }
        
        return cycles;
    }
    
    private void findCyclesDFS(String node, Map<String, Set<String>> graph, Set<String> visited,
                               Set<String> recStack, Map<String, String> parent, List<List<String>> cycles) {
        visited.add(node);
        recStack.add(node);
        
        Set<String> neighbors = graph.getOrDefault(node, Collections.emptySet());
        for (String neighbor : neighbors) {
            if (!visited.contains(neighbor)) {
                parent.put(neighbor, node);
                findCyclesDFS(neighbor, graph, visited, recStack, parent, cycles);
            } else if (recStack.contains(neighbor)) {
                // Found a cycle - reconstruct it
                List<String> cycle = new ArrayList<>();
                cycle.add(neighbor);
                String current = node;
                while (current != null && !current.equals(neighbor)) {
                    cycle.add(0, current);
                    current = parent.get(current);
                }
                cycle.add(0, neighbor);
                if (cycles.size() < 100) { // Limit cycles
                    cycles.add(cycle);
                }
            }
        }
        
        recStack.remove(node);
    }
    
    /**
     * Find shortest path using BFS
     */
    private List<String> findShortestPath(Map<String, Set<String>> graph, String start, String end) {
        if (start.equals(end)) {
            return Arrays.asList(start);
        }
        
        Queue<String> queue = new LinkedList<>();
        Map<String, String> parent = new HashMap<>();
        Set<String> visited = new HashSet<>();
        
        queue.add(start);
        visited.add(start);
        
        while (!queue.isEmpty()) {
            String current = queue.poll();
            Set<String> neighbors = graph.getOrDefault(current, Collections.emptySet());
            
            for (String neighbor : neighbors) {
                if (!visited.contains(neighbor)) {
                    visited.add(neighbor);
                    parent.put(neighbor, current);
                    
                    if (neighbor.equals(end)) {
                        // Reconstruct path
                        List<String> path = new ArrayList<>();
                        String node = end;
                        while (node != null) {
                            path.add(0, node);
                            node = parent.get(node);
                        }
                        return path;
                    }
                    
                    queue.add(neighbor);
                }
            }
        }
        
        return null; // No path found
    }
    
    /**
     * Find strongly connected components using Kosaraju's algorithm
     */
    private List<Set<String>> findStronglyConnectedComponents(Map<String, Set<String>> graph) {
        // Step 1: Fill vertices in stack according to finishing times
        Stack<String> stack = new Stack<>();
        Set<String> visited = new HashSet<>();
        
        // Get all nodes
        Set<String> allNodes = new HashSet<>(graph.keySet());
        for (Set<String> neighbors : graph.values()) {
            allNodes.addAll(neighbors);
        }
        
        for (String node : allNodes) {
            if (!visited.contains(node)) {
                fillOrder(node, graph, visited, stack);
            }
        }
        
        // Step 2: Create reversed graph
        Map<String, Set<String>> reversedGraph = new HashMap<>();
        for (Map.Entry<String, Set<String>> entry : graph.entrySet()) {
            for (String neighbor : entry.getValue()) {
                reversedGraph.computeIfAbsent(neighbor, k -> new HashSet<>()).add(entry.getKey());
            }
        }
        
        // Step 3: Process vertices in order of decreasing finish time
        visited.clear();
        List<Set<String>> sccs = new ArrayList<>();
        
        while (!stack.isEmpty()) {
            String node = stack.pop();
            if (!visited.contains(node)) {
                Set<String> scc = new HashSet<>();
                dfsCollect(node, reversedGraph, visited, scc);
                sccs.add(scc);
            }
        }
        
        return sccs;
    }
    
    private void fillOrder(String node, Map<String, Set<String>> graph, Set<String> visited, Stack<String> stack) {
        visited.add(node);
        Set<String> neighbors = graph.getOrDefault(node, Collections.emptySet());
        for (String neighbor : neighbors) {
            if (!visited.contains(neighbor)) {
                fillOrder(neighbor, graph, visited, stack);
            }
        }
        stack.push(node);
    }
    
    private void dfsCollect(String node, Map<String, Set<String>> graph, Set<String> visited, Set<String> component) {
        visited.add(node);
        component.add(node);
        Set<String> neighbors = graph.getOrDefault(node, Collections.emptySet());
        for (String neighbor : neighbors) {
            if (!visited.contains(neighbor)) {
                dfsCollect(neighbor, graph, visited, component);
            }
        }
    }
    private Response batchRenameFunctionComponents(String functionAddress, String functionName,
                                                Map<String, String> parameterRenames,
                                                Map<String, String> localRenames,
                                                String returnType) {
        Program program = getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

        final AtomicBoolean success = new AtomicBoolean(false);
        final AtomicReference<String> error = new AtomicReference<>();
        final AtomicReference<Integer> paramsRenamed = new AtomicReference<>(0);
        final AtomicReference<Integer> localsRenamed = new AtomicReference<>(0);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Batch Rename Function Components");
                try {
                    Address addr = program.getAddressFactory().getAddress(functionAddress);
                    if (addr == null) {
                        error.set("Invalid address: " + functionAddress);
                        return;
                    }

                    Function func = program.getFunctionManager().getFunctionAt(addr);
                    if (func == null) {
                        error.set("No function at address: " + functionAddress);
                        return;
                    }

                    if (functionName != null && !functionName.isEmpty()) {
                        func.setName(functionName, SourceType.USER_DEFINED);
                    }

                    if (parameterRenames != null && !parameterRenames.isEmpty()) {
                        Parameter[] params = func.getParameters();
                        for (Parameter param : params) {
                            String newName = parameterRenames.get(param.getName());
                            if (newName != null && !newName.isEmpty()) {
                                param.setName(newName, SourceType.USER_DEFINED);
                                paramsRenamed.getAndSet(paramsRenamed.get() + 1);
                            }
                        }
                    }

                    if (localRenames != null && !localRenames.isEmpty()) {
                        Variable[] locals = func.getLocalVariables();
                        for (Variable local : locals) {
                            String newName = localRenames.get(local.getName());
                            if (newName != null && !newName.isEmpty()) {
                                local.setName(newName, SourceType.USER_DEFINED);
                                localsRenamed.getAndSet(localsRenamed.get() + 1);
                            }
                        }
                    }

                    if (returnType != null && !returnType.isEmpty()) {
                        DataTypeManager dtm = program.getDataTypeManager();
                        DataType dt = dtm.getDataType(returnType);
                        if (dt != null) {
                            func.setReturnType(dt, SourceType.USER_DEFINED);
                        }
                    }

                    success.set(true);
                } catch (Exception e) {
                    error.set(e.getMessage());
                    Msg.error(this, "Error in batch rename", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }

        if (error.get() != null) {
            return Response.err(error.get());
        }

        JsonObject jo = new JsonObject();
        jo.addProperty("success", true);
        jo.addProperty("function_renamed", functionName != null);
        jo.addProperty("parameters_renamed", paramsRenamed.get());
        jo.addProperty("locals_renamed", localsRenamed.get());
        return new Response.Ok(jo);
    }
    private Response batchSetVariableTypesOptimized(String functionAddress, Map<String, String> variableTypes) {
        if (variableTypes == null || variableTypes.isEmpty()) {
            JsonObject _jo56 = new JsonObject();
            _jo56.addProperty("success", true);
            _jo56.addProperty("method", "optimized");
            _jo56.addProperty("variables_typed", 0);
            _jo56.addProperty("variables_failed", 0);
            return new Response.Ok(_jo56);
        }

        final AtomicInteger variablesTyped = new AtomicInteger(0);
        final AtomicInteger variablesFailed = new AtomicInteger(0);
        final List<String> errors = new ArrayList<>();

        for (Map.Entry<String, String> entry : variableTypes.entrySet()) {
            String varName = entry.getKey();
            String newType = entry.getValue();

            try {
                Response resp = setLocalVariableType(functionAddress, varName, newType);
                String result = resp instanceof Response.Text t ? t.content()
                              : resp instanceof Response.Err e ? e.message()
                              : resp.toString();

                if (result.toLowerCase().contains("success")) {
                    variablesTyped.incrementAndGet();
                } else {
                    errors.add(varName + ": " + result);
                    variablesFailed.incrementAndGet();
                }

                // Small delay to allow Ghidra to process
                try {
                    Thread.sleep(50);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                }
            } catch (Exception e) {
                errors.add(varName + ": " + e.getMessage());
                variablesFailed.incrementAndGet();
            }
        }

        int typed = variablesTyped.get();
        int failed = variablesFailed.get();
        List<String> errorsCopy = new ArrayList<>(errors);
        JsonObject _jo57 = new JsonObject();
        _jo57.addProperty("success", failed == 0 && typed > 0);
        _jo57.addProperty("method", "optimized");
        _jo57.addProperty("variables_typed", typed);
        _jo57.addProperty("variables_failed", failed);
        _jo57.add("errors", JsonHelper.gson().toJsonTree(errorsCopy.isEmpty() ? null : errorsCopy));
        return new Response.Ok(_jo57);
    }
    // ==================== SERVER LIFECYCLE ====================

}
