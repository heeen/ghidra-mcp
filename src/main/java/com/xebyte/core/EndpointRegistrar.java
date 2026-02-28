package com.xebyte.core;

import com.sun.net.httpserver.Headers;
import com.xebyte.core.services.*;
import ghidra.util.Msg;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.function.Consumer;

/**
 * Shared endpoint dispatch infrastructure.
 * Registers {@link Ep} entries against any server that provides a {@link ContextRegistrar}.
 * Extracted from EndpointRouter so both GUI and headless can share the same dispatch logic.
 */
public final class EndpointRegistrar {

    private EndpointRegistrar() {}

    /**
     * Abstraction for registering an HTTP context handler on a server.
     * GUI uses UdsHttpServer, headless uses com.sun.net.httpserver.HttpServer.
     */
    @FunctionalInterface
    public interface ContextRegistrar {
        void createContext(String path, Consumer<HttpExchange> handler);
    }

    // ==================================================================================
    // Bulk registration
    // ==================================================================================

    public static void registerAll(ContextRegistrar registrar, List<Ep> table) {
        for (Ep ep : table) {
            register(registrar, ep);
        }
    }

    // ==================================================================================
    // Single endpoint dispatch — exhaustive switch on Ep variants
    // ==================================================================================

    public static void register(ContextRegistrar registrar, Ep ep) {
        switch (ep) {
            case Ep.Get0(var path, var fn)                                     -> get0(registrar, path, fn);
            case Ep.Get1(var path, var p1, var fn)                             -> get1(registrar, path, p1, fn);
            case Ep.Get2(var path, var p1, var p2, var fn)                     -> get2(registrar, path, p1, p2, fn);
            case Ep.Get3(var path, var p1, var p2, var p3, var fn)             -> get3(registrar, path, p1, p2, p3, fn);
            case Ep.Get4(var path, var p1, var p2, var p3, var p4, var fn)     -> get4(registrar, path, p1, p2, p3, p4, fn);
            case Ep.GetPage(var path, var fn)                                  -> getPage(registrar, path, fn);
            case Ep.GetPage1(var path, var pn, var fn)                         -> getPage1(registrar, path, pn, fn);
            case Ep.GetPage1R(var path, var pn, var fn)                        -> getPage1r(registrar, path, pn, fn);
            case Ep.GetPageNP(var path, var fn)                                -> getPageNP(registrar, path, fn);
            case Ep.GetPage1NP(var path, var pn, var fn)                       -> getPage1NP(registrar, path, pn, fn);
            case Ep.GetQuery(var path, var fn)                                 -> getWithQuery(registrar, path, fn);
            case Ep.Post1(var path, var p1, var fn)                            -> post1(registrar, path, p1, fn);
            case Ep.Post2(var path, var p1, var p2, var fn)                    -> post2(registrar, path, p1, p2, fn);
            case Ep.Post3(var path, var p1, var p2, var p3, var fn)            -> post3(registrar, path, p1, p2, p3, fn);
            case Ep.Json1(var path, var p1, var fn)                            -> json1(registrar, path, p1, fn);
            case Ep.Json2(var path, var p1, var p2, var fn)                    -> json2(registrar, path, p1, p2, fn);
            case Ep.Json3(var path, var p1, var p2, var p3, var fn)            -> json3(registrar, path, p1, p2, p3, fn);
            case Ep.Json4(var path, var p1, var p2, var p3, var p4, var fn)    -> json4(registrar, path, p1, p2, p3, p4, fn);
            case Ep.JsonPost(var path, var fn)                                 -> jsonPost(registrar, path, fn);
        }
    }

    // ==================================================================================
    // Handler helpers — each wires a specific Ep pattern to param parsing + dispatch
    // ==================================================================================

    private static void getPage(ContextRegistrar r, String path, Ep.PageFn fn) {
        r.createContext(path, safeHandler(ex -> {
            Map<String,String> q = parseQueryParams(ex);
            sendResponse(ex, fn.apply(parseIntOrDefault(q.get("offset"),0), parseIntOrDefault(q.get("limit"),100), q.get("program")));
        }));
    }

    private static void getPage1(ContextRegistrar r, String path, String pName, Ep.PageFn1 fn) {
        r.createContext(path, safeHandler(ex -> {
            Map<String,String> q = parseQueryParams(ex);
            sendResponse(ex, fn.apply(q.get(pName), parseIntOrDefault(q.get("offset"),0), parseIntOrDefault(q.get("limit"),100), q.get("program")));
        }));
    }

    private static void getPage1r(ContextRegistrar r, String path, String pName, Ep.PageFn1R fn) {
        r.createContext(path, safeHandler(ex -> {
            Map<String,String> q = parseQueryParams(ex);
            sendResponse(ex, fn.apply(parseIntOrDefault(q.get("offset"),0), parseIntOrDefault(q.get("limit"),100), q.get(pName), q.get("program")));
        }));
    }

    private static void get0(ContextRegistrar r, String path, Ep.Fn0 fn) {
        r.createContext(path, safeHandler(ex -> sendResponse(ex, fn.apply())));
    }

    private static void get1(ContextRegistrar r, String path, String p1, Ep.Fn1 fn) {
        r.createContext(path, safeHandler(ex -> sendResponse(ex, fn.apply(parseQueryParams(ex).get(p1)))));
    }

    private static void get2(ContextRegistrar r, String path, String p1, String p2, Ep.Fn2 fn) {
        r.createContext(path, safeHandler(ex -> {
            Map<String,String> q = parseQueryParams(ex);
            sendResponse(ex, fn.apply(q.get(p1), q.get(p2)));
        }));
    }

    private static void get3(ContextRegistrar r, String path, String p1, String p2, String p3, Ep.Fn3 fn) {
        r.createContext(path, safeHandler(ex -> {
            Map<String,String> q = parseQueryParams(ex);
            sendResponse(ex, fn.apply(q.get(p1), q.get(p2), q.get(p3)));
        }));
    }

    private static void get4(ContextRegistrar r, String path, String p1, String p2, String p3, String p4, Ep.Fn4 fn) {
        r.createContext(path, safeHandler(ex -> {
            Map<String,String> q = parseQueryParams(ex);
            sendResponse(ex, fn.apply(q.get(p1), q.get(p2), q.get(p3), q.get(p4)));
        }));
    }

    private static void getPageNP(ContextRegistrar r, String path, Ep.PageFn0 fn) {
        r.createContext(path, safeHandler(ex -> {
            Map<String,String> q = parseQueryParams(ex);
            sendResponse(ex, fn.apply(parseIntOrDefault(q.get("offset"),0), parseIntOrDefault(q.get("limit"),100)));
        }));
    }

    private static void getPage1NP(ContextRegistrar r, String path, String pName, Ep.PageFn1NP fn) {
        r.createContext(path, safeHandler(ex -> {
            Map<String,String> q = parseQueryParams(ex);
            sendResponse(ex, fn.apply(q.get(pName), parseIntOrDefault(q.get("offset"),0), parseIntOrDefault(q.get("limit"),100)));
        }));
    }

    private static void getWithQuery(ContextRegistrar r, String path, Ep.QueryHandler fn) {
        r.createContext(path, safeHandler(ex -> sendResponse(ex, fn.apply(parseQueryParams(ex)))));
    }

    private static void post1(ContextRegistrar r, String path, String p1, Ep.Fn1 fn) {
        r.createContext(path, safeHandler(ex -> sendResponse(ex, fn.apply(parsePostParams(ex).get(p1)))));
    }

    private static void post2(ContextRegistrar r, String path, String p1, String p2, Ep.Fn2 fn) {
        r.createContext(path, safeHandler(ex -> {
            Map<String,String> p = parsePostParams(ex);
            sendResponse(ex, fn.apply(p.get(p1), p.get(p2)));
        }));
    }

    private static void post3(ContextRegistrar r, String path, String p1, String p2, String p3, Ep.Fn3 fn) {
        r.createContext(path, safeHandler(ex -> {
            Map<String,String> p = parsePostParams(ex);
            sendResponse(ex, fn.apply(p.get(p1), p.get(p2), p.get(p3)));
        }));
    }

    private static void json1(ContextRegistrar r, String path, String p1, Ep.Fn1 fn) {
        r.createContext(path, safeHandler(ex -> sendResponse(ex, fn.apply((String) parseJsonParams(ex).get(p1)))));
    }

    private static void json2(ContextRegistrar r, String path, String p1, String p2, Ep.Fn2 fn) {
        r.createContext(path, safeHandler(ex -> {
            Map<String,Object> j = parseJsonParams(ex);
            sendResponse(ex, fn.apply((String) j.get(p1), (String) j.get(p2)));
        }));
    }

    private static void json3(ContextRegistrar r, String path, String p1, String p2, String p3, Ep.Fn3 fn) {
        r.createContext(path, safeHandler(ex -> {
            Map<String,Object> j = parseJsonParams(ex);
            sendResponse(ex, fn.apply((String) j.get(p1), (String) j.get(p2), (String) j.get(p3)));
        }));
    }

    private static void json4(ContextRegistrar r, String path, String p1, String p2, String p3, String p4, Ep.Fn4 fn) {
        r.createContext(path, safeHandler(ex -> {
            Map<String,Object> j = parseJsonParams(ex);
            sendResponse(ex, fn.apply((String) j.get(p1), (String) j.get(p2), (String) j.get(p3), (String) j.get(p4)));
        }));
    }

    private static void jsonPost(ContextRegistrar r, String path, Ep.JsonHandler fn) {
        r.createContext(path, safeHandler(ex -> sendResponse(ex, fn.apply(parseJsonParams(ex)))));
    }

    // ==================================================================================
    // Param parsing
    // ==================================================================================

    public static Map<String, String> parseQueryParams(HttpExchange exchange) {
        Map<String, String> result = new HashMap<>();
        String query = exchange.getRequestURI().getQuery();
        if (query != null) {
            for (String p : query.split("&")) {
                String[] kv = p.split("=", 2);
                if (kv.length == 2) {
                    try {
                        result.put(
                            URLDecoder.decode(kv[0], StandardCharsets.UTF_8),
                            URLDecoder.decode(kv[1], StandardCharsets.UTF_8));
                    } catch (Exception e) {
                        // skip malformed param
                    }
                }
            }
        }
        return result;
    }

    public static Map<String, String> parsePostParams(HttpExchange exchange) throws IOException {
        byte[] body = exchange.getRequestBody().readAllBytes();
        String bodyStr = new String(body, StandardCharsets.UTF_8);
        Map<String, String> params = new HashMap<>();
        for (String pair : bodyStr.split("&")) {
            String[] kv = pair.split("=", 2);
            if (kv.length == 2) {
                try {
                    params.put(
                        URLDecoder.decode(kv[0], StandardCharsets.UTF_8),
                        URLDecoder.decode(kv[1], StandardCharsets.UTF_8));
                } catch (Exception e) {
                    // skip malformed param
                }
            }
        }
        return params;
    }

    public static Map<String, Object> parseJsonParams(HttpExchange exchange) throws IOException {
        return JsonHelper.parseBody(exchange.getRequestBody());
    }

    // ==================================================================================
    // Response sending
    // ==================================================================================

    public static void sendResponse(HttpExchange exchange, Response response) throws IOException {
        String body = switch (response) {
            case Response.Ok(var data)     -> JsonHelper.toJson(data);
            case Response.Err(var message) -> JsonHelper.toJson(Map.of("error", message));
            case Response.Text(var text)   -> text;
        };
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
            os.flush();
        }
    }

    // ==================================================================================
    // Safe handler wrapper
    // ==================================================================================

    @FunctionalInterface
    private interface CheckedHandler { void handle(HttpExchange ex) throws Exception; }

    private static Consumer<HttpExchange> safeHandler(CheckedHandler handler) {
        return exchange -> {
            try {
                handler.handle(exchange);
            } catch (Throwable e) {
                try {
                    String msg = e.getMessage() != null ? e.getMessage() : e.toString();
                    sendResponse(exchange, new Response.Err(msg));
                } catch (Throwable ignored) {
                    Msg.error(EndpointRegistrar.class, "Failed to send error response", ignored);
                }
            }
        };
    }

    // ==================================================================================
    // Static param helpers
    // ==================================================================================

    public static int getInt(Map<String, ?> map, String key, int defaultValue) {
        Object v = map != null ? map.get(key) : null;
        if (v == null) return defaultValue;
        if (v instanceof Number) return ((Number) v).intValue();
        try { return Integer.parseInt(v.toString()); } catch (NumberFormatException e) { return defaultValue; }
    }

    public static double getDouble(Map<String, ?> map, String key, double defaultValue) {
        Object v = map != null ? map.get(key) : null;
        if (v == null) return defaultValue;
        if (v instanceof Number) return ((Number) v).doubleValue();
        try { return Double.parseDouble(v.toString()); } catch (NumberFormatException e) { return defaultValue; }
    }

    public static boolean getBool(Map<String, ?> map, String key, boolean defaultValue) {
        Object v = map != null ? map.get(key) : null;
        if (v == null) return defaultValue;
        if (v instanceof Boolean) return (Boolean) v;
        return Boolean.parseBoolean(v.toString());
    }

    public static String getStr(Map<String, ?> map, String key) {
        Object v = map != null ? map.get(key) : null;
        return v != null ? v.toString() : null;
    }

    /** Coerce a parsed JSON value (String, List, Map) to a JSON string for service methods that accept raw JSON. */
    public static String coerceToJsonString(Object obj) {
        if (obj == null) return null;
        if (obj instanceof String) return (String) obj;
        return JsonHelper.toJson(obj);
    }

    public static int parseIntOrDefault(String val, int defaultValue) {
        if (val == null) return defaultValue;
        try { return Integer.parseInt(val); } catch (NumberFormatException e) { return defaultValue; }
    }

    /** Convert Object (potentially List) to List<Map<String, String>> for batch operations. */
    @SuppressWarnings("unchecked")
    public static List<Map<String, String>> convertToMapList(Object obj) {
        if (obj == null) return null;
        if (obj instanceof List) {
            List<Object> objList = (List<Object>) obj;
            List<Map<String, String>> result = new ArrayList<>();
            for (Object item : objList) {
                if (item instanceof Map) {
                    result.add((Map<String, String>) item);
                }
            }
            return result;
        }
        return null;
    }

    public static String objectToCommaSeparated(Object obj) {
        if (obj == null) return "";
        if (obj instanceof List) {
            StringBuilder sb = new StringBuilder();
            for (Object item : (List<?>) obj) {
                if (item != null) {
                    if (sb.length() > 0) sb.append(",");
                    sb.append(item.toString());
                }
            }
            return sb.toString();
        }
        return obj.toString();
    }

    // ==================================================================================
    // Shared endpoint table — entries that are identical for GUI and headless
    // ==================================================================================

    /**
     * Returns the shared endpoint table: ~112 entries that reference only service methods,
     * with no GUI-only or headless-only dependencies.
     * Both EndpointRouter (GUI) and GhidraMCPHeadlessServer (headless) call this and
     * append their own server-specific entries.
     */
    @SuppressWarnings("unchecked")
    public static List<Ep> sharedEndpoints(
            ListingService listingService,
            CommentService commentService,
            SymbolService symbolService,
            FunctionService functionService,
            MutationService mutationService,
            DataTypeService dataTypeService,
            AnalysisService analysisService,
            ComparisonService comparisonService) {

        return List.of(
            // --- Listing ---
            new Ep.GetPage("/list_methods", listingService::listMethods),
            new Ep.GetPage("/list_classes", listingService::listClasses),
            new Ep.GetPage("/list_segments", listingService::listSegments),
            new Ep.GetPage("/list_imports", listingService::listImports),
            new Ep.GetPage("/list_exports", listingService::listExports),
            new Ep.GetPage("/list_namespaces", listingService::listNamespaces),
            new Ep.GetPage("/list_data_items", listingService::listDataItems),
            new Ep.GetPage1R("/list_data_items_by_xrefs", "format", listingService::listDataItemsByXrefs),
            new Ep.GetPage("/list_functions", listingService::listFunctions),
            new Ep.GetQuery("/list_functions_enhanced", q ->
                listingService.listFunctionsEnhanced(getInt(q, "offset", 0), getInt(q, "limit", 10000), getStr(q, "program"))),

            // --- Rename / Mutation ---
            new Ep.Post2("/rename_function", "oldName", "newName", mutationService::renameFunction),
            new Ep.Post2("/rename_data", "address", "newName", mutationService::renameData),
            new Ep.Post3("/rename_variable", "functionName", "oldName", "newName", mutationService::renameVariable),
            new Ep.Post2("/rename_function_by_address", "function_address", "new_name", mutationService::renameFunctionByAddress),
            new Ep.Post2("/rename_or_label", "address", "name", mutationService::renameOrLabel),
            new Ep.Get1("/can_rename_at_address", "address", mutationService::canRenameAtAddress),
            new Ep.Json1("/delete_function", "address", mutationService::deleteFunctionAtAddress),
            new Ep.JsonPost("/create_function", p ->
                mutationService.createFunctionAtAddress(getStr(p, "address"), getStr(p, "name"),
                    getBool(p, "disassemble_first", true))),
            new Ep.JsonPost("/create_memory_block", p -> {
                long size = p.get("size") != null ? ((Number) p.get("size")).longValue() : 0;
                return mutationService.createMemoryBlock(getStr(p, "name"), getStr(p, "address"), size,
                    getBool(p, "read", true), getBool(p, "write", true), getBool(p, "execute", false),
                    getBool(p, "volatile", false), getStr(p, "comment"));
            }),
            new Ep.Get0("/save_program", mutationService::saveCurrentProgram),

            // --- Search ---
            new Ep.GetPage1("/search_functions", "query", symbolService::searchFunctions),
            new Ep.GetQuery("/search_functions_enhanced", q -> {
                String minX = getStr(q, "min_xrefs");
                String maxX = getStr(q, "max_xrefs");
                String hcn = getStr(q, "has_custom_name");
                Integer minXrefs = minX != null ? Integer.parseInt(minX) : null;
                Integer maxXrefs = maxX != null ? Integer.parseInt(maxX) : null;
                Boolean hasCustomName = hcn != null ? Boolean.parseBoolean(hcn) : null;
                return symbolService.searchFunctionsEnhanced(getStr(q, "name_pattern"), minXrefs, maxXrefs,
                    getStr(q, "calling_convention"), hasCustomName, getBool(q, "regex", false),
                    getStr(q, "sort_by") != null ? getStr(q, "sort_by") : "address",
                    getInt(q, "offset", 0), getInt(q, "limit", 100), getStr(q, "program"));
            }),

            // --- Function info ---
            new Ep.Get2("/get_function_by_address", "address", "program", functionService::getFunctionByAddress),
            new Ep.Get3("/decompile_function", "address", "name", "program", functionService::decompileFunction),
            new Ep.Get2("/disassemble_function", "address", "program", functionService::disassembleFunction),
            new Ep.Post3("/force_decompile", "function_address", "name", "program", functionService::forceDecompile),
            new Ep.Get2("/get_function_variables", "function_name", "program", functionService::getFunctionVariables),
            new Ep.GetQuery("/analyze_function_complete", q ->
                functionService.analyzeFunctionComplete(getStr(q, "name"),
                    !"false".equalsIgnoreCase(getStr(q, "include_xrefs")),
                    !"false".equalsIgnoreCase(getStr(q, "include_callees")),
                    !"false".equalsIgnoreCase(getStr(q, "include_callers")),
                    !"false".equalsIgnoreCase(getStr(q, "include_disasm")),
                    !"false".equalsIgnoreCase(getStr(q, "include_variables")),
                    getStr(q, "program"))),
            new Ep.GetQuery("/find_next_undefined_function", q ->
                functionService.findNextUndefinedFunction(getStr(q, "start_address"), getStr(q, "criteria"),
                    getStr(q, "pattern"), getStr(q, "direction"), getStr(q, "program"))),
            new Ep.GetPage1("/get_function_callees", "name", functionService::getFunctionCallees),
            new Ep.GetPage1("/get_function_callers", "name", functionService::getFunctionCallers),

            // --- Prototype / types ---
            new Ep.Json3("/set_function_prototype", "function_address", "prototype", "calling_convention", mutationService::setFunctionPrototype),
            new Ep.Get0("/list_calling_conventions", () -> symbolService.listCallingConventions(null)),
            new Ep.Post3("/set_local_variable_type", "function_address", "variable_name", "new_type", mutationService::setLocalVariableType),

            // --- Comments ---
            new Ep.Post2("/set_decompiler_comment", "address", "comment", commentService::setDecompilerComment),
            new Ep.Post2("/set_disassembly_comment", "address", "comment", commentService::setDisassemblyComment),
            new Ep.Post2("/set_plate_comment", "function_address", "comment", commentService::setPlateComment),
            new Ep.JsonPost("/batch_set_comments", p ->
                commentService.batchSetComments(getStr(p, "function_address"),
                    convertToMapList(p.get("decompiler_comments")), convertToMapList(p.get("disassembly_comments")),
                    getStr(p, "plate_comment"))),
            new Ep.JsonPost("/clear_function_comments", p ->
                commentService.clearFunctionComments(getStr(p, "function_address"),
                    getBool(p, "clear_plate", true), getBool(p, "clear_pre", true), getBool(p, "clear_eol", true))),

            // --- Cross-references ---
            new Ep.GetPage1("/get_xrefs_to", "address", symbolService::getXrefsTo),
            new Ep.GetPage1("/get_xrefs_from", "address", symbolService::getXrefsFrom),
            new Ep.GetPage1("/get_function_xrefs", "name", symbolService::getFunctionXrefs),
            new Ep.JsonPost("/get_bulk_xrefs", p -> {
                Object addressesObj = p.get("addresses");
                List<String> addresses = new ArrayList<>();
                if (addressesObj instanceof List) {
                    for (Object addr : (List<?>) addressesObj) {
                        if (addr != null) addresses.add(addr.toString());
                    }
                } else if (addressesObj instanceof String) {
                    for (String part : ((String) addressesObj).split(",")) {
                        addresses.add(part.trim());
                    }
                }
                return symbolService.getBulkXrefs(addresses, null);
            }),

            // --- Labels / Symbols ---
            new Ep.GetPage1NP("/get_function_labels", "name", symbolService::getFunctionLabels),
            new Ep.GetPage1NP("/get_function_jump_targets", "name", symbolService::getFunctionJumpTargets),
            new Ep.Post3("/rename_label", "address", "old_name", "new_name", symbolService::renameLabel),
            new Ep.Post2("/create_label", "address", "name", symbolService::createLabel),
            new Ep.Post2("/delete_label", "address", "name", symbolService::deleteLabel),
            new Ep.JsonPost("/batch_create_labels", p -> symbolService.batchCreateLabels(convertToMapList(p.get("labels")))),
            new Ep.JsonPost("/batch_delete_labels", p -> symbolService.batchDeleteLabels(convertToMapList(p.get("labels")))),
            new Ep.GetPage("/list_external_locations", symbolService::listExternalLocations),
            new Ep.Get3("/get_external_location", "address", "dll_name", "program", symbolService::getExternalLocationDetails),
            new Ep.Post2("/rename_external_location", "address", "new_name", symbolService::renameExternalLocation),
            new Ep.GetPage1R("/list_globals", "filter", symbolService::listGlobals),
            new Ep.Post2("/rename_global_variable", "old_name", "new_name", symbolService::renameGlobalVariable),
            new Ep.Get0("/get_entry_points", () -> symbolService.getEntryPoints(null)),

            // --- Data types ---
            new Ep.GetPage1R("/list_data_types", "category", listingService::listDataTypes),
            new Ep.GetPage1R("/list_strings", "filter", listingService::listStrings),
            new Ep.JsonPost("/create_struct", p ->
                dataTypeService.createStruct(getStr(p, "name"), coerceToJsonString(p.get("fields")))),
            new Ep.JsonPost("/create_enum", p ->
                dataTypeService.createEnum(getStr(p, "name"), coerceToJsonString(p.get("values")), getInt(p, "size", 4))),
            new Ep.JsonPost("/apply_data_type", p ->
                dataTypeService.applyDataType(getStr(p, "address"), getStr(p, "type_name"), getBool(p, "clear_existing", true))),
            new Ep.JsonPost("/create_union", p ->
                dataTypeService.createUnion(getStr(p, "name"), coerceToJsonString(p.get("fields")))),
            new Ep.Get1("/get_type_size", "type_name", dataTypeService::getTypeSize),
            new Ep.Get1("/get_struct_layout", "struct_name", dataTypeService::getStructLayout),
            new Ep.GetPage1NP("/search_data_types", "pattern", dataTypeService::searchDataTypes),
            new Ep.Get1("/get_enum_values", "enum_name", dataTypeService::getEnumValues),
            new Ep.Json2("/create_typedef", "name", "base_type", dataTypeService::createTypedef),
            new Ep.Json2("/clone_data_type", "source_type", "new_name", dataTypeService::cloneDataType),
            new Ep.Json2("/import_data_types", "source", "format", dataTypeService::importDataTypes),
            new Ep.Json1("/delete_data_type", "type_name", dataTypeService::deleteDataType),
            new Ep.Json4("/modify_struct_field", "struct_name", "field_name", "new_type", "new_name", dataTypeService::modifyStructField),
            new Ep.JsonPost("/add_struct_field", p ->
                dataTypeService.addStructField(getStr(p, "struct_name"), getStr(p, "field_name"),
                    getStr(p, "field_type"), getInt(p, "offset", -1))),
            new Ep.Post2("/remove_struct_field", "struct_name", "field_name", dataTypeService::removeStructField),
            new Ep.JsonPost("/create_array_type", p ->
                dataTypeService.createArrayType(getStr(p, "base_type"), getInt(p, "length", 1), getStr(p, "name"))),
            new Ep.Post2("/create_pointer_type", "base_type", "name", dataTypeService::createPointerType),
            new Ep.Post1("/create_data_type_category", "category_path", dataTypeService::createDataTypeCategory),
            new Ep.Post2("/move_data_type_to_category", "type_name", "category_path", dataTypeService::moveDataTypeToCategory),
            new Ep.GetPageNP("/list_data_type_categories", dataTypeService::listDataTypeCategories),
            new Ep.Get1("/get_valid_data_types", "category", dataTypeService::getValidDataTypes),
            new Ep.Get2("/validate_data_type", "address", "type_name", dataTypeService::validateDataType),
            new Ep.Get1("/get_data_type_size", "type_name", dataTypeService::getDataTypeSize),
            new Ep.Get3("/validate_function_prototype", "function_address", "prototype", "calling_convention", dataTypeService::validateFunctionPrototype),
            new Ep.Get1("/validate_data_type_exists", "type_name", dataTypeService::validateDataTypeExists),
            new Ep.JsonPost("/create_function_signature", p ->
                dataTypeService.createFunctionSignature(getStr(p, "name"), getStr(p, "return_type"),
                    coerceToJsonString(p.get("parameters")))),

            // --- Metadata ---
            new Ep.Get0("/check_connection", listingService::checkConnection),
            new Ep.Get0("/get_version", listingService::getVersion),
            new Ep.Get0("/get_metadata", listingService::getMetadata),
            new Ep.GetQuery("/convert_number", q -> listingService.convertNumber(getStr(q, "text"), getInt(q, "size", 4))),
            new Ep.GetQuery("/get_function_count", q -> listingService.getFunctionCount(getStr(q, "program"))),
            new Ep.GetQuery("/search_strings", q ->
                listingService.searchStrings(getStr(q, "query"), getInt(q, "min_length", 4),
                    getStr(q, "encoding"), getInt(q, "offset", 0), getInt(q, "limit", 100), getStr(q, "program"))),

            // --- Analysis ---
            new Ep.GetQuery("/read_memory", q ->
                analysisService.readMemory(getStr(q, "address"), getInt(q, "length", 16), getStr(q, "program"))),
            new Ep.GetQuery("/inspect_memory_content", q ->
                analysisService.inspectMemoryContent(getStr(q, "address"), getInt(q, "length", 64), getBool(q, "detect_strings", true))),
            new Ep.JsonPost("/analyze_data_region", p ->
                analysisService.analyzeDataRegion(getStr(p, "address"), getInt(p, "max_scan_bytes", 1024),
                    getBool(p, "include_xref_map", true), getBool(p, "include_assembly_patterns", true),
                    getBool(p, "include_boundary_detection", true))),
            new Ep.JsonPost("/detect_array_bounds", p ->
                analysisService.detectArrayBounds(getStr(p, "address"), getBool(p, "analyze_loop_bounds", true),
                    getBool(p, "analyze_indexing", true), getInt(p, "max_scan_range", 2048))),
            new Ep.JsonPost("/get_assembly_context", p ->
                analysisService.getAssemblyContext(objectToCommaSeparated(p.get("xref_sources")),
                    getInt(p, "context_instructions", 5), objectToCommaSeparated(p.get("include_patterns")))),
            new Ep.JsonPost("/apply_data_classification", p ->
                analysisService.applyDataClassification(getStr(p, "address"), getStr(p, "classification"), getStr(p, "name"),
                    getStr(p, "comment"), p.get("type_definition"))),
            new Ep.JsonPost("/analyze_struct_field_usage", p ->
                analysisService.analyzeStructFieldUsage(getStr(p, "address"), getStr(p, "struct_name"), getInt(p, "max_functions", 10))),
            new Ep.JsonPost("/get_field_access_context", p ->
                analysisService.getFieldAccessContext(getStr(p, "struct_address"), getInt(p, "field_offset", 0), getInt(p, "num_examples", 5))),
            new Ep.JsonPost("/suggest_field_names", p ->
                analysisService.suggestFieldNames(getStr(p, "struct_address"), getInt(p, "struct_size", 0))),
            new Ep.Get0("/detect_crypto_constants", analysisService::detectCryptoConstants),
            new Ep.GetQuery("/list_analyzers", q -> analysisService.listAnalyzers(getStr(q, "program"))),
            new Ep.Post1("/run_analysis", "program", analysisService::runAnalysis),
            new Ep.Get2("/search_byte_patterns", "pattern", "mask", analysisService::searchBytePatterns),
            new Ep.GetQuery("/find_similar_functions", q ->
                analysisService.findSimilarFunctions(getStr(q, "target_function"), getDouble(q, "threshold", 0.8))),
            new Ep.Get1("/analyze_control_flow", "function_name", analysisService::analyzeControlFlow),
            new Ep.Get0("/find_anti_analysis_techniques", analysisService::findAntiAnalysisTechniques),
            new Ep.Get1("/batch_decompile", "functions", analysisService::batchDecompileFunctions),
            new Ep.Get1("/find_dead_code", "function_name", analysisService::findDeadCode),
            new Ep.Get0("/decrypt_strings_auto", analysisService::autoDecryptStrings),
            new Ep.Get0("/analyze_api_call_chains", analysisService::analyzeAPICallChains),
            new Ep.Get0("/extract_iocs_with_context", analysisService::extractIOCsWithContext),
            new Ep.Get0("/detect_malware_behaviors", analysisService::detectMalwareBehaviors),
            new Ep.JsonPost("/disassemble_bytes", p -> {
                Integer length = p.get("length") != null ? ((Number) p.get("length")).intValue() : null;
                return analysisService.disassembleBytes(getStr(p, "start_address"), getStr(p, "end_address"), length, getBool(p, "restrict_to_execute_memory", true));
            }),

            // --- Bookmarks ---
            new Ep.Json3("/set_bookmark", "address", "category", "comment", symbolService::setBookmark),
            new Ep.Get2("/list_bookmarks", "category", "address", symbolService::listBookmarks),
            new Ep.Json2("/delete_bookmark", "address", "category", symbolService::deleteBookmark),

            // --- Batch rename variables ---
            new Ep.JsonPost("/batch_rename_variables", p -> {
                @SuppressWarnings("unchecked")
                Map<String, String> variableRenames = p.get("variable_renames") instanceof Map
                    ? (Map<String, String>) p.get("variable_renames") : new HashMap<>();
                return mutationService.batchRenameVariables(getStr(p, "function_address"), variableRenames);
            }),

            // --- Comparison ---
            new Ep.Get2("/get_function_hash", "address", "program", comparisonService::getFunctionHash),
            new Ep.GetPage1R("/get_bulk_function_hashes", "filter", comparisonService::getBulkFunctionHashes),
            new Ep.Get1("/get_function_documentation", "address", comparisonService::getFunctionDocumentation),
            new Ep.Get0("/compare_programs_documentation", comparisonService::compareProgramsDocumentation),
            new Ep.Get2("/find_undocumented_by_string", "address", "program", comparisonService::findUndocumentedByString),
            new Ep.Get2("/batch_string_anchor_report", "pattern", "program", comparisonService::batchStringAnchorReport),
            new Ep.Get2("/get_function_signature", "address", "program", comparisonService::getFunctionSignature),
            new Ep.GetQuery("/find_similar_functions_fuzzy", q ->
                comparisonService.findSimilarFunctionsFuzzy(getStr(q, "address"), getStr(q, "source_program"),
                    getStr(q, "target_program"), getDouble(q, "threshold", 0.7), getInt(q, "limit", 20))),
            new Ep.GetQuery("/bulk_fuzzy_match", q ->
                comparisonService.bulkFuzzyMatch(getStr(q, "source_program"), getStr(q, "target_program"),
                    getDouble(q, "threshold", 0.7), getInt(q, "offset", 0), getInt(q, "limit", 50), getStr(q, "filter"))),
            new Ep.Get4("/diff_functions", "address_a", "address_b", "program_a", "program_b", comparisonService::diffFunctions)
        );
    }
}
