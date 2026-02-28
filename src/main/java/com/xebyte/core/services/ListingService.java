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
package com.xebyte.core.services;

import com.google.gson.JsonObject;
import com.xebyte.core.ProgramProvider;
import com.xebyte.core.Response;
import com.xebyte.core.ThreadingStrategy;
import com.xebyte.VersionInfo;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;

import java.util.*;
import java.util.regex.Pattern;

/**
 * Shared service for read-only listing endpoints.
 *
 * Contains the business logic for list_methods, list_functions, list_classes,
 * list_segments, list_imports, list_exports, list_namespaces, list_data_items,
 * list_strings, and list_data_types.
 */
public class ListingService extends BaseService {

    public ListingService(ProgramProvider programProvider, ThreadingStrategy threadingStrategy) {
        super(programProvider, threadingStrategy);
    }

    /**
     * List all function names (paginated).
     * Endpoint: /list_methods
     */
    public Response listMethods(int offset, int limit, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        List<String> names = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            names.add(f.getName());
        }
        return paginateList(names, offset, limit);
    }

    /**
     * List all functions with name and address (paginated).
     * Endpoint: /list_functions
     */
    public Response listFunctions(int offset, int limit, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        List<String> lines = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            lines.add(f.getName() + " @ " + f.getEntryPoint().toString());
        }
        return paginateList(lines, offset, limit);
    }

    /**
     * List all class/namespace names (paginated).
     * Endpoint: /list_classes
     */
    public Response listClasses(int offset, int limit, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        Set<String> classNames = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !ns.isGlobal()) {
                classNames.add(ns.getName());
            }
        }
        List<String> sorted = new ArrayList<>(classNames);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    /**
     * List memory segments/blocks (paginated).
     * Endpoint: /list_segments
     */
    public Response listSegments(int offset, int limit, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            lines.add(String.format("%s: %s - %s", block.getName(), block.getStart(), block.getEnd()));
        }
        return paginateList(lines, offset, limit);
    }

    /**
     * List imported symbols (paginated).
     * Endpoint: /list_imports
     */
    public Response listImports(int offset, int limit, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        List<String> lines = new ArrayList<>();
        for (Symbol symbol : program.getSymbolTable().getExternalSymbols()) {
            lines.add(symbol.getName() + " -> " + symbol.getAddress());
        }
        return paginateList(lines, offset, limit);
    }

    /**
     * List exported entry point symbols (paginated).
     * Endpoint: /list_exports
     */
    public Response listExports(int offset, int limit, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        SymbolTable table = program.getSymbolTable();
        List<String> lines = new ArrayList<>();
        SymbolIterator iter = table.getAllSymbols(true);
        while (iter.hasNext()) {
            Symbol symbol = iter.next();
            if (symbol.isExternalEntryPoint()) {
                lines.add(symbol.getName() + " @ " + symbol.getAddress());
            }
        }
        return paginateList(lines, offset, limit);
    }

    /**
     * List all namespaces (paginated, full paths).
     * Endpoint: /list_namespaces
     */
    public Response listNamespaces(int offset, int limit, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        Set<String> namespaces = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            while (ns != null && !ns.isGlobal()) {
                namespaces.add(ns.getName(true));
                ns = ns.getParentNamespace();
            }
        }
        List<String> sorted = new ArrayList<>(namespaces);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    /**
     * List defined data items (paginated).
     * Endpoint: /list_data_items
     */
    public Response listDataItems(int offset, int limit, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        List<String> lines = new ArrayList<>();
        Listing listing = program.getListing();
        DataIterator dataIterator = listing.getDefinedData(true);
        int count = 0;
        int skipped = 0;

        while (dataIterator.hasNext() && count < limit) {
            Data data = dataIterator.next();
            if (skipped < offset) {
                skipped++;
                continue;
            }

            String name = data.getLabel();
            if (name == null || name.isEmpty()) {
                name = "DAT_" + data.getAddress().toString();
            }
            String type = data.getDataType().getName();
            lines.add(name + " @ " + data.getAddress() + " [" + type + "]");
            count++;
        }
        return Response.text(String.join("\n", lines));
    }

    /**
     * List defined strings with optional filter (paginated).
     * Endpoint: /list_strings
     */
    public Response listStrings(int offset, int limit, String filter, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        List<String> lines = new ArrayList<>();
        Listing listing = program.getListing();
        DataIterator dataIterator = listing.getDefinedData(true);

        while (dataIterator.hasNext()) {
            Data data = dataIterator.next();
            DataType dt = data.getDataType();

            if (dt instanceof StringDataType || dt instanceof TerminatedStringDataType ||
                dt instanceof UnicodeDataType || dt.getName().toLowerCase().contains("string")) {

                Object value = data.getValue();
                String strValue = value != null ? value.toString() : "";

                if (filter == null || filter.isEmpty() || strValue.contains(filter)) {
                    lines.add(data.getAddress() + ": \"" + strValue + "\"");
                }
            }
        }

        return paginateList(lines, offset, limit);
    }

    /**
     * List data types with optional category filter (paginated).
     * Endpoint: /list_data_types
     */
    public Response listDataTypes(int offset, int limit, String category, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        List<String> lines = new ArrayList<>();
        DataTypeManager dtm = program.getDataTypeManager();

        Iterator<DataType> dtIterator = dtm.getAllDataTypes();
        while (dtIterator.hasNext()) {
            DataType dt = dtIterator.next();
            String catPath = dt.getCategoryPath().toString();

            if (category == null || category.isEmpty() ||
                catPath.toLowerCase().contains(category.toLowerCase())) {
                lines.add(dt.getName() + " [" + dt.getLength() + " bytes] " + catPath);
            }
        }

        Collections.sort(lines);
        return paginateList(lines, offset, limit);
    }

    /**
     * List defined data items sorted by xref count (paginated).
     * Endpoint: /list_data_items_by_xrefs
     */
    public Response listDataItemsByXrefs(int offset, int limit, String format, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }
        if (format == null || format.isEmpty()) format = "text";

        List<DataItemInfo> dataItems = new ArrayList<>();
        ReferenceManager refMgr = program.getReferenceManager();

        for (MemoryBlock block : program.getMemory().getBlocks()) {
            DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
            while (it.hasNext()) {
                Data data = it.next();
                if (block.contains(data.getAddress())) {
                    ghidra.program.model.address.Address addr = data.getAddress();
                    int xrefCount = refMgr.getReferenceCountTo(addr);
                    String label = data.getLabel() != null ? data.getLabel() : "DAT_" + addr.toString().replace(":", "");
                    DataType dt = data.getDataType();
                    String typeName = (dt != null) ? dt.getName() : "undefined";
                    int length = data.getLength();
                    dataItems.add(new DataItemInfo(addr.toString().replace(":", ""), label, typeName, length, xrefCount));
                }
            }
        }

        dataItems.sort((a, b) -> Integer.compare(b.xrefCount, a.xrefCount));

        if ("json".equalsIgnoreCase(format)) {
            return formatDataItemsAsJson(dataItems, offset, limit);
        }
        return formatDataItemsAsText(dataItems, offset, limit);
    }

    private static final class DataItemInfo {
        final String address;
        final String label;
        final String typeName;
        final int length;
        final int xrefCount;

        DataItemInfo(String address, String label, String typeName, int length, int xrefCount) {
            this.address = address;
            this.label = label;
            this.typeName = typeName;
            this.length = length;
            this.xrefCount = xrefCount;
        }
    }

    private Response formatDataItemsAsText(List<DataItemInfo> dataItems, int offset, int limit) {
        List<String> lines = new ArrayList<>();
        int start = Math.min(offset, dataItems.size());
        int end = Math.min(start + limit, dataItems.size());
        for (int i = start; i < end; i++) {
            DataItemInfo item = dataItems.get(i);
            String sizeStr = (item.length == 1) ? "1 byte" : item.length + " bytes";
            lines.add(item.label + " @ " + item.address + " [" + item.typeName + "] (" + sizeStr + ") - " + item.xrefCount + " xrefs");
        }
        return Response.text(String.join("\n", lines));
    }

    private Response formatDataItemsAsJson(List<DataItemInfo> dataItems, int offset, int limit) {
        int start = Math.min(offset, dataItems.size());
        int end = Math.min(start + limit, dataItems.size());
        List<Object> items = new ArrayList<>();
        for (int i = start; i < end; i++) {
            DataItemInfo item = dataItems.get(i);
            String sizeStr = (item.length == 1) ? "1 byte" : item.length + " bytes";
            items.add(new LinkedHashMap<>(Map.of(
                "address", item.address,
                "name", item.label,
                "type", item.typeName,
                "size", sizeStr,
                "xref_count", item.xrefCount
            )));
        }
        return Response.ok(items);
    }

    /**
     * Get the total function count for a program.
     * Endpoint: /get_function_count
     */
    public Response getFunctionCount(String programName) {
        Program program = resolveProgram(programName);
        if (program == null) return programNotFoundError(programName);

        int count = program.getFunctionManager().getFunctionCount();
        return Response.ok(Map.of(
            "function_count", count,
            "program", program.getName()));
    }

    /**
     * Search defined strings by regex pattern (paginated).
     * Endpoint: /search_strings
     */
    public Response searchStrings(String query, int minLength, String encoding,
                                   int offset, int limit, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) return programNotFoundError(programName);
        if (query == null || query.isEmpty()) return Response.err("query parameter is required");

        Pattern pat;
        try {
            pat = Pattern.compile(query, Pattern.CASE_INSENSITIVE);
        } catch (Exception e) {
            return Response.err("Invalid regex: " + e.getMessage());
        }

        List<Map<String, String>> results = new ArrayList<>();
        DataIterator dataIt = program.getListing().getDefinedData(true);
        while (dataIt.hasNext()) {
            Data data = dataIt.next();
            if (data == null) continue;
            DataType dt = data.getDataType();
            if (!(dt instanceof StringDataType || dt instanceof TerminatedStringDataType ||
                  dt instanceof UnicodeDataType || dt.getName().toLowerCase().contains("string"))) continue;
            String value = data.getValue() != null ? data.getValue().toString() : "";
            if (value.length() < minLength) continue;
            if (!pat.matcher(value).find()) continue;
            String enc = (encoding != null && !encoding.isEmpty()) ? encoding : "ascii";
            results.add(Map.of("address", data.getAddress().toString(), "value", value, "encoding", enc));
        }

        int total = results.size();
        int from = Math.min(offset, total);
        int to = Math.min(from + limit, total);
        return Response.ok(Map.of(
            "matches", results.subList(from, to),
            "total", total,
            "offset", offset,
            "limit", limit));
    }

    // =========================================================================
    // UTILITY ENDPOINTS (moved from EndpointRouter)
    // =========================================================================

    /**
     * Check if the plugin is running and accessible.
     * Endpoint: /check_connection
     */
    public Response checkConnection() {
        Program program = resolveProgram(null);
        String programName = program != null ? program.getName() : null;
        boolean loaded = program != null;
        JsonObject jo = new JsonObject();
        jo.addProperty("connected", true);
        jo.addProperty("program_loaded", loaded);
        jo.addProperty("program_name", programName);
        return new Response.Ok(jo);
    }

    /**
     * Get version information about the plugin and Ghidra.
     * Endpoint: /get_version
     */
    public Response getVersion() {
        String pluginVersion = VersionInfo.getVersion();
        String pluginName = VersionInfo.getAppName();
        String buildTimestamp = VersionInfo.getBuildTimestamp();
        String buildNumber = VersionInfo.getBuildNumber();
        String fullVersion = VersionInfo.getFullVersion();
        String javaVersion = System.getProperty("java.version");
        int endpointCount = VersionInfo.getEndpointCount();
        JsonObject jo = new JsonObject();
        jo.addProperty("plugin_version", pluginVersion);
        jo.addProperty("plugin_name", pluginName);
        jo.addProperty("build_timestamp", buildTimestamp);
        jo.addProperty("build_number", buildNumber);
        jo.addProperty("full_version", fullVersion);
        jo.addProperty("ghidra_version", "12.0.2");
        jo.addProperty("java_version", javaVersion);
        jo.addProperty("endpoint_count", endpointCount);
        return new Response.Ok(jo);
    }

    /**
     * Get metadata about the current program.
     * Endpoint: /get_metadata
     */
    public Response getMetadata() {
        Program program = resolveProgram(null);
        if (program == null) {
            return Response.err("No program loaded");
        }

        long totalSize = 0;
        int blockCount = 0;
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            totalSize += block.getSize();
            blockCount++;
        }

        JsonObject jo = new JsonObject();
        jo.addProperty("program_name", program.getName());
        jo.addProperty("executable_path", program.getExecutablePath());
        jo.addProperty("arch", program.getLanguage().getProcessor().toString());
        jo.addProperty("comp", program.getCompilerSpec().getCompilerSpecID().toString());
        jo.addProperty("lang", program.getLanguage().getLanguageID().toString());
        jo.addProperty("endianness", program.getLanguage().isBigEndian() ? "Big" : "Little");
        jo.addProperty("address_size_bits", program.getAddressFactory().getDefaultAddressSpace().getSize());
        jo.addProperty("base_address", program.getImageBase().toString());
        jo.addProperty("memory_block_count", blockCount);
        jo.addProperty("total_memory_size_bytes", totalSize);
        jo.addProperty("function_count", program.getFunctionManager().getFunctionCount());
        jo.addProperty("symbol_count", program.getSymbolTable().getNumSymbols());
        return new Response.Ok(jo);
    }

    /**
     * Convert a number to different representations.
     * Endpoint: /convert_number
     */
    public Response convertNumber(String text, int size) {
        if (text == null || text.isEmpty()) {
            return Response.err("No number provided");
        }

        try {
            long value;
            String inputType;

            if (text.startsWith("0x") || text.startsWith("0X")) {
                value = Long.parseUnsignedLong(text.substring(2), 16);
                inputType = "hexadecimal";
            } else if (text.startsWith("0b") || text.startsWith("0B")) {
                value = Long.parseUnsignedLong(text.substring(2), 2);
                inputType = "binary";
            } else if (text.startsWith("0") && text.length() > 1 && text.matches("0[0-7]+")) {
                value = Long.parseUnsignedLong(text, 8);
                inputType = "octal";
            } else {
                value = Long.parseUnsignedLong(text);
                inputType = "decimal";
            }

            long mask = (size == 8) ? -1L : (1L << (size * 8)) - 1L;
            long maskedValue = value & mask;

            Long decimalSigned = null;
            if (size <= 8) {
                long signedValue = maskedValue;
                if (size < 8) {
                    long signBit = 1L << (size * 8 - 1);
                    if ((maskedValue & signBit) != 0) {
                        signedValue = maskedValue | (~mask);
                    }
                }
                decimalSigned = signedValue;
            }

            JsonObject jo = new JsonObject();
            jo.addProperty("input", text);
            jo.addProperty("input_type", inputType);
            jo.addProperty("size_bytes", size);
            jo.addProperty("decimal_unsigned", Long.toUnsignedString(maskedValue));
            jo.addProperty("decimal_signed", decimalSigned);
            jo.addProperty("hexadecimal", "0x" + Long.toHexString(maskedValue).toUpperCase());
            jo.addProperty("binary", "0b" + Long.toBinaryString(maskedValue));
            jo.addProperty("octal", "0" + Long.toOctalString(maskedValue));
            jo.addProperty("hex_padded", "0x" + String.format(String.format("%%0%dX", size * 2), maskedValue));
            return new Response.Ok(jo);

        } catch (NumberFormatException e) {
            return Response.err("Invalid number format: " + text);
        } catch (Exception e) {
            return Response.err("Error converting number: " + e.getMessage());
        }
    }

    /**
     * List all functions with enhanced metadata including thunk/external flags.
     * Endpoint: /list_functions_enhanced
     */
    public Response listFunctionsEnhanced(int offset, int limit, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        var functions = new ArrayList<>();
        int skipped = 0;
        int count = 0;

        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (skipped < offset) {
                skipped++;
                continue;
            }
            if (count >= limit) break;

            JsonObject jo = new JsonObject();
            jo.addProperty("name", func.getName());
            jo.addProperty("address", func.getEntryPoint().toString());
            jo.addProperty("isThunk", func.isThunk());
            jo.addProperty("isExternal", func.isExternal());
            functions.add(jo);
            count++;
        }

        var result = new LinkedHashMap<String, Object>();
        result.put("functions", functions);
        result.put("count", count);
        result.put("offset", offset);
        result.put("limit", limit);
        return Response.ok(result);
    }
}
