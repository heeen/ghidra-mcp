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

import com.xebyte.core.ProgramProvider;
import com.xebyte.core.ThreadingStrategy;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

import java.util.*;

/**
 * Shared service for cross-references, labels, symbol search, and global variables.
 *
 * Handles xref lookups, label CRUD, function search (simple and enhanced),
 * global variable listing/renaming, entry points, and calling conventions.
 */
public class SymbolService extends BaseService {

    public SymbolService(ProgramProvider programProvider, ThreadingStrategy threadingStrategy) {
        super(programProvider, threadingStrategy);
    }

    // =========================================================================
    // XREF ENDPOINTS
    // =========================================================================

    /**
     * Get cross-references TO an address (paginated).
     * Endpoint: /get_xrefs_to
     */
    public String getXrefsTo(String addressStr, int offset, int limit, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        Address addr = parseAddress(program, addressStr);
        if (addr == null) {
            return "{\"error\": \"Invalid address: " + addressStr + "\"}";
        }

        List<String> lines = new ArrayList<>();
        ReferenceManager refMgr = program.getReferenceManager();
        ReferenceIterator refs = refMgr.getReferencesTo(addr);

        int count = 0;
        int skipped = 0;
        while (refs.hasNext() && count < limit) {
            Reference ref = refs.next();
            if (skipped < offset) {
                skipped++;
                continue;
            }
            lines.add(ref.getFromAddress() + " -> " + addr + " [" + ref.getReferenceType() + "]");
            count++;
        }

        return String.join("\n", lines);
    }

    /**
     * Get cross-references FROM an address (paginated).
     * Endpoint: /get_xrefs_from
     */
    public String getXrefsFrom(String addressStr, int offset, int limit, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        Address addr = parseAddress(program, addressStr);
        if (addr == null) {
            return "{\"error\": \"Invalid address: " + addressStr + "\"}";
        }

        List<String> lines = new ArrayList<>();
        ReferenceManager refMgr = program.getReferenceManager();
        Reference[] refs = refMgr.getReferencesFrom(addr);

        int end = Math.min(refs.length, offset + limit);
        for (int i = offset; i < end; i++) {
            Reference ref = refs[i];
            lines.add(addr + " -> " + ref.getToAddress() + " [" + ref.getReferenceType() + "]");
        }

        return String.join("\n", lines);
    }

    /**
     * Get cross-references to a function by name (paginated).
     * Endpoint: /get_function_xrefs
     */
    public String getFunctionXrefs(String functionName, int offset, int limit, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        Function func = null;
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(functionName)) {
                func = f;
                break;
            }
        }

        if (func == null) {
            return "{\"error\": \"Function not found: " + functionName + "\"}";
        }

        return getXrefsTo(func.getEntryPoint().toString(), offset, limit, programName);
    }

    /**
     * Get cross-references for multiple addresses in bulk.
     * Endpoint: /get_bulk_xrefs
     *
     * @param addresses List of address strings
     */
    public String getBulkXrefs(List<String> addresses, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        if (addresses == null || addresses.isEmpty()) {
            return "{\"error\": \"No valid addresses in input\"}";
        }

        ReferenceManager refMgr = program.getReferenceManager();
        StringBuilder sb = new StringBuilder();
        sb.append("{");

        boolean first = true;
        for (String addrStr : addresses) {
            Address addr = parseAddress(program, addrStr);
            if (addr == null) continue;

            if (!first) sb.append(", ");
            sb.append("\"").append(addrStr).append("\": [");

            int count = 0;
            for (Reference ref : refMgr.getReferencesTo(addr)) {
                if (count > 0) sb.append(", ");
                sb.append("{\"from\": \"").append(ref.getFromAddress()).append("\"");
                sb.append(", \"type\": \"").append(ref.getReferenceType()).append("\"}");
                if (++count >= 20) break;
            }
            sb.append("]");
            first = false;
        }

        sb.append("}");
        return sb.toString();
    }

    // =========================================================================
    // LABEL ENDPOINTS
    // =========================================================================

    /**
     * Create multiple labels in a single batch operation.
     * Endpoint: /batch_create_labels
     *
     * @param labels List of {address, name} maps
     */
    public String batchCreateLabels(List<Map<String, String>> labels) {
        Program program = resolveProgram(null);
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
        }

        if (labels == null || labels.isEmpty()) {
            return "{\"error\": \"Labels list is required\"}";
        }

        try {
            return threadingStrategy.executeWrite(program, "Batch create labels", () -> {
                SymbolTable symbolTable = program.getSymbolTable();

                int created = 0;
                int failed = 0;
                List<String> errors = new ArrayList<>();

                for (Map<String, String> label : labels) {
                    String addrStr = label.get("address");
                    String name = label.get("name");

                    if (addrStr == null || name == null) {
                        errors.add("Missing address or name in label entry");
                        failed++;
                        continue;
                    }

                    Address addr = parseAddress(program, addrStr);
                    if (addr == null) {
                        errors.add("Invalid address: " + addrStr);
                        failed++;
                        continue;
                    }

                    try {
                        symbolTable.createLabel(addr, name, SourceType.USER_DEFINED);
                        created++;
                    } catch (Exception e) {
                        errors.add(addrStr + ": " + e.getMessage());
                        failed++;
                    }
                }

                StringBuilder sb = new StringBuilder();
                sb.append("{\"success\": ").append(failed == 0).append(", ");
                sb.append("\"labels_created\": ").append(created).append(", ");
                sb.append("\"labels_failed\": ").append(failed);

                if (!errors.isEmpty()) {
                    sb.append(", \"errors\": [");
                    for (int i = 0; i < Math.min(errors.size(), 10); i++) {
                        if (i > 0) sb.append(", ");
                        sb.append("\"").append(escapeJson(errors.get(i))).append("\"");
                    }
                    sb.append("]");
                }
                sb.append("}");
                return sb.toString();
            });
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Delete a label at the specified address.
     * Endpoint: /delete_label
     *
     * @param addressStr Memory address
     * @param labelName Optional specific label name; if null, deletes all labels at address
     */
    public String deleteLabel(String addressStr, String labelName) {
        Program program = resolveProgram(null);
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
        }

        if (addressStr == null || addressStr.isEmpty()) {
            return "{\"error\": \"Address is required\"}";
        }

        try {
            return threadingStrategy.executeWrite(program, "Delete label", () -> {
                Address address = parseAddress(program, addressStr);
                if (address == null) {
                    return "{\"error\": \"Invalid address: " + addressStr + "\"}";
                }

                SymbolTable symbolTable = program.getSymbolTable();
                Symbol[] symbols = symbolTable.getSymbols(address);

                if (symbols == null || symbols.length == 0) {
                    return "{\"success\": false, \"message\": \"No symbols found at address " + addressStr + "\"}";
                }

                int deletedCount = 0;
                List<String> deletedNames = new ArrayList<>();
                List<String> errors = new ArrayList<>();

                for (Symbol symbol : symbols) {
                    if (symbol.getSymbolType() != SymbolType.LABEL) {
                        continue;
                    }

                    if (labelName != null && !labelName.isEmpty()) {
                        if (!symbol.getName().equals(labelName)) {
                            continue;
                        }
                    }

                    String name = symbol.getName();
                    boolean deleted = symbol.delete();
                    if (deleted) {
                        deletedCount++;
                        deletedNames.add(name);
                    } else {
                        errors.add("Failed to delete label: " + name);
                    }
                }

                StringBuilder result = new StringBuilder();
                result.append("{\"success\": ").append(deletedCount > 0);
                result.append(", \"deleted_count\": ").append(deletedCount);
                result.append(", \"deleted_names\": [");
                for (int i = 0; i < deletedNames.size(); i++) {
                    if (i > 0) result.append(", ");
                    result.append("\"").append(escapeJson(deletedNames.get(i))).append("\"");
                }
                result.append("]");
                if (!errors.isEmpty()) {
                    result.append(", \"errors\": [");
                    for (int i = 0; i < errors.size(); i++) {
                        if (i > 0) result.append(", ");
                        result.append("\"").append(escapeJson(errors.get(i))).append("\"");
                    }
                    result.append("]");
                }
                result.append("}");
                return result.toString();
            });
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Batch delete multiple labels in a single transaction.
     * Endpoint: /batch_delete_labels
     *
     * @param labels List of {address, name} maps (name is optional)
     */
    public String batchDeleteLabels(List<Map<String, String>> labels) {
        Program program = resolveProgram(null);
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
        }

        if (labels == null || labels.isEmpty()) {
            return "{\"error\": \"Labels list is required\"}";
        }

        try {
            return threadingStrategy.executeWrite(program, "Batch delete labels", () -> {
                SymbolTable symbolTable = program.getSymbolTable();

                int deleted = 0;
                int skipped = 0;
                int failed = 0;
                List<String> errors = new ArrayList<>();

                for (Map<String, String> label : labels) {
                    String addrStr = label.get("address");
                    String name = label.get("name");

                    if (addrStr == null) {
                        errors.add("Missing address in label entry");
                        failed++;
                        continue;
                    }

                    Address addr = parseAddress(program, addrStr);
                    if (addr == null) {
                        errors.add("Invalid address: " + addrStr);
                        failed++;
                        continue;
                    }

                    Symbol[] symbols = symbolTable.getSymbols(addr);
                    if (symbols == null || symbols.length == 0) {
                        skipped++;
                        continue;
                    }

                    for (Symbol symbol : symbols) {
                        if (symbol.getSymbolType() != SymbolType.LABEL) {
                            continue;
                        }

                        if (name != null && !name.isEmpty()) {
                            if (!symbol.getName().equals(name)) {
                                continue;
                            }
                        }

                        try {
                            if (symbol.delete()) {
                                deleted++;
                            } else {
                                errors.add("Failed to delete at " + addrStr);
                                failed++;
                            }
                        } catch (Exception e) {
                            errors.add(addrStr + ": " + e.getMessage());
                            failed++;
                        }
                    }
                }

                StringBuilder sb = new StringBuilder();
                sb.append("{\"success\": true");
                sb.append(", \"labels_deleted\": ").append(deleted);
                sb.append(", \"labels_skipped\": ").append(skipped);
                sb.append(", \"errors_count\": ").append(failed);

                if (!errors.isEmpty()) {
                    sb.append(", \"errors\": [");
                    for (int i = 0; i < Math.min(errors.size(), 10); i++) {
                        if (i > 0) sb.append(", ");
                        sb.append("\"").append(escapeJson(errors.get(i))).append("\"");
                    }
                    sb.append("]");
                }
                sb.append("}");
                return sb.toString();
            });
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    // =========================================================================
    // SEARCH ENDPOINTS
    // =========================================================================

    /**
     * Simple function name search (paginated).
     * Endpoint: /search_functions
     */
    public String searchFunctions(String query, int offset, int limit, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        if (query == null || query.isEmpty()) {
            return "{\"error\": \"Query parameter required\"}";
        }

        List<String> matches = new ArrayList<>();
        String lowerQuery = query.toLowerCase();

        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.getName().toLowerCase().contains(lowerQuery)) {
                matches.add(f.getName() + " @ " + f.getEntryPoint());
            }
        }

        return paginateList(matches, offset, limit);
    }

    /**
     * Enhanced function search with multiple filter options.
     * Endpoint: /search_functions_enhanced
     */
    public String searchFunctionsEnhanced(String namePattern, Integer minXrefs, Integer maxXrefs,
                                          String callingConvention, Boolean hasCustomName,
                                          boolean regex, String sortBy,
                                          int offset, int limit, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        FunctionManager fm = program.getFunctionManager();
        ReferenceManager refMgr = program.getReferenceManager();
        List<FunctionSearchResult> results = new ArrayList<>();

        FunctionIterator funcIter = fm.getFunctions(true);
        while (funcIter.hasNext()) {
            Function func = funcIter.next();
            String name = func.getName();

            // Filter by name pattern
            if (namePattern != null && !namePattern.isEmpty()) {
                boolean matches;
                if (regex) {
                    try {
                        matches = name.matches(namePattern);
                    } catch (Exception e) {
                        matches = false;
                    }
                } else {
                    matches = name.toLowerCase().contains(namePattern.toLowerCase());
                }
                if (!matches) continue;
            }

            // Filter by calling convention
            if (callingConvention != null && !callingConvention.isEmpty()) {
                String cc = func.getCallingConventionName();
                if (!callingConvention.equalsIgnoreCase(cc)) continue;
            }

            // Filter by custom name
            if (hasCustomName != null) {
                boolean isCustom = !name.startsWith("FUN_");
                if (hasCustomName && !isCustom) continue;
                if (!hasCustomName && isCustom) continue;
            }

            // Count xrefs
            int xrefCount = 0;
            for (Reference ref : refMgr.getReferencesTo(func.getEntryPoint())) {
                xrefCount++;
            }

            // Filter by xref count
            if (minXrefs != null && xrefCount < minXrefs) continue;
            if (maxXrefs != null && xrefCount > maxXrefs) continue;

            results.add(new FunctionSearchResult(name, func.getEntryPoint().toString(), xrefCount));
        }

        // Sort results
        if ("xref_count".equalsIgnoreCase(sortBy)) {
            results.sort((a, b) -> Integer.compare(b.xrefCount, a.xrefCount));
        } else if ("name".equalsIgnoreCase(sortBy)) {
            results.sort((a, b) -> a.name.compareToIgnoreCase(b.name));
        } else {
            results.sort((a, b) -> a.address.compareTo(b.address));
        }

        // Build JSON response with pagination
        StringBuilder sb = new StringBuilder();
        sb.append("{\"total\": ").append(results.size());
        sb.append(", \"offset\": ").append(offset);
        sb.append(", \"limit\": ").append(limit);
        sb.append(", \"results\": [");

        int start = Math.max(0, offset);
        int end = Math.min(results.size(), start + limit);
        for (int i = start; i < end; i++) {
            if (i > start) sb.append(", ");
            FunctionSearchResult fi = results.get(i);
            sb.append("{\"name\": \"").append(escapeJson(fi.name)).append("\"");
            sb.append(", \"address\": \"").append(fi.address).append("\"");
            sb.append(", \"xref_count\": ").append(fi.xrefCount).append("}");
        }

        sb.append("]}");
        return sb.toString();
    }

    // =========================================================================
    // GLOBALS AND MISC
    // =========================================================================

    /**
     * List global variables with optional filtering (paginated).
     * Endpoint: /list_globals
     */
    public String listGlobals(int offset, int limit, String filter, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        SymbolTable symbolTable = program.getSymbolTable();
        List<String> results = new ArrayList<>();

        SymbolIterator symbols = symbolTable.getAllSymbols(true);
        while (symbols.hasNext()) {
            Symbol sym = symbols.next();
            if (sym.isGlobal() && !sym.getName().startsWith("FUN_") &&
                !sym.getName().startsWith("LAB_") && !sym.getName().startsWith("DAT_")) {

                String name = sym.getName();
                if (filter != null && !filter.isEmpty()) {
                    if (!name.toLowerCase().contains(filter.toLowerCase())) {
                        continue;
                    }
                }
                results.add(name + " @ " + sym.getAddress());
            }
        }

        return paginateList(results, offset, limit);
    }

    /**
     * Rename a global variable.
     * Endpoint: /rename_global_variable
     */
    public String renameGlobalVariable(String oldName, String newName) {
        Program program = resolveProgram(null);
        if (program == null) {
            return "Error: No program loaded";
        }

        if (oldName == null || oldName.isEmpty()) {
            return "Error: Old name is required";
        }
        if (newName == null || newName.isEmpty()) {
            return "Error: New name is required";
        }

        try {
            return threadingStrategy.executeWrite(program, "Rename global variable", () -> {
                SymbolTable symbolTable = program.getSymbolTable();
                List<Symbol> symbols = symbolTable.getGlobalSymbols(oldName);

                if (symbols.isEmpty()) {
                    return "Error: Global variable not found: " + oldName;
                }

                Symbol sym = symbols.get(0);
                sym.setName(newName, SourceType.USER_DEFINED);

                return "Success: Renamed " + oldName + " to " + newName;
            });
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Get program entry points.
     * Endpoint: /get_entry_points
     */
    public String getEntryPoints(String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        SymbolTable symbolTable = program.getSymbolTable();
        StringBuilder sb = new StringBuilder();
        sb.append("{\"entry_points\": [");

        ghidra.program.model.address.AddressIterator addresses = symbolTable.getExternalEntryPointIterator();
        boolean first = true;
        while (addresses.hasNext()) {
            Address addr = addresses.next();
            Symbol sym = symbolTable.getPrimarySymbol(addr);
            String name = (sym != null) ? sym.getName() : "entry_" + addr;
            if (!first) sb.append(", ");
            sb.append("{\"name\": \"").append(escapeJson(name)).append("\"");
            sb.append(", \"address\": \"").append(addr).append("\"}");
            first = false;
        }

        sb.append("]}");
        return sb.toString();
    }

    /**
     * List available calling conventions.
     * Endpoint: /list_calling_conventions
     */
    public String listCallingConventions(String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        FunctionManager fm = program.getFunctionManager();
        StringBuilder sb = new StringBuilder();
        sb.append("{\"calling_conventions\": [");

        Collection<String> conventions = fm.getCallingConventionNames();
        boolean first = true;
        for (String convention : conventions) {
            if (!first) sb.append(", ");
            sb.append("\"").append(escapeJson(convention)).append("\"");
            first = false;
        }

        sb.append("]}");
        return sb.toString();
    }

    // =========================================================================
    // Internal helper
    // =========================================================================

    private static class FunctionSearchResult {
        final String name;
        final String address;
        final int xrefCount;

        FunctionSearchResult(String name, String address, int xrefCount) {
            this.name = name;
            this.address = address;
            this.xrefCount = xrefCount;
        }
    }
}
