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
import com.xebyte.core.Response;
import com.xebyte.core.ThreadingStrategy;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
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
    public Response getXrefsTo(String addressStr, int offset, int limit, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        Address addr = parseAddress(program, addressStr);
        if (addr == null) {
            return Response.err("Invalid address: " + addressStr);
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

        return Response.text(String.join("\n", lines));
    }

    /**
     * Get cross-references FROM an address (paginated).
     * Endpoint: /get_xrefs_from
     */
    public Response getXrefsFrom(String addressStr, int offset, int limit, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        Address addr = parseAddress(program, addressStr);
        if (addr == null) {
            return Response.err("Invalid address: " + addressStr);
        }

        List<String> lines = new ArrayList<>();
        ReferenceManager refMgr = program.getReferenceManager();
        Reference[] refs = refMgr.getReferencesFrom(addr);

        int end = Math.min(refs.length, offset + limit);
        for (int i = offset; i < end; i++) {
            Reference ref = refs[i];
            lines.add(addr + " -> " + ref.getToAddress() + " [" + ref.getReferenceType() + "]");
        }

        return Response.text(String.join("\n", lines));
    }

    /**
     * Get cross-references to a function by name (paginated).
     * Endpoint: /get_function_xrefs
     */
    public Response getFunctionXrefs(String functionName, int offset, int limit, String programName) {
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
            return Response.err("Function not found: " + functionName);
        }

        return getXrefsTo(func.getEntryPoint().toString(), offset, limit, programName);
    }

    /**
     * Get cross-references for multiple addresses in bulk.
     * Endpoint: /get_bulk_xrefs
     *
     * @param addresses List of address strings
     */
    public Response getBulkXrefs(List<String> addresses, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        if (addresses == null || addresses.isEmpty()) {
            return Response.err("No valid addresses in input");
        }

        ReferenceManager refMgr = program.getReferenceManager();
        Map<String, List<Map<String, String>>> result = new LinkedHashMap<>();

        for (String addrStr : addresses) {
            Address addr = parseAddress(program, addrStr);
            if (addr == null) continue;

            List<Map<String, String>> refs = new ArrayList<>();
            int count = 0;
            for (Reference ref : refMgr.getReferencesTo(addr)) {
                Map<String, String> entry = new LinkedHashMap<>();
                entry.put("from", ref.getFromAddress().toString());
                entry.put("type", ref.getReferenceType().toString());
                refs.add(entry);
                if (++count >= 20) break;
            }
            result.put(addrStr, refs);
        }

        return Response.ok(result);
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
    public Response batchCreateLabels(List<Map<String, String>> labels) {
        Program program = resolveProgram(null);
        if (program == null) {
            return Response.err("No program loaded");
        }

        if (labels == null || labels.isEmpty()) {
            return Response.err("Labels list is required");
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

                Map<String, Object> result = new LinkedHashMap<>();
                result.put("success", failed == 0);
                result.put("labels_created", created);
                result.put("labels_failed", failed);
                if (!errors.isEmpty()) {
                    result.put("errors", errors.size() > 10 ? errors.subList(0, 10) : errors);
                }
                return Response.ok(result);
            });
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Delete a label at the specified address.
     * Endpoint: /delete_label
     *
     * @param addressStr Memory address
     * @param labelName Optional specific label name; if null, deletes all labels at address
     */
    public Response deleteLabel(String addressStr, String labelName) {
        Program program = resolveProgram(null);
        if (program == null) {
            return Response.err("No program loaded");
        }

        if (addressStr == null || addressStr.isEmpty()) {
            return Response.err("Address is required");
        }

        try {
            return threadingStrategy.executeWrite(program, "Delete label", () -> {
                Address address = parseAddress(program, addressStr);
                if (address == null) {
                    return Response.err("Invalid address: " + addressStr);
                }

                SymbolTable symbolTable = program.getSymbolTable();
                Symbol[] symbols = symbolTable.getSymbols(address);

                if (symbols == null || symbols.length == 0) {
                    Map<String, Object> noSymbols = new LinkedHashMap<>();
                    noSymbols.put("success", false);
                    noSymbols.put("message", "No symbols found at address " + addressStr);
                    return Response.ok(noSymbols);
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

                Map<String, Object> result = new LinkedHashMap<>();
                result.put("success", deletedCount > 0);
                result.put("deleted_count", deletedCount);
                result.put("deleted_names", deletedNames);
                if (!errors.isEmpty()) {
                    result.put("errors", errors);
                }
                return Response.ok(result);
            });
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Batch delete multiple labels in a single transaction.
     * Endpoint: /batch_delete_labels
     *
     * @param labels List of {address, name} maps (name is optional)
     */
    public Response batchDeleteLabels(List<Map<String, String>> labels) {
        Program program = resolveProgram(null);
        if (program == null) {
            return Response.err("No program loaded");
        }

        if (labels == null || labels.isEmpty()) {
            return Response.err("Labels list is required");
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

                Map<String, Object> result = new LinkedHashMap<>();
                result.put("success", true);
                result.put("labels_deleted", deleted);
                result.put("labels_skipped", skipped);
                result.put("errors_count", failed);
                if (!errors.isEmpty()) {
                    result.put("errors", errors.size() > 10 ? errors.subList(0, 10) : errors);
                }
                return Response.ok(result);
            });
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Create a new label at the specified address.
     * Endpoint: /create_label
     */
    public Response createLabel(String addressStr, String labelName) {
        Program program = resolveProgram(null);
        if (program == null) {
            return Response.err("No program loaded");
        }

        if (addressStr == null || addressStr.isEmpty()) {
            return Response.err("Address is required");
        }

        if (labelName == null || labelName.isEmpty()) {
            return Response.err("Label name is required");
        }

        try {
            return threadingStrategy.executeWrite(program, "Create Label", () -> {
                Address address = parseAddress(program, addressStr);
                if (address == null) {
                    return Response.err("Invalid address: " + addressStr);
                }

                SymbolTable symbolTable = program.getSymbolTable();

                // Check if a label with this name already exists at this address
                Symbol[] existingSymbols = symbolTable.getSymbols(address);
                for (Symbol symbol : existingSymbols) {
                    if (symbol.getName().equals(labelName) && symbol.getSymbolType() == SymbolType.LABEL) {
                        return Response.err("Label '" + labelName + "' already exists at address " + addressStr);
                    }
                }

                Symbol newSymbol = symbolTable.createLabel(address, labelName, SourceType.USER_DEFINED);
                if (newSymbol != null) {
                    Map<String, Object> result = new LinkedHashMap<>();
                    result.put("status", "success");
                    result.put("name", labelName);
                    result.put("address", addressStr);
                    return Response.ok(result);
                } else {
                    return Response.err("Failed to create label '" + labelName + "' at address " + addressStr);
                }
            });
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Rename a label at the specified address.
     * Endpoint: /rename_label
     */
    public Response renameLabel(String addressStr, String oldName, String newName) {
        Program program = resolveProgram(null);
        if (program == null) {
            return Response.err("No program loaded");
        }

        try {
            return threadingStrategy.executeWrite(program, "Rename Label", () -> {
                Address address = parseAddress(program, addressStr);
                if (address == null) {
                    return Response.err("Invalid address: " + addressStr);
                }

                SymbolTable symbolTable = program.getSymbolTable();
                Symbol[] symbols = symbolTable.getSymbols(address);

                // Find the specific symbol with the old name
                Symbol targetSymbol = null;
                for (Symbol symbol : symbols) {
                    if (symbol.getName().equals(oldName) && symbol.getSymbolType() == SymbolType.LABEL) {
                        targetSymbol = symbol;
                        break;
                    }
                }

                if (targetSymbol == null) {
                    return Response.err("Label not found: " + oldName + " at address " + addressStr);
                }

                // Check if new name already exists at this address
                for (Symbol symbol : symbols) {
                    if (symbol.getName().equals(newName) && symbol.getSymbolType() == SymbolType.LABEL) {
                        return Response.err("Label with name '" + newName + "' already exists at address " + addressStr);
                    }
                }

                targetSymbol.setName(newName, SourceType.USER_DEFINED);
                Map<String, Object> result = new LinkedHashMap<>();
                result.put("status", "success");
                result.put("old_name", oldName);
                result.put("new_name", newName);
                result.put("address", addressStr);
                return Response.ok(result);
            });
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Get labels within a specific function by name.
     * Endpoint: /get_function_labels
     */
    public Response getFunctionLabels(String functionName, int offset, int limit) {
        Program program = resolveProgram(null);
        if (program == null) {
            return Response.err("No program loaded");
        }

        SymbolTable symbolTable = program.getSymbolTable();
        FunctionManager functionManager = program.getFunctionManager();

        Function function = null;
        for (Function f : functionManager.getFunctions(true)) {
            if (f.getName().equals(functionName)) {
                function = f;
                break;
            }
        }

        if (function == null) {
            return Response.err("Function not found: " + functionName);
        }

        AddressSetView functionBody = function.getBody();
        SymbolIterator symbols = symbolTable.getSymbolIterator();
        List<Object> list = new ArrayList<>();
        int count = 0;
        int skipped = 0;

        while (symbols.hasNext() && count < limit) {
            Symbol symbol = symbols.next();
            if (symbol.getSymbolType() == SymbolType.LABEL &&
                functionBody.contains(symbol.getAddress())) {

                if (skipped < offset) {
                    skipped++;
                    continue;
                }

                Map<String, String> entry = new LinkedHashMap<>();
                entry.put("address", symbol.getAddress().toString());
                entry.put("label_name", symbol.getName());
                entry.put("label_source", symbol.getSource().toString());
                list.add(entry);
                count++;
            }
        }

        return Response.ok(Map.of("labels", list));
    }

    /**
     * Get all jump target addresses from a function's disassembly.
     * Endpoint: /get_function_jump_targets
     */
    public Response getFunctionJumpTargets(String functionName, int offset, int limit) {
        Program program = resolveProgram(null);
        if (program == null) {
            return Response.err("No program loaded");
        }

        FunctionManager functionManager = program.getFunctionManager();

        Function function = null;
        for (Function f : functionManager.getFunctions(true)) {
            if (f.getName().equals(functionName)) {
                function = f;
                break;
            }
        }

        if (function == null) {
            return Response.err("Function not found: " + functionName);
        }

        AddressSetView functionBody = function.getBody();
        Listing listing = program.getListing();
        Set<Address> jumpTargets = new HashSet<>();

        InstructionIterator instructions = listing.getInstructions(functionBody, true);
        while (instructions.hasNext()) {
            Instruction instr = instructions.next();
            if (instr.getFlowType().isJump()) {
                for (Reference ref : instr.getReferencesFrom()) {
                    Address targetAddr = ref.getToAddress();
                    if (targetAddr != null && program.getMemory().contains(targetAddr)) {
                        jumpTargets.add(targetAddr);
                    }
                }
                if (instr.getFlowType().isConditional()) {
                    Address fallThroughAddr = instr.getFallThrough();
                    if (fallThroughAddr != null) {
                        jumpTargets.add(fallThroughAddr);
                    }
                }
            }
        }

        List<Address> sortedTargets = new ArrayList<>(jumpTargets);
        Collections.sort(sortedTargets);

        List<Object> list = new ArrayList<>();
        int count = 0;
        int skipped = 0;

        for (Address target : sortedTargets) {
            if (count >= limit) break;
            if (skipped < offset) { skipped++; continue; }

            String context;
            Function targetFunc = functionManager.getFunctionContaining(target);
            if (targetFunc != null) {
                context = targetFunc.getName();
            } else {
                Symbol symbol = program.getSymbolTable().getPrimarySymbol(target);
                context = symbol != null ? symbol.getName() : null;
            }

            Map<String, String> entry = new LinkedHashMap<>();
            entry.put("address", target.toString());
            entry.put("label", context);
            list.add(entry);
            count++;
        }

        return Response.ok(Map.of("jump_targets", list));
    }

    // =========================================================================
    // EXTERNAL LOCATION ENDPOINTS
    // =========================================================================

    /**
     * List all external locations (imports, ordinal imports, etc.).
     * Endpoint: /list_external_locations
     */
    public Response listExternalLocations(int offset, int limit, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        ExternalManager extMgr = program.getExternalManager();
        List<String> lines = new ArrayList<>();

        try {
            String[] extLibNames = extMgr.getExternalLibraryNames();
            for (String libName : extLibNames) {
                ExternalLocationIterator iter = extMgr.getExternalLocations(libName);
                while (iter.hasNext()) {
                    ExternalLocation extLoc = iter.next();
                    String locName = extLoc.getLabel();
                    String address = extLoc.getAddress().toString().replace(":", "");
                    String info = String.format("%s (%s) - %s @ %s",
                        locName, libName, extLoc.getLabel(), address);
                    lines.add(info);
                }
            }
        } catch (Exception e) {
            return Response.err("Error listing external locations: " + e.getMessage());
        }

        return paginateList(lines, offset, limit);
    }

    /**
     * Get details of a specific external location.
     * Endpoint: /get_external_location
     */
    public Response getExternalLocationDetails(String address, String dllName, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        Address addr = parseAddress(program, address);
        ExternalManager extMgr = program.getExternalManager();

        String foundLabel = null;
        String foundDll = null;

        if (dllName != null && !dllName.isEmpty()) {
            ExternalLocationIterator iter = extMgr.getExternalLocations(dllName);
            while (iter.hasNext()) {
                ExternalLocation extLoc = iter.next();
                if (extLoc.getAddress().equals(addr)) {
                    foundLabel = extLoc.getLabel();
                    foundDll = dllName;
                    break;
                }
            }
        } else {
            String[] libNames = extMgr.getExternalLibraryNames();
            outer:
            for (String libName : libNames) {
                ExternalLocationIterator iter = extMgr.getExternalLocations(libName);
                while (iter.hasNext()) {
                    ExternalLocation extLoc = iter.next();
                    if (extLoc.getAddress().equals(addr)) {
                        foundLabel = extLoc.getLabel();
                        foundDll = libName;
                        break outer;
                    }
                }
            }
        }

        if (foundLabel == null) {
            String errMsg = dllName != null && !dllName.isEmpty()
                ? "External location not found in DLL"
                : "External location not found at address " + address;
            Map<String, String> errResult = new LinkedHashMap<>();
            errResult.put("address", address);
            errResult.put("error", errMsg);
            return Response.ok(errResult);
        }

        Map<String, String> result = new LinkedHashMap<>();
        result.put("address", address);
        result.put("dll_name", foundDll);
        result.put("label", foundLabel);
        return Response.ok(result);
    }

    /**
     * Rename an external location (e.g., change Ordinal_123 to a real function name).
     * Endpoint: /rename_external_location
     */
    public Response renameExternalLocation(String address, String newName) {
        Program program = resolveProgram(null);
        if (program == null) {
            return Response.err("No program loaded");
        }

        try {
            Address addr = parseAddress(program, address);
            ExternalManager extMgr = program.getExternalManager();

            String[] libNames = extMgr.getExternalLibraryNames();
            for (String libName : libNames) {
                ExternalLocationIterator iter = extMgr.getExternalLocations(libName);
                while (iter.hasNext()) {
                    ExternalLocation extLoc = iter.next();
                    if (extLoc.getAddress().equals(addr)) {
                        final String finalLibName = libName;
                        final ExternalLocation finalExtLoc = extLoc;
                        final String oldName = extLoc.getLabel();

                        try {
                            return threadingStrategy.executeWrite(program, "Rename external location", () -> {
                                Namespace extLibNamespace = extMgr.getExternalLibrary(finalLibName);
                                finalExtLoc.setName(extLibNamespace, newName, SourceType.USER_DEFINED);

                                Map<String, Object> result = new LinkedHashMap<>();
                                result.put("success", true);
                                result.put("old_name", oldName);
                                result.put("new_name", newName);
                                result.put("dll", finalLibName);
                                return Response.ok(result);
                            });
                        } catch (Exception e) {
                            return Response.err(e.getMessage());
                        }
                    }
                }
            }

            return Response.err("External location not found at address " + address);
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    // =========================================================================
    // BOOKMARK ENDPOINTS
    // =========================================================================

    /**
     * Set a bookmark at an address with category and comment.
     * Endpoint: /set_bookmark
     */
    public Response setBookmark(String addressStr, String category, String comment) {
        Program program = resolveProgram(null);
        if (program == null) {
            return Response.err("No program loaded");
        }
        if (addressStr == null || addressStr.isEmpty()) {
            Map<String, Object> err = new LinkedHashMap<>();
            err.put("success", false);
            err.put("error", "Address is required");
            return Response.ok(err);
        }
        String finalCategory = (category == null || category.isEmpty()) ? "Note" : category;
        String finalComment = (comment == null) ? "" : comment;

        Address addr = parseAddress(program, addressStr);
        if (addr == null) {
            Map<String, Object> err = new LinkedHashMap<>();
            err.put("success", false);
            err.put("error", "Invalid address: " + addressStr);
            return Response.ok(err);
        }

        try {
            return threadingStrategy.executeWrite(program, "Set bookmark at " + addressStr, () -> {
                BookmarkManager bookmarkManager = program.getBookmarkManager();
                Bookmark existing = bookmarkManager.getBookmark(addr, BookmarkType.NOTE, finalCategory);
                if (existing != null) {
                    bookmarkManager.removeBookmark(existing);
                }
                bookmarkManager.setBookmark(addr, BookmarkType.NOTE, finalCategory, finalComment);

                Map<String, Object> result = new LinkedHashMap<>();
                result.put("success", true);
                result.put("address", addr.toString());
                result.put("category", finalCategory);
                result.put("comment", finalComment);
                return Response.ok(result);
            });
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * List bookmarks, optionally filtered by category and/or address.
     * Endpoint: /list_bookmarks
     */
    public Response listBookmarks(String category, String addressStr) {
        Program program = resolveProgram(null);
        if (program == null) {
            return Response.err("No program loaded");
        }

        BookmarkManager bookmarkManager = program.getBookmarkManager();
        List<Map<String, Object>> bookmarks = new ArrayList<>();

        if (addressStr != null && !addressStr.isEmpty()) {
            Address addr = parseAddress(program, addressStr);
            if (addr == null) {
                Map<String, Object> err = new LinkedHashMap<>();
                err.put("success", false);
                err.put("error", "Invalid address: " + addressStr);
                return Response.ok(err);
            }

            Bookmark[] bms = bookmarkManager.getBookmarks(addr);
            for (Bookmark bm : bms) {
                if (category == null || category.isEmpty() || bm.getCategory().equals(category)) {
                    Map<String, Object> bmMap = new LinkedHashMap<>();
                    bmMap.put("address", bm.getAddress().toString());
                    bmMap.put("category", bm.getCategory());
                    bmMap.put("comment", bm.getComment());
                    bmMap.put("type", bm.getTypeString());
                    bookmarks.add(bmMap);
                }
            }
        } else {
            BookmarkType[] types = bookmarkManager.getBookmarkTypes();
            for (BookmarkType type : types) {
                Iterator<Bookmark> iter = bookmarkManager.getBookmarksIterator(type.getTypeString());
                while (iter.hasNext()) {
                    Bookmark bm = iter.next();
                    if (category == null || category.isEmpty() || bm.getCategory().equals(category)) {
                        Map<String, Object> bmMap = new LinkedHashMap<>();
                        bmMap.put("address", bm.getAddress().toString());
                        bmMap.put("category", bm.getCategory());
                        bmMap.put("comment", bm.getComment());
                        bmMap.put("type", bm.getTypeString());
                        bookmarks.add(bmMap);
                    }
                }
            }
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", true);
        result.put("count", bookmarks.size());
        return Response.ok(result);
    }

    /**
     * Delete a bookmark at an address with optional category filter.
     * Endpoint: /delete_bookmark
     */
    public Response deleteBookmark(String addressStr, String category) {
        Program program = resolveProgram(null);
        if (program == null) {
            return Response.err("No program loaded");
        }
        if (addressStr == null || addressStr.isEmpty()) {
            Map<String, Object> err = new LinkedHashMap<>();
            err.put("success", false);
            err.put("error", "Address is required");
            return Response.ok(err);
        }

        Address addr = parseAddress(program, addressStr);
        if (addr == null) {
            Map<String, Object> err = new LinkedHashMap<>();
            err.put("success", false);
            err.put("error", "Invalid address: " + addressStr);
            return Response.ok(err);
        }

        try {
            return threadingStrategy.executeWrite(program, "Delete bookmark at " + addressStr, () -> {
                BookmarkManager bookmarkManager = program.getBookmarkManager();
                int deleted = 0;
                Bookmark[] bmarks = bookmarkManager.getBookmarks(addr);

                for (Bookmark bm : bmarks) {
                    if (category == null || category.isEmpty() || bm.getCategory().equals(category)) {
                        bookmarkManager.removeBookmark(bm);
                        deleted++;
                    }
                }

                Map<String, Object> result = new LinkedHashMap<>();
                result.put("success", true);
                result.put("deleted", deleted);
                result.put("address", addr.toString());
                return Response.ok(result);
            });
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    // =========================================================================
    // SEARCH ENDPOINTS
    // =========================================================================

    /**
     * Simple function name search (paginated).
     * Endpoint: /search_functions
     */
    public Response searchFunctions(String query, int offset, int limit, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        if (query == null || query.isEmpty()) {
            return Response.err("Query parameter required");
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
    public Response searchFunctionsEnhanced(String namePattern, Integer minXrefs, Integer maxXrefs,
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

            if (callingConvention != null && !callingConvention.isEmpty()) {
                String cc = func.getCallingConventionName();
                if (!callingConvention.equalsIgnoreCase(cc)) continue;
            }

            if (hasCustomName != null) {
                boolean isCustom = !name.startsWith("FUN_");
                if (hasCustomName && !isCustom) continue;
                if (!hasCustomName && isCustom) continue;
            }

            int xrefCount = 0;
            for (Reference ref : refMgr.getReferencesTo(func.getEntryPoint())) {
                xrefCount++;
            }

            if (minXrefs != null && xrefCount < minXrefs) continue;
            if (maxXrefs != null && xrefCount > maxXrefs) continue;

            results.add(new FunctionSearchResult(name, func.getEntryPoint().toString(), xrefCount));
        }

        if ("xref_count".equalsIgnoreCase(sortBy)) {
            results.sort((a, b) -> Integer.compare(b.xrefCount, a.xrefCount));
        } else if ("name".equalsIgnoreCase(sortBy)) {
            results.sort((a, b) -> a.name.compareToIgnoreCase(b.name));
        } else {
            results.sort((a, b) -> a.address.compareTo(b.address));
        }

        int start = Math.max(0, offset);
        int end = Math.min(results.size(), start + limit);
        List<Map<String, Object>> items = new ArrayList<>();
        for (int i = start; i < end; i++) {
            FunctionSearchResult fi = results.get(i);
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("name", fi.name);
            item.put("address", fi.address);
            item.put("xref_count", fi.xrefCount);
            items.add(item);
        }

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("total", results.size());
        response.put("offset", offset);
        response.put("limit", limit);
        response.put("results", items);
        return Response.ok(response);
    }

    // =========================================================================
    // GLOBALS AND MISC
    // =========================================================================

    /**
     * List global variables with optional filtering (paginated).
     * Endpoint: /list_globals
     */
    public Response listGlobals(int offset, int limit, String filter, String programName) {
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
    public Response renameGlobalVariable(String oldName, String newName) {
        Program program = resolveProgram(null);
        if (program == null) {
            return Response.err("No program loaded");
        }

        if (oldName == null || oldName.isEmpty()) {
            return Response.err("Old name is required");
        }
        if (newName == null || newName.isEmpty()) {
            return Response.err("New name is required");
        }

        try {
            return threadingStrategy.executeWrite(program, "Rename global variable", () -> {
                SymbolTable symbolTable = program.getSymbolTable();
                List<Symbol> symbols = symbolTable.getGlobalSymbols(oldName);

                if (symbols.isEmpty()) {
                    return Response.err("Global variable not found: " + oldName);
                }

                Symbol sym = symbols.get(0);
                sym.setName(newName, SourceType.USER_DEFINED);

                return Response.ok(Map.of("message", "Renamed " + oldName + " to " + newName));
            });
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Get program entry points.
     * Endpoint: /get_entry_points
     */
    public Response getEntryPoints(String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        SymbolTable symbolTable = program.getSymbolTable();
        List<Object> entryPoints = new ArrayList<>();

        ghidra.program.model.address.AddressIterator addresses = symbolTable.getExternalEntryPointIterator();
        while (addresses.hasNext()) {
            Address addr = addresses.next();
            Symbol sym = symbolTable.getPrimarySymbol(addr);
            String name = (sym != null) ? sym.getName() : "entry_" + addr;
            Map<String, String> entry = new LinkedHashMap<>();
            entry.put("name", name);
            entry.put("address", addr.toString());
            entryPoints.add(entry);
        }

        return Response.ok(Map.of("entry_points", entryPoints));
    }

    /**
     * List available calling conventions.
     * Endpoint: /list_calling_conventions
     */
    public Response listCallingConventions(String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        FunctionManager fm = program.getFunctionManager();
        Collection<String> conventions = fm.getCallingConventionNames();

        return Response.ok(Map.of("calling_conventions", conventions));
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
