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
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;

import java.util.*;

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
    public String listMethods(int offset, int limit, String programName) {
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
     * List all functions with name and address.
     * Endpoint: /list_functions
     */
    public String listFunctions(String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        List<String> lines = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            lines.add(f.getName() + " @ " + f.getEntryPoint().toString());
        }
        return String.join("\n", lines);
    }

    /**
     * List all class/namespace names (paginated).
     * Endpoint: /list_classes
     */
    public String listClasses(int offset, int limit, String programName) {
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
    public String listSegments(int offset, int limit, String programName) {
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
    public String listImports(int offset, int limit, String programName) {
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
    public String listExports(int offset, int limit, String programName) {
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
    public String listNamespaces(int offset, int limit, String programName) {
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
    public String listDataItems(int offset, int limit, String programName) {
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
        return String.join("\n", lines);
    }

    /**
     * List defined strings with optional filter (paginated).
     * Endpoint: /list_strings
     */
    public String listStrings(int offset, int limit, String filter, String programName) {
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
                    lines.add(data.getAddress() + ": \"" + escapeJson(strValue) + "\"");
                }
            }
        }

        return paginateList(lines, offset, limit);
    }

    /**
     * List data types with optional category filter (paginated).
     * Endpoint: /list_data_types
     */
    public String listDataTypes(int offset, int limit, String category, String programName) {
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
}
