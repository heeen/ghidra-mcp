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
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Shared service for function analysis endpoints.
 *
 * Handles decompile, disassemble, call graph (callees/callers), function variables,
 * analyze_function_complete, force_decompile, and find_next_undefined_function.
 */
public class FunctionService extends BaseService {

    private static final int DECOMPILE_TIMEOUT_SECONDS = 60;

    public FunctionService(ProgramProvider programProvider, ThreadingStrategy threadingStrategy) {
        super(programProvider, threadingStrategy);
    }

    // =========================================================================
    // GETTER ENDPOINTS
    // =========================================================================

    /**
     * Get function info at a specific address.
     * Endpoint: /get_function_by_address
     */
    public String getFunctionByAddress(String addressStr, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        Address addr = parseAddress(program, addressStr);
        if (addr == null) {
            return "{\"error\": \"Invalid address: " + addressStr + "\"}";
        }

        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            func = program.getFunctionManager().getFunctionContaining(addr);
        }

        if (func == null) {
            return "{\"error\": \"No function found at address: " + addressStr + "\"}";
        }

        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"name\": \"").append(escapeJson(func.getName())).append("\",");
        sb.append("\"address\": \"").append(func.getEntryPoint().toString()).append("\",");
        sb.append("\"signature\": \"").append(escapeJson(func.getSignature().getPrototypeString())).append("\",");
        sb.append("\"calling_convention\": \"").append(escapeJson(func.getCallingConventionName())).append("\"");
        sb.append("}");
        return sb.toString();
    }

    // =========================================================================
    // DECOMPILE / DISASSEMBLE ENDPOINTS
    // =========================================================================

    /**
     * Decompile a function by address or name.
     * Endpoint: /decompile_function
     */
    public String decompileFunction(String addressStr, String name, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        Function func = resolveFunction(program, addressStr, name);
        if (func == null) {
            return "Error: Function not found";
        }

        try {
            DecompInterface decompiler = new DecompInterface();
            decompiler.openProgram(program);

            DecompileResults results = decompiler.decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS, monitor);

            if (results == null || !results.decompileCompleted()) {
                String errorMsg = results != null ? results.getErrorMessage() : "Unknown error";
                return "Error: Decompilation failed - " + errorMsg;
            }

            String decompiled = results.getDecompiledFunction().getC();
            decompiler.dispose();

            return decompiled != null ? decompiled : "Error: No decompiled output";

        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Disassemble a function at an address.
     * Endpoint: /disassemble_function
     */
    public String disassembleFunction(String addressStr, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        Address addr = parseAddress(program, addressStr);
        if (addr == null) {
            return "Error: Invalid address: " + addressStr;
        }

        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            func = program.getFunctionManager().getFunctionContaining(addr);
        }

        if (func == null) {
            return "Error: No function found at address: " + addressStr;
        }

        List<String> lines = new ArrayList<>();
        Listing listing = program.getListing();
        InstructionIterator iter = listing.getInstructions(func.getBody(), true);

        while (iter.hasNext()) {
            Instruction inst = iter.next();
            String comment = inst.getComment(CodeUnit.EOL_COMMENT);
            String line = inst.getAddress() + ": " + inst.toString();
            if (comment != null && !comment.isEmpty()) {
                line += " ; " + comment;
            }
            lines.add(line);
        }

        return String.join("\n", lines);
    }

    /**
     * Force re-decompilation of a function (bypasses cache).
     * Endpoint: /force_decompile
     */
    public String forceDecompile(String address, String name, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        Function func = resolveFunction(program, address, name);
        if (func == null) {
            return "{\"error\": \"Function not found\"}";
        }

        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.openProgram(program);
            DecompileResults results = decompiler.decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS, monitor);

            if (results == null || !results.decompileCompleted()) {
                return "{\"error\": \"Decompilation failed\"}";
            }

            String code = results.getDecompiledFunction().getC();
            return code != null ? code : "{\"error\": \"No decompiled code available\"}";
        } finally {
            decompiler.dispose();
        }
    }

    // =========================================================================
    // CALL GRAPH ENDPOINTS
    // =========================================================================

    /**
     * Get all functions called by a function (callees).
     * Endpoint: /get_function_callees
     */
    public String getFunctionCallees(String functionName, int offset, int limit, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        if (functionName == null || functionName.isEmpty()) {
            return "{\"error\": \"Function name is required\"}";
        }

        Function func = findFunctionByName(program, functionName);
        if (func == null) {
            return "{\"error\": \"Function not found: " + escapeJson(functionName) + "\"}";
        }

        Set<Function> callees = new LinkedHashSet<>();
        ReferenceManager refMgr = program.getReferenceManager();
        FunctionManager funcMgr = program.getFunctionManager();
        InstructionIterator instrs = program.getListing().getInstructions(func.getBody(), true);

        while (instrs.hasNext()) {
            Instruction instr = instrs.next();
            if (instr.getFlowType().isCall()) {
                for (Reference ref : refMgr.getReferencesFrom(instr.getAddress())) {
                    if (ref.getReferenceType().isCall()) {
                        Function target = funcMgr.getFunctionAt(ref.getToAddress());
                        if (target != null) {
                            callees.add(target);
                        }
                    }
                }
            }
        }

        List<String> results = callees.stream()
            .map(f -> f.getName() + " @ " + f.getEntryPoint())
            .collect(Collectors.toList());

        return paginateList(results, offset, limit);
    }

    /**
     * Get all functions that call a function (callers).
     * Endpoint: /get_function_callers
     */
    public String getFunctionCallers(String functionName, int offset, int limit, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        if (functionName == null || functionName.isEmpty()) {
            return "{\"error\": \"Function name is required\"}";
        }

        Function func = findFunctionByName(program, functionName);
        if (func == null) {
            return "{\"error\": \"Function not found: " + escapeJson(functionName) + "\"}";
        }

        Set<Function> callers = new LinkedHashSet<>();
        ReferenceManager refMgr = program.getReferenceManager();
        FunctionManager funcMgr = program.getFunctionManager();
        ReferenceIterator refs = refMgr.getReferencesTo(func.getEntryPoint());

        while (refs.hasNext()) {
            Reference ref = refs.next();
            if (ref.getReferenceType().isCall()) {
                Function caller = funcMgr.getFunctionContaining(ref.getFromAddress());
                if (caller != null) {
                    callers.add(caller);
                }
            }
        }

        List<String> results = callers.stream()
            .map(f -> f.getName() + " @ " + f.getEntryPoint())
            .collect(Collectors.toList());

        return paginateList(results, offset, limit);
    }

    // =========================================================================
    // VARIABLE ENDPOINTS
    // =========================================================================

    /**
     * Get all variables (parameters and locals) for a function.
     * Endpoint: /get_function_variables
     */
    public String getFunctionVariables(String functionName, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        if (functionName == null || functionName.isEmpty()) {
            return "{\"error\": \"Function name is required\"}";
        }

        Function func = findFunctionByName(program, functionName);
        if (func == null) {
            return "{\"error\": \"Function not found: " + escapeJson(functionName) + "\"}";
        }

        StringBuilder sb = new StringBuilder();
        sb.append("{\"function\": \"").append(escapeJson(func.getName())).append("\", ");
        sb.append("\"parameters\": [");

        Parameter[] params = func.getParameters();
        for (int i = 0; i < params.length; i++) {
            if (i > 0) sb.append(", ");
            Parameter p = params[i];
            sb.append("{");
            sb.append("\"name\": \"").append(escapeJson(p.getName())).append("\", ");
            sb.append("\"type\": \"").append(escapeJson(p.getDataType().getName())).append("\", ");
            sb.append("\"ordinal\": ").append(p.getOrdinal()).append(", ");
            sb.append("\"storage\": \"").append(escapeJson(p.getVariableStorage().toString())).append("\"");
            sb.append("}");
        }

        sb.append("], \"locals\": [");

        Variable[] locals = func.getLocalVariables();
        for (int i = 0; i < locals.length; i++) {
            if (i > 0) sb.append(", ");
            Variable v = locals[i];
            sb.append("{");
            sb.append("\"name\": \"").append(escapeJson(v.getName())).append("\", ");
            sb.append("\"type\": \"").append(escapeJson(v.getDataType().getName())).append("\", ");
            sb.append("\"storage\": \"").append(escapeJson(v.getVariableStorage().toString())).append("\"");
            sb.append("}");
        }

        sb.append("]}");
        return sb.toString();
    }

    // =========================================================================
    // COMPOSITE / SEARCH ENDPOINTS
    // =========================================================================

    /**
     * Comprehensive function analysis in a single call.
     * Endpoint: /analyze_function_complete
     */
    public String analyzeFunctionComplete(String name, boolean includeXrefs, boolean includeCallees,
                                          boolean includeCallers, boolean includeDisasm,
                                          boolean includeVariables, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        Function func = findFunctionByName(program, name);
        if (func == null) {
            return "{\"error\": \"Function not found: " + escapeJson(name) + "\"}";
        }

        StringBuilder sb = new StringBuilder();
        sb.append("{");

        // Basic info
        sb.append("\"name\": \"").append(escapeJson(func.getName())).append("\"");
        sb.append(", \"address\": \"").append(func.getEntryPoint()).append("\"");
        sb.append(", \"signature\": \"").append(escapeJson(func.getSignature().getPrototypeString())).append("\"");

        // Decompiled code
        String decompiled = decompileFunction(null, name, programName);
        sb.append(", \"decompiled_code\": \"").append(escapeJson(decompiled)).append("\"");

        // Xrefs
        if (includeXrefs) {
            sb.append(", \"xrefs\": [");
            ReferenceManager refMgr = program.getReferenceManager();
            int count = 0;
            for (Reference ref : refMgr.getReferencesTo(func.getEntryPoint())) {
                if (count > 0) sb.append(", ");
                sb.append("{\"from\": \"").append(ref.getFromAddress()).append("\"");
                sb.append(", \"type\": \"").append(ref.getReferenceType()).append("\"}");
                if (++count >= 50) break;
            }
            sb.append("]");
        }

        // Callees
        if (includeCallees) {
            String callees = getFunctionCallees(name, 0, 50, programName);
            sb.append(", \"callees\": [");
            String[] lines = callees.split("\n");
            boolean first = true;
            for (String line : lines) {
                if (line.isEmpty() || line.contains("error")) continue;
                if (!first) sb.append(", ");
                sb.append("\"").append(escapeJson(line)).append("\"");
                first = false;
            }
            sb.append("]");
        }

        // Callers
        if (includeCallers) {
            String callers = getFunctionCallers(name, 0, 50, programName);
            sb.append(", \"callers\": [");
            String[] lines = callers.split("\n");
            boolean first = true;
            for (String line : lines) {
                if (line.isEmpty() || line.contains("error")) continue;
                if (!first) sb.append(", ");
                sb.append("\"").append(escapeJson(line)).append("\"");
                first = false;
            }
            sb.append("]");
        }

        // Disassembly
        if (includeDisasm) {
            String disasm = disassembleFunction(func.getEntryPoint().toString(), programName);
            sb.append(", \"disassembly\": \"").append(escapeJson(disasm)).append("\"");
        }

        // Variables
        if (includeVariables) {
            String vars = getFunctionVariables(name, programName);
            sb.append(", \"variables\": ").append(vars);
        }

        sb.append("}");
        return sb.toString();
    }

    /**
     * Find the next undefined/unnamed function based on criteria.
     * Endpoint: /find_next_undefined_function
     */
    public String findNextUndefinedFunction(String startAddress, String criteria,
                                            String pattern, String direction, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        FunctionManager fm = program.getFunctionManager();
        Address startAddr = null;

        if (startAddress != null && !startAddress.isEmpty()) {
            startAddr = parseAddress(program, startAddress);
        }

        if (startAddr == null) {
            startAddr = program.getMinAddress();
        }

        String searchPattern = (pattern != null && !pattern.isEmpty()) ? pattern : "FUN_";
        boolean ascending = !"descending".equalsIgnoreCase(direction);

        FunctionIterator funcIter = fm.getFunctions(startAddr, ascending);
        while (funcIter.hasNext()) {
            Function func = funcIter.next();
            String name = func.getName();

            if (name.contains(searchPattern)) {
                StringBuilder sb = new StringBuilder();
                sb.append("{\"found\": true");
                sb.append(", \"name\": \"").append(escapeJson(name)).append("\"");
                sb.append(", \"address\": \"").append(func.getEntryPoint()).append("\"");
                sb.append(", \"signature\": \"").append(escapeJson(func.getSignature().getPrototypeString())).append("\"");
                sb.append("}");
                return sb.toString();
            }
        }

        return "{\"found\": false}";
    }

    // =========================================================================
    // Internal helpers
    // =========================================================================

    /**
     * Find a function by name (linear scan).
     */
    private Function findFunctionByName(Program program, String name) {
        if (name == null || name.isEmpty()) return null;
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(name)) {
                return f;
            }
        }
        return null;
    }

    /**
     * Resolve a function by address first, then by name.
     */
    private Function resolveFunction(Program program, String addressStr, String name) {
        Function func = null;

        if (addressStr != null && !addressStr.isEmpty()) {
            Address addr = parseAddress(program, addressStr);
            if (addr != null) {
                func = program.getFunctionManager().getFunctionAt(addr);
                if (func == null) {
                    func = program.getFunctionManager().getFunctionContaining(addr);
                }
            }
        }

        if (func == null && name != null && !name.isEmpty()) {
            func = findFunctionByName(program, name);
        }

        return func;
    }
}
