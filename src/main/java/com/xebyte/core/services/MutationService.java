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
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

import java.util.*;

/**
 * Shared service for write (mutation) operations.
 *
 * Handles rename, create, delete, and type-change operations on functions,
 * variables, data labels, and memory blocks. All write operations use
 * {@link ThreadingStrategy#executeWrite} for proper transaction management.
 */
public class MutationService extends BaseService {

    public MutationService(ProgramProvider programProvider, ThreadingStrategy threadingStrategy) {
        super(programProvider, threadingStrategy);
    }

    // =========================================================================
    // FUNCTION RENAME / DELETE / CREATE
    // =========================================================================

    /**
     * Find a function by name and rename it.
     * Endpoint: /rename_function
     */
    public String renameFunction(String oldName, String newName) {
        Program program = resolveProgram(null);
        if (program == null) return programNotFoundError(null);
        if (oldName == null || oldName.isEmpty()) return "Error: Old function name is required";
        if (newName == null || newName.isEmpty()) return "Error: New function name is required";

        try {
            return threadingStrategy.executeWrite(program, "Rename function", () -> {
                for (Function func : program.getFunctionManager().getFunctions(true)) {
                    if (func.getName().equals(oldName)) {
                        func.setName(newName, SourceType.USER_DEFINED);
                        return "Success: Renamed function '" + oldName + "' to '" + newName + "'";
                    }
                }
                return "Error: Function '" + oldName + "' not found";
            });
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Find a function at or containing an address and rename it.
     * Endpoint: /rename_function_by_address
     */
    public String renameFunctionByAddress(String addressStr, String newName) {
        Program program = resolveProgram(null);
        if (program == null) return programNotFoundError(null);
        if (addressStr == null || addressStr.isEmpty()) return "Error: Function address is required";
        if (newName == null || newName.isEmpty()) return "Error: New function name is required";

        Address addr = parseAddress(program, addressStr);
        if (addr == null) return "Error: Invalid address: " + addressStr;

        try {
            return threadingStrategy.executeWrite(program, "Rename function by address", () -> {
                Function func = program.getFunctionManager().getFunctionAt(addr);
                if (func == null) {
                    func = program.getFunctionManager().getFunctionContaining(addr);
                }
                if (func == null) {
                    return "Error: No function found at address: " + addressStr;
                }

                String oldName = func.getName();
                func.setName(newName, SourceType.USER_DEFINED);
                return "Success: Renamed function '" + oldName + "' to '" + newName + "'";
            });
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Save the current program's domain file.
     * Endpoint: /save_program
     */
    public String saveCurrentProgram() {
        Program program = resolveProgram(null);
        if (program == null) return "{\"error\": \"No program loaded\"}";

        try {
            return threadingStrategy.executeWrite(program, "Save program", () -> {
                ghidra.framework.model.DomainFile df = program.getDomainFile();
                if (df == null) {
                    return "{\"error\": \"Program has no domain file\"}";
                }
                df.save(TaskMonitor.DUMMY);
                return "{\"success\": true, \"program\": \"" + escapeJson(program.getName()) +
                       "\", \"message\": \"Program saved successfully\"}";
            });
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Remove a function at the given address.
     * Endpoint: /delete_function
     */
    public String deleteFunctionAtAddress(String addressStr) {
        Program program = resolveProgram(null);
        if (program == null) return "{\"error\": \"No program loaded\"}";
        if (addressStr == null || addressStr.isEmpty()) return "{\"error\": \"address parameter required\"}";

        Address addr = parseAddress(program, addressStr);
        if (addr == null) return "{\"error\": \"Invalid address: " + addressStr + "\"}";

        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) return "{\"error\": \"No function found at address " + addressStr + "\"}";

        String funcName = func.getName();
        long bodySize = func.getBody().getNumAddresses();

        try {
            return threadingStrategy.executeWrite(program, "Delete function at address", () -> {
                program.getFunctionManager().removeFunction(addr);
                return "{" +
                    "\"success\": true, " +
                    "\"address\": \"" + addr + "\", " +
                    "\"deleted_function\": \"" + escapeJson(funcName) + "\", " +
                    "\"body_size\": " + bodySize + ", " +
                    "\"message\": \"Function '" + escapeJson(funcName) + "' deleted at " + addr + "\"" +
                    "}";
            });
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Create a function at the given address, optionally disassembling first.
     * Endpoint: /create_function
     */
    public String createFunctionAtAddress(String addressStr, String name, boolean disassembleFirst) {
        Program program = resolveProgram(null);
        if (program == null) return "{\"error\": \"No program loaded\"}";
        if (addressStr == null || addressStr.isEmpty()) return "{\"error\": \"address parameter required\"}";

        Address addr = parseAddress(program, addressStr);
        if (addr == null) return "{\"error\": \"Invalid address: " + addressStr + "\"}";

        Function existing = program.getFunctionManager().getFunctionAt(addr);
        if (existing != null) {
            return "{\"error\": \"Function already exists at " + addressStr + ": " + existing.getName() + "\"}";
        }

        try {
            return threadingStrategy.executeWrite(program, "Create function at address", () -> {
                if (disassembleFirst) {
                    if (program.getListing().getInstructionAt(addr) == null) {
                        ghidra.program.model.address.AddressSet addrSet =
                            new ghidra.program.model.address.AddressSet(addr, addr);
                        ghidra.app.cmd.disassemble.DisassembleCommand disCmd =
                            new ghidra.app.cmd.disassemble.DisassembleCommand(addrSet, null, true);
                        if (!disCmd.applyTo(program, TaskMonitor.DUMMY)) {
                            return "{\"error\": \"Failed to disassemble at " + addressStr +
                                   ": " + disCmd.getStatusMsg() + "\"}";
                        }
                    }
                }

                ghidra.app.cmd.function.CreateFunctionCmd cmd =
                    new ghidra.app.cmd.function.CreateFunctionCmd(addr);
                if (!cmd.applyTo(program, TaskMonitor.DUMMY)) {
                    return "{\"error\": \"Failed to create function at " + addressStr +
                           ": " + cmd.getStatusMsg() + "\"}";
                }

                Function func = program.getFunctionManager().getFunctionAt(addr);
                if (func == null) {
                    return "{\"error\": \"Function creation reported success but function not found at " +
                           addressStr + "\"}";
                }

                if (name != null && !name.isEmpty()) {
                    func.setName(name, SourceType.USER_DEFINED);
                }

                String funcName = func.getName();
                return "{" +
                    "\"success\": true, " +
                    "\"address\": \"" + addr + "\", " +
                    "\"function_name\": \"" + escapeJson(funcName) + "\", " +
                    "\"entry_point\": \"" + func.getEntryPoint() + "\", " +
                    "\"body_size\": " + func.getBody().getNumAddresses() + ", " +
                    "\"message\": \"Function created successfully at " + addr + "\"" +
                    "}";
            });
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    // =========================================================================
    // MEMORY BLOCK CREATION
    // =========================================================================

    /**
     * Create an uninitialized memory block.
     * Endpoint: /create_memory_block
     */
    public String createMemoryBlock(String name, String addressStr, long size,
                                    boolean read, boolean write, boolean execute,
                                    boolean isVolatile, String comment) {
        Program program = resolveProgram(null);
        if (program == null) return "{\"error\": \"No program loaded\"}";
        if (name == null || name.isEmpty()) return "{\"error\": \"name parameter required\"}";
        if (addressStr == null || addressStr.isEmpty()) return "{\"error\": \"address parameter required\"}";
        if (size <= 0) return "{\"error\": \"size must be positive\"}";

        Address addr = parseAddress(program, addressStr);
        if (addr == null) return "{\"error\": \"Invalid address: " + addressStr + "\"}";

        try {
            return threadingStrategy.executeWrite(program, "Create memory block", () -> {
                ghidra.program.model.mem.MemoryBlock block =
                    program.getMemory().createUninitializedBlock(name, addr, size, false);

                block.setRead(read);
                block.setWrite(write);
                block.setExecute(execute);
                block.setVolatile(isVolatile);
                if (comment != null && !comment.isEmpty()) {
                    block.setComment(comment);
                }

                return "{" +
                    "\"success\": true, " +
                    "\"name\": \"" + escapeJson(name) + "\", " +
                    "\"start\": \"" + block.getStart() + "\", " +
                    "\"end\": \"" + block.getEnd() + "\", " +
                    "\"size\": " + block.getSize() + ", " +
                    "\"permissions\": \"" + (read ? "r" : "-") + (write ? "w" : "-") +
                        (execute ? "x" : "-") + "\", " +
                    "\"volatile\": " + isVolatile + ", " +
                    "\"message\": \"Memory block '" + escapeJson(name) + "' created at " + addr + "\"" +
                    "}";
            });
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    // =========================================================================
    // DATA / LABEL RENAME
    // =========================================================================

    /**
     * Rename the primary symbol at an address, or create a label if none exists.
     * Endpoint: /rename_data
     */
    public String renameData(String addressStr, String newName) {
        Program program = resolveProgram(null);
        if (program == null) return "Error: No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Error: Address is required";
        if (newName == null || newName.isEmpty()) return "Error: New name is required";

        Address addr = parseAddress(program, addressStr);
        if (addr == null) return "Error: Invalid address: " + addressStr;

        try {
            return threadingStrategy.executeWrite(program, "Rename data", () -> {
                SymbolTable symTable = program.getSymbolTable();
                Symbol symbol = symTable.getPrimarySymbol(addr);

                if (symbol != null) {
                    symbol.setName(newName, SourceType.USER_DEFINED);
                    return "Success: Renamed data at " + addressStr + " to '" + newName + "'";
                } else {
                    symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
                    return "Success: Created label '" + newName + "' at " + addressStr;
                }
            });
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Delegate to {@link #renameData} and wrap the result in JSON format.
     * Endpoint: /rename_or_label
     */
    public String renameOrLabel(String addressStr, String newName) {
        if (addressStr == null || addressStr.isEmpty()) return "{\"error\": \"Address is required\"}";
        if (newName == null || newName.isEmpty()) return "{\"error\": \"Name is required\"}";

        String result = renameData(addressStr, newName);

        if (result.startsWith("Success:")) {
            return "{\"success\": true, \"message\": \"" + escapeJson(result) + "\"}";
        } else if (result.startsWith("Error:")) {
            return "{\"error\": \"" + escapeJson(result.substring(7).trim()) + "\"}";
        }
        return "{\"result\": \"" + escapeJson(result) + "\"}";
    }

    /**
     * Read-only check: determine what exists at an address and suggest a rename operation.
     * Endpoint: /can_rename_at_address
     */
    public String canRenameAtAddress(String addressStr) {
        Program program = resolveProgram(null);
        if (program == null) return "{\"error\": \"No program loaded\"}";

        try {
            Address addr = parseAddress(program, addressStr);
            if (addr == null) return "{\"can_rename\": false, \"error\": \"Invalid address\"}";

            StringBuilder result = new StringBuilder();
            result.append("{\"can_rename\": true");

            Function func = program.getFunctionManager().getFunctionAt(addr);
            if (func != null) {
                result.append(", \"type\": \"function\"");
                result.append(", \"suggested_operation\": \"rename_function\"");
                result.append(", \"current_name\": \"").append(escapeJson(func.getName())).append("\"");
                result.append("}");
                return result.toString();
            }

            Data data = program.getListing().getDefinedDataAt(addr);
            if (data != null) {
                result.append(", \"type\": \"defined_data\"");
                result.append(", \"suggested_operation\": \"rename_data\"");
                Symbol symbol = program.getSymbolTable().getPrimarySymbol(addr);
                if (symbol != null) {
                    result.append(", \"current_name\": \"").append(escapeJson(symbol.getName())).append("\"");
                }
                result.append("}");
                return result.toString();
            }

            result.append(", \"type\": \"undefined\"");
            result.append(", \"suggested_operation\": \"create_label\"");
            result.append("}");
            return result.toString();
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    // =========================================================================
    // VARIABLE RENAME / TYPE CHANGE
    // =========================================================================

    /**
     * Rename a parameter or local variable in a function (found by name).
     * Endpoint: /rename_variable
     */
    public String renameVariable(String functionName, String oldName, String newName) {
        Program program = resolveProgram(null);
        if (program == null) return "Error: No program loaded";
        if (functionName == null || functionName.isEmpty()) return "Error: Function name is required";
        if (oldName == null || oldName.isEmpty()) return "Error: Old variable name is required";
        if (newName == null || newName.isEmpty()) return "Error: New variable name is required";

        Function func = null;
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(functionName)) {
                func = f;
                break;
            }
        }

        if (func == null) return "Error: Function '" + functionName + "' not found";

        final Function targetFunc = func;

        try {
            return threadingStrategy.executeWrite(program, "Rename variable", () -> {
                for (Parameter param : targetFunc.getParameters()) {
                    if (param.getName().equals(oldName)) {
                        param.setName(newName, SourceType.USER_DEFINED);
                        return "Success: Renamed parameter '" + oldName + "' to '" + newName + "'";
                    }
                }

                for (Variable var : targetFunc.getLocalVariables()) {
                    if (var.getName().equals(oldName)) {
                        var.setName(newName, SourceType.USER_DEFINED);
                        return "Success: Renamed local variable '" + oldName + "' to '" + newName + "'";
                    }
                }

                return "Error: Variable '" + oldName + "' not found in function '" + functionName + "'";
            });
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Rename multiple variables in a single transaction.
     * Endpoint: /batch_rename_variables
     *
     * @param functionAddress  Entry point address of the function
     * @param renames          Pre-parsed map of old name to new name
     */
    public String batchRenameVariables(String functionAddress, Map<String, String> renames) {
        Program program = resolveProgram(null);
        if (program == null) return "Error: No program loaded";
        if (functionAddress == null || functionAddress.isEmpty()) return "Error: Function address is required";
        if (renames == null || renames.isEmpty()) return "Error: Renames map is required";

        Address addr = parseAddress(program, functionAddress);
        if (addr == null) return "Error: Invalid address: " + functionAddress;

        try {
            return threadingStrategy.executeWrite(program, "Batch rename variables", () -> {
                Function func = program.getFunctionManager().getFunctionAt(addr);
                if (func == null) {
                    func = program.getFunctionManager().getFunctionContaining(addr);
                }
                if (func == null) {
                    return "{\"error\": \"No function found at address: " + functionAddress + "\"}";
                }

                int renamed = 0;
                int failed = 0;
                List<String> errors = new ArrayList<>();

                for (Map.Entry<String, String> entry : renames.entrySet()) {
                    String oldName = entry.getKey();
                    String newName = entry.getValue();
                    boolean found = false;

                    for (Parameter param : func.getParameters()) {
                        if (param.getName().equals(oldName)) {
                            try {
                                param.setName(newName, SourceType.USER_DEFINED);
                                renamed++;
                                found = true;
                                break;
                            } catch (Exception e) {
                                errors.add(oldName + ": " + e.getMessage());
                                failed++;
                                found = true;
                                break;
                            }
                        }
                    }

                    if (!found) {
                        for (Variable var : func.getLocalVariables()) {
                            if (var.getName().equals(oldName)) {
                                try {
                                    var.setName(newName, SourceType.USER_DEFINED);
                                    renamed++;
                                    found = true;
                                    break;
                                } catch (Exception e) {
                                    errors.add(oldName + ": " + e.getMessage());
                                    failed++;
                                    found = true;
                                    break;
                                }
                            }
                        }
                    }

                    if (!found) {
                        errors.add(oldName + ": not found");
                        failed++;
                    }
                }

                StringBuilder sb = new StringBuilder();
                sb.append("{\"success\": ").append(failed == 0).append(", ");
                sb.append("\"renamed\": ").append(renamed).append(", ");
                sb.append("\"failed\": ").append(failed);

                if (!errors.isEmpty()) {
                    sb.append(", \"errors\": [");
                    for (int i = 0; i < errors.size(); i++) {
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
    // FUNCTION PROTOTYPE / VARIABLE TYPE
    // =========================================================================

    /**
     * Parse and apply a function signature, then optionally set the calling convention.
     * Endpoint: /set_function_prototype
     */
    public String setFunctionPrototype(String functionAddress, String prototype, String callingConvention) {
        Program program = resolveProgram(null);
        if (program == null) return "Error: No program loaded";
        if (functionAddress == null || functionAddress.isEmpty()) return "Error: Function address is required";
        if (prototype == null || prototype.isEmpty()) return "Error: Prototype is required";

        Address addr = parseAddress(program, functionAddress);
        if (addr == null) return "Error: Invalid address: " + functionAddress;

        try {
            return threadingStrategy.executeWrite(program, "Set function prototype", () -> {
                Function func = program.getFunctionManager().getFunctionAt(addr);
                if (func == null) {
                    func = program.getFunctionManager().getFunctionContaining(addr);
                }
                if (func == null) {
                    return "Error: No function found at address: " + functionAddress;
                }

                DataTypeManager dtm = program.getDataTypeManager();
                ghidra.app.util.parser.FunctionSignatureParser parser =
                    new ghidra.app.util.parser.FunctionSignatureParser(dtm, null);

                FunctionDefinitionDataType sig = parser.parse(null, prototype);

                ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd =
                    new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
                        func.getEntryPoint(), sig, SourceType.USER_DEFINED);

                if (!cmd.applyTo(program, monitor)) {
                    return "Error: Failed to apply signature - " + cmd.getStatusMsg();
                }

                if (callingConvention != null && !callingConvention.isEmpty()) {
                    try {
                        func.setCallingConvention(callingConvention);
                    } catch (Exception e) {
                        return "Success: Signature set, but calling convention failed: " + e.getMessage();
                    }
                }

                return "Success: Function prototype set for " + func.getName();
            });
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Change the data type of a parameter or local variable.
     * Endpoint: /set_local_variable_type
     */
    public String setLocalVariableType(String functionAddress, String variableName, String newType) {
        Program program = resolveProgram(null);
        if (program == null) return "Error: No program loaded";
        if (functionAddress == null || functionAddress.isEmpty()) return "Error: Function address is required";
        if (variableName == null || variableName.isEmpty()) return "Error: Variable name is required";
        if (newType == null || newType.isEmpty()) return "Error: New type is required";

        Address addr = parseAddress(program, functionAddress);
        if (addr == null) return "Error: Invalid address: " + functionAddress;

        try {
            return threadingStrategy.executeWrite(program, "Set variable type", () -> {
                Function func = program.getFunctionManager().getFunctionAt(addr);
                if (func == null) {
                    func = program.getFunctionManager().getFunctionContaining(addr);
                }
                if (func == null) {
                    return "Error: No function found at address: " + functionAddress;
                }

                DataType dataType = findDataType(program.getDataTypeManager(), newType);
                if (dataType == null) {
                    return "Error: Data type not found: " + newType;
                }

                for (Parameter param : func.getParameters()) {
                    if (param.getName().equals(variableName)) {
                        param.setDataType(dataType, SourceType.USER_DEFINED);
                        return "Success: Set type of parameter '" + variableName + "' to '" + newType + "'";
                    }
                }

                for (Variable var : func.getLocalVariables()) {
                    if (var.getName().equals(variableName)) {
                        var.setDataType(dataType, SourceType.USER_DEFINED);
                        return "Success: Set type of local '" + variableName + "' to '" + newType + "'";
                    }
                }

                return "Error: Variable '" + variableName + "' not found in function";
            });
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // =========================================================================
    // Internal helpers
    // =========================================================================

    /**
     * Look up a data type by name with fallbacks to built-in types and common aliases.
     * Handles pointer types (names ending with {@code *}) recursively.
     */
    private DataType findDataType(DataTypeManager dtm, String typeName) {
        // Exact match in program's data type manager
        Iterator<DataType> iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType dt = iter.next();
            if (dt.getName().equals(typeName)) {
                return dt;
            }
        }

        // Try built-in types (exact then case-insensitive)
        DataTypeManager builtIn = BuiltInDataTypeManager.getDataTypeManager();
        iter = builtIn.getAllDataTypes();
        while (iter.hasNext()) {
            DataType dt = iter.next();
            if (dt.getName().equals(typeName) || dt.getName().equalsIgnoreCase(typeName)) {
                return dt;
            }
        }

        // Common aliases
        switch (typeName.toLowerCase()) {
            case "int":    return new IntegerDataType();
            case "uint":   return new UnsignedIntegerDataType();
            case "short":  return new ShortDataType();
            case "ushort": return new UnsignedShortDataType();
            case "long":   return new LongDataType();
            case "ulong":  return new UnsignedLongDataType();
            case "byte":   return new ByteDataType();
            case "ubyte":  return new UnsignedCharDataType();
            case "char":   return new CharDataType();
            case "uchar":  return new UnsignedCharDataType();
            case "float":  return new FloatDataType();
            case "double": return new DoubleDataType();
            case "void":   return new VoidDataType();
            case "bool":   return new BooleanDataType();
            case "dword":  return new DWordDataType();
            case "word":   return new WordDataType();
            case "qword":  return new QWordDataType();
            default:       break;
        }

        // Pointer types (e.g. "int *" or "SomeStruct*")
        if (typeName.endsWith("*")) {
            String baseTypeName = typeName.substring(0, typeName.length() - 1).trim();
            DataType baseType = findDataType(dtm, baseTypeName);
            if (baseType != null) {
                return dtm.getPointer(baseType);
            }
        }

        return null;
    }
}
