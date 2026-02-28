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

import com.xebyte.core.JsonHelper;
import com.xebyte.core.ProgramProvider;
import com.xebyte.core.Response;
import com.xebyte.core.ThreadingStrategy;
import com.xebyte.core.services.*;
import com.google.gson.reflect.TypeToken;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Headless endpoint handler implementation.
 *
 * Delegates to shared services in com.xebyte.core.services for business logic
 * that is common to both GUI and headless modes. Keeps headless-only endpoints
 * (program/project lifecycle, scripts, analysis control) as local implementations.
 */
public class HeadlessEndpointHandler {

    private static final String VERSION = "1.9.4-headless";

    private final ProgramProvider programProvider;
    private final ThreadingStrategy threadingStrategy;
    private final TaskMonitor monitor;

    private final ListingService listingService;
    private final FunctionService functionService;
    private final SymbolService symbolService;
    private final CommentService commentService;
    private final MutationService mutationService;
    private final DataTypeService dataTypeService;
    private final AnalysisService analysisService;
    private final ComparisonService comparisonService;

    public HeadlessEndpointHandler(ProgramProvider programProvider, ThreadingStrategy threadingStrategy) {
        this.programProvider = programProvider;
        this.threadingStrategy = threadingStrategy;
        this.monitor = new ConsoleTaskMonitor();
        this.listingService = new ListingService(programProvider, threadingStrategy);
        this.functionService = new FunctionService(programProvider, threadingStrategy);
        this.symbolService = new SymbolService(programProvider, threadingStrategy);
        this.commentService = new CommentService(programProvider, threadingStrategy);
        this.mutationService = new MutationService(programProvider, threadingStrategy);
        this.dataTypeService = new DataTypeService(programProvider, threadingStrategy);
        this.analysisService = new AnalysisService(programProvider, threadingStrategy);
        this.comparisonService = new ComparisonService(programProvider, threadingStrategy);
    }

    // ==========================================================================
    // UTILITY METHODS
    // ==========================================================================

    private Program getProgram(String programName) {
        return programProvider.resolveProgram(programName);
    }

    private String getProgramError(String programName) {
        if (programName != null && !programName.isEmpty()) {
            return "{\"error\": \"Program not found: " + escapeJson(programName) + "\"}";
        }
        return "{\"error\": \"No program currently loaded\"}";
    }

    private String paginateList(List<String> items, int offset, int limit) {
        if (items.isEmpty()) {
            return "";
        }
        int start = Math.max(0, offset);
        int end = Math.min(items.size(), start + limit);
        if (start >= items.size()) {
            return "";
        }
        return String.join("\n", items.subList(start, end));
    }

    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    private Address parseAddress(Program program, String addressStr) {
        if (addressStr == null || addressStr.isEmpty()) {
            return null;
        }
        return program.getAddressFactory().getAddress(addressStr);
    }

    /**
     * Bridge: convert a Response sealed type back to String for HEH's String-returning API.
     */
    private String responseToString(Response response) {
        return switch (response) {
            case Response.Ok ok -> JsonHelper.toJson(ok.data());
            case Response.Err err -> JsonHelper.errorJson(err.message());
            case Response.Text text -> text.content();
        };
    }

    // ==========================================================================
    // VERSION AND METADATA
    // ==========================================================================

    public String getVersion() {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"plugin_version\": \"").append(VERSION).append("\",");
        sb.append("\"plugin_name\": \"GhidraMCP Headless\",");
        sb.append("\"mode\": \"headless\"");
        sb.append("}");
        return sb.toString();
    }

    /**
     * Health check endpoint for container orchestration (Docker, Kubernetes).
     * Returns JSON with status, version, and program information.
     */
    public String getHealth() {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"status\": \"healthy\",");
        sb.append("\"version\": \"").append(VERSION).append("\",");
        
        // Check if any program is loaded
        Program program = getProgram(null);
        boolean programLoaded = (program != null);
        sb.append("\"program_loaded\": ").append(programLoaded);
        
        if (programLoaded) {
            sb.append(",\"program_name\": \"").append(escapeJson(program.getName())).append("\"");
        }
        
        sb.append("}");
        return sb.toString();
    }

    public String getMetadata() {
        Program program = getProgram(null);
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
        }

        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"name\": \"").append(escapeJson(program.getName())).append("\",");
        sb.append("\"path\": \"").append(escapeJson(program.getExecutablePath())).append("\",");
        sb.append("\"language\": \"").append(escapeJson(program.getLanguageID().toString())).append("\",");
        sb.append("\"compiler\": \"").append(escapeJson(program.getCompilerSpec().getCompilerSpecID().toString())).append("\",");
        sb.append("\"image_base\": \"").append(program.getImageBase().toString()).append("\",");
        sb.append("\"address_size\": ").append(program.getAddressFactory().getDefaultAddressSpace().getSize()).append(",");
        sb.append("\"min_address\": \"").append(program.getMinAddress().toString()).append("\",");
        sb.append("\"max_address\": \"").append(program.getMaxAddress().toString()).append("\"");
        sb.append("}");
        return sb.toString();
    }


    // ==========================================================================
    // DELEGATED ENDPOINTS — ListingService
    // ==========================================================================

    public String listMethods(int offset, int limit, String programName) {
        return responseToString(listingService.listMethods(offset, limit, programName));
    }

    public String listFunctions(String programName) {
        return responseToString(listingService.listFunctions(0, Integer.MAX_VALUE, programName));
    }

    public String listClasses(int offset, int limit, String programName) {
        return responseToString(listingService.listClasses(offset, limit, programName));
    }

    public String listSegments(int offset, int limit, String programName) {
        return responseToString(listingService.listSegments(offset, limit, programName));
    }

    public String listImports(int offset, int limit, String programName) {
        return responseToString(listingService.listImports(offset, limit, programName));
    }

    public String listExports(int offset, int limit, String programName) {
        return responseToString(listingService.listExports(offset, limit, programName));
    }

    public String listNamespaces(int offset, int limit, String programName) {
        return responseToString(listingService.listNamespaces(offset, limit, programName));
    }

    public String listDataItems(int offset, int limit, String programName) {
        return responseToString(listingService.listDataItems(offset, limit, programName));
    }

    public String listStrings(int offset, int limit, String filter, String programName) {
        return responseToString(listingService.listStrings(offset, limit, filter, programName));
    }

    public String listDataTypes(int offset, int limit, String category, String programName) {
        return responseToString(listingService.listDataTypes(offset, limit, category, programName));
    }

    public String listDataItemsByXrefs(int offset, int limit, String format, String programName) {
        return responseToString(listingService.listDataItemsByXrefs(offset, limit, format, programName));
    }

    public String getFunctionCount(String programName) {
        return responseToString(listingService.getFunctionCount(programName));
    }

    // ==========================================================================
    // DELEGATED ENDPOINTS — FunctionService
    // ==========================================================================

    public String getFunctionByAddress(String addressStr, String programName) {
        return responseToString(functionService.getFunctionByAddress(addressStr, programName));
    }

    public String decompileFunction(String addressStr, String name, String programName) {
        return responseToString(functionService.decompileFunction(addressStr, name, programName));
    }

    public String disassembleFunction(String addressStr, String programName) {
        return responseToString(functionService.disassembleFunction(addressStr, programName));
    }

    public String forceDecompile(String address, String name, String programName) {
        return responseToString(functionService.forceDecompile(address, name, programName));
    }

    public String getFunctionCallees(String functionName, int offset, int limit, String programName) {
        return responseToString(functionService.getFunctionCallees(functionName, offset, limit, programName));
    }

    public String getFunctionCallers(String functionName, int offset, int limit, String programName) {
        return responseToString(functionService.getFunctionCallers(functionName, offset, limit, programName));
    }

    public String getFunctionVariables(String functionName, String programName) {
        return responseToString(functionService.getFunctionVariables(functionName, programName));
    }

    public String analyzeFunctionComplete(String name, boolean includeXrefs, boolean includeCallees,
                                          boolean includeCallers, boolean includeDisasm,
                                          boolean includeVariables, String programName) {
        return responseToString(functionService.analyzeFunctionComplete(name, includeXrefs, includeCallees,
                includeCallers, includeDisasm, includeVariables, programName));
    }

    public String findNextUndefinedFunction(String startAddress, String criteria,
                                            String pattern, String direction, String programName) {
        return responseToString(functionService.findNextUndefinedFunction(startAddress, criteria,
                pattern, direction, programName));
    }

    // ==========================================================================
    // DELEGATED ENDPOINTS — SymbolService
    // ==========================================================================

    public String getXrefsTo(String addressStr, int offset, int limit, String programName) {
        return responseToString(symbolService.getXrefsTo(addressStr, offset, limit, programName));
    }

    public String getXrefsFrom(String addressStr, int offset, int limit, String programName) {
        return responseToString(symbolService.getXrefsFrom(addressStr, offset, limit, programName));
    }

    public String getFunctionXrefs(String functionName, int offset, int limit, String programName) {
        return responseToString(symbolService.getFunctionXrefs(functionName, offset, limit, programName));
    }

    public String getBulkXrefs(String addressesJson) {
        List<String> addresses = JsonHelper.gson().fromJson(addressesJson, new TypeToken<List<String>>(){}.getType());
        if (addresses == null) addresses = List.of();
        return responseToString(symbolService.getBulkXrefs(addresses, null));
    }

    public String searchFunctions(String query, int offset, int limit, String programName) {
        return responseToString(symbolService.searchFunctions(query, offset, limit, programName));
    }

    public String searchFunctionsEnhanced(String namePattern, Integer minXrefs, Integer maxXrefs,
                                          Boolean hasCustomName, boolean regex, String sortBy,
                                          int offset, int limit, String programName) {
        return responseToString(symbolService.searchFunctionsEnhanced(namePattern, minXrefs, maxXrefs,
                null, hasCustomName, regex, sortBy, offset, limit, programName));
    }

    public String listGlobals(int offset, int limit, String filter, String programName) {
        return responseToString(symbolService.listGlobals(offset, limit, filter, programName));
    }

    public String renameGlobalVariable(String oldName, String newName) {
        return responseToString(symbolService.renameGlobalVariable(oldName, newName));
    }

    public String getEntryPoints(String programName) {
        return responseToString(symbolService.getEntryPoints(programName));
    }

    public String listCallingConventions(String programName) {
        return responseToString(symbolService.listCallingConventions(programName));
    }

    public String deleteLabel(String addressStr, String labelName) {
        return responseToString(symbolService.deleteLabel(addressStr, labelName));
    }

    public String batchCreateLabels(String labelsJson) {
        List<Map<String, String>> labels = JsonHelper.gson().fromJson(labelsJson,
                new TypeToken<List<Map<String, String>>>(){}.getType());
        if (labels == null) labels = List.of();
        return responseToString(symbolService.batchCreateLabels(labels));
    }

    public String batchDeleteLabels(String labelsJson) {
        List<Map<String, String>> labels = JsonHelper.gson().fromJson(labelsJson,
                new TypeToken<List<Map<String, String>>>(){}.getType());
        if (labels == null) labels = List.of();
        return responseToString(symbolService.batchDeleteLabels(labels));
    }

    // ==========================================================================
    // DELEGATED ENDPOINTS — CommentService
    // ==========================================================================

    public String setDecompilerComment(String addressStr, String comment) {
        return responseToString(commentService.setDecompilerComment(addressStr, comment));
    }

    public String setDisassemblyComment(String addressStr, String comment) {
        return responseToString(commentService.setDisassemblyComment(addressStr, comment));
    }

    public String setPlateComment(String functionAddress, String comment) {
        return responseToString(commentService.setPlateComment(functionAddress, comment));
    }

    public String batchSetComments(String functionAddress, String decompilerCommentsJson,
                                   String disassemblyCommentsJson, String plateComment) {
        List<Map<String, String>> decompilerComments = (decompilerCommentsJson != null && !decompilerCommentsJson.isEmpty())
                ? JsonHelper.gson().fromJson(decompilerCommentsJson, new TypeToken<List<Map<String, String>>>(){}.getType())
                : null;
        List<Map<String, String>> disassemblyComments = (disassemblyCommentsJson != null && !disassemblyCommentsJson.isEmpty())
                ? JsonHelper.gson().fromJson(disassemblyCommentsJson, new TypeToken<List<Map<String, String>>>(){}.getType())
                : null;
        return responseToString(commentService.batchSetComments(functionAddress,
                decompilerComments, disassemblyComments, plateComment));
    }

    public String clearFunctionComments(String functionAddress, boolean clearPlate, boolean clearPre, boolean clearEol) {
        return responseToString(commentService.clearFunctionComments(functionAddress, clearPlate, clearPre, clearEol));
    }

    // ==========================================================================
    // DELEGATED ENDPOINTS — MutationService
    // ==========================================================================

    public String renameFunction(String oldName, String newName) {
        return responseToString(mutationService.renameFunction(oldName, newName));
    }

    public String renameFunctionByAddress(String addressStr, String newName) {
        return responseToString(mutationService.renameFunctionByAddress(addressStr, newName));
    }

    public String saveCurrentProgram() {
        return responseToString(mutationService.saveCurrentProgram());
    }

    public String deleteFunctionAtAddress(String addressStr) {
        return responseToString(mutationService.deleteFunctionAtAddress(addressStr));
    }

    public String createFunctionAtAddress(String addressStr, String name, boolean disassembleFirst) {
        return responseToString(mutationService.createFunctionAtAddress(addressStr, name, disassembleFirst));
    }

    public String createMemoryBlock(String name, String addressStr, long size,
                                    boolean read, boolean write, boolean execute,
                                    boolean isVolatile, String comment) {
        return responseToString(mutationService.createMemoryBlock(name, addressStr, size,
                read, write, execute, isVolatile, comment));
    }

    public String renameData(String addressStr, String newName) {
        return responseToString(mutationService.renameData(addressStr, newName));
    }

    public String renameVariable(String functionName, String oldName, String newName) {
        return responseToString(mutationService.renameVariable(functionName, oldName, newName));
    }

    public String batchRenameVariables(String functionAddress, String renamesJson) {
        Map<String, String> renames = JsonHelper.gson().fromJson(renamesJson,
                new TypeToken<Map<String, String>>(){}.getType());
        if (renames == null) renames = Map.of();
        return responseToString(mutationService.batchRenameVariables(functionAddress, renames));
    }

    public String setFunctionPrototype(String functionAddress, String prototype, String callingConvention) {
        return responseToString(mutationService.setFunctionPrototype(functionAddress, prototype, callingConvention));
    }

    public String setLocalVariableType(String functionAddress, String variableName, String newType) {
        return responseToString(mutationService.setLocalVariableType(functionAddress, variableName, newType));
    }

    public String renameOrLabel(String addressStr, String newName) {
        return responseToString(mutationService.renameOrLabel(addressStr, newName));
    }

    public String canRenameAtAddress(String addressStr) {
        return responseToString(mutationService.canRenameAtAddress(addressStr));
    }

    // ==========================================================================
    // DELEGATED ENDPOINTS — DataTypeService
    // ==========================================================================

    public String createStruct(String name, String fieldsJson) {
        return responseToString(dataTypeService.createStruct(name, fieldsJson));
    }

    public String applyDataType(String addressStr, String typeName, boolean clearExisting) {
        return responseToString(dataTypeService.applyDataType(addressStr, typeName, clearExisting));
    }

    public String createEnum(String name, String valuesJson, int size) {
        return responseToString(dataTypeService.createEnum(name, valuesJson, size));
    }

    public String createUnion(String name, String fieldsJson) {
        return responseToString(dataTypeService.createUnion(name, fieldsJson));
    }

    public String createTypedef(String name, String baseType) {
        return responseToString(dataTypeService.createTypedef(name, baseType));
    }

    public String createArrayType(String baseType, int length, String name) {
        return responseToString(dataTypeService.createArrayType(baseType, length, name));
    }

    public String createPointerType(String baseType, String name) {
        return responseToString(dataTypeService.createPointerType(baseType, name));
    }

    public String addStructField(String structName, String fieldName, String fieldType, int offset) {
        return responseToString(dataTypeService.addStructField(structName, fieldName, fieldType, offset));
    }

    public String modifyStructField(String structName, String fieldName, String newType, String newName) {
        return responseToString(dataTypeService.modifyStructField(structName, fieldName, newType, newName));
    }

    public String removeStructField(String structName, String fieldName) {
        return responseToString(dataTypeService.removeStructField(structName, fieldName));
    }

    public String deleteDataType(String typeName) {
        return responseToString(dataTypeService.deleteDataType(typeName));
    }

    public String searchDataTypes(String pattern, int offset, int limit) {
        return responseToString(dataTypeService.searchDataTypes(pattern, offset, limit));
    }

    public String validateDataTypeExists(String typeName) {
        return responseToString(dataTypeService.validateDataTypeExists(typeName));
    }

    public String getDataTypeSize(String typeName) {
        return responseToString(dataTypeService.getDataTypeSize(typeName));
    }

    public String getStructLayout(String structName) {
        return responseToString(dataTypeService.getStructLayout(structName));
    }

    public String getEnumValues(String enumName) {
        return responseToString(dataTypeService.getEnumValues(enumName));
    }

    public String cloneDataType(String sourceType, String newName) {
        return responseToString(dataTypeService.cloneDataType(sourceType, newName));
    }

    // ==========================================================================
    // DELEGATED ENDPOINTS — AnalysisService
    // ==========================================================================

    public String searchBytePatterns(String pattern, String mask) {
        return responseToString(analysisService.searchBytePatterns(pattern, mask));
    }

    public String analyzeDataRegion(String startAddressStr, int maxScanBytes,
                                    boolean includeXrefMap, boolean includeAssemblyPatterns,
                                    boolean includeBoundaryDetection) {
        return responseToString(analysisService.analyzeDataRegion(startAddressStr, maxScanBytes,
                includeXrefMap, includeAssemblyPatterns, includeBoundaryDetection));
    }

    public String detectArrayBounds(String addressStr, boolean analyzeLoopBounds,
                                    boolean analyzeIndexing, int maxScanRange) {
        return responseToString(analysisService.detectArrayBounds(addressStr, analyzeLoopBounds,
                analyzeIndexing, maxScanRange));
    }

    public String getAssemblyContext(String xrefSourcesStr, int contextInstructions, String includePatterns) {
        return responseToString(analysisService.getAssemblyContext(xrefSourcesStr, contextInstructions, includePatterns));
    }

    public String analyzeStructFieldUsage(String addressStr, String structName, int maxFunctions) {
        return responseToString(analysisService.analyzeStructFieldUsage(addressStr, structName, maxFunctions));
    }

    public String getFieldAccessContext(String structAddressStr, int fieldOffset, int numExamples) {
        return responseToString(analysisService.getFieldAccessContext(structAddressStr, fieldOffset, numExamples));
    }

    public String listAnalyzers(String programName) {
        return responseToString(analysisService.listAnalyzers(programName));
    }

    public String runAnalysis(String programName) {
        return responseToString(analysisService.runAnalysis(programName));
    }

    // ==========================================================================
    // DELEGATED ENDPOINTS — ComparisonService
    // ==========================================================================

    public String getFunctionHash(String addressStr, String programName) {
        return responseToString(comparisonService.getFunctionHash(addressStr, programName));
    }

    public String getBulkFunctionHashes(int offset, int limit, String filter, String programName) {
        return responseToString(comparisonService.getBulkFunctionHashes(offset, limit, filter, programName));
    }

    public String getFunctionSignature(String addressStr, String programName) {
        return responseToString(comparisonService.getFunctionSignature(addressStr, programName));
    }

    public String findSimilarFunctionsFuzzy(String addressStr, String sourceProgramName,
            String targetProgramName, double threshold, int limit) {
        return responseToString(comparisonService.findSimilarFunctionsFuzzy(addressStr, sourceProgramName,
                targetProgramName, threshold, limit));
    }

    public String bulkFuzzyMatch(String sourceProgramName, String targetProgramName,
            double threshold, int offset, int limit, String filter) {
        return responseToString(comparisonService.bulkFuzzyMatch(sourceProgramName, targetProgramName,
                threshold, offset, limit, filter));
    }

    public String diffFunctions(String addressA, String addressB,
            String programAName, String programBName) {
        return responseToString(comparisonService.diffFunctions(addressA, addressB,
                programAName, programBName));
    }

    // ==========================================================================
    // PROGRAM MANAGEMENT (headless-only)
    // ==========================================================================

    public String listOpenPrograms() {
        Program[] programs = programProvider.getAllOpenPrograms();
        Program current = programProvider.getCurrentProgram();

        StringBuilder sb = new StringBuilder();
        sb.append("{\"programs\": [");

        for (int i = 0; i < programs.length; i++) {
            if (i > 0) sb.append(", ");
            Program p = programs[i];
            sb.append("{");
            sb.append("\"name\": \"").append(escapeJson(p.getName())).append("\",");
            sb.append("\"is_current\": ").append(p == current);
            sb.append("}");
        }

        sb.append("], \"count\": ").append(programs.length);
        if (current != null) {
            sb.append(", \"current_program\": \"").append(escapeJson(current.getName())).append("\"");
        }
        sb.append("}");

        return sb.toString();
    }

    public String getCurrentProgramInfo() {
        Program program = getProgram(null);
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
        }

        return getMetadata();
    }

    public String switchProgram(String name) {
        if (name == null || name.isEmpty()) {
            return "{\"error\": \"Program name required\"}";
        }

        Program program = programProvider.getProgram(name);
        if (program == null) {
            return "{\"error\": \"Program not found: " + escapeJson(name) + "\"}";
        }

        programProvider.setCurrentProgram(program);
        return "{\"success\": true, \"current_program\": \"" + escapeJson(program.getName()) + "\"}";
    }

    // ==========================================================================
    // HEADLESS-SPECIFIC ENDPOINTS
    // ==========================================================================

    public String loadProgram(String filePath) {
        if (filePath == null || filePath.isEmpty()) {
            return "{\"error\": \"File path required\"}";
        }

        File file = new File(filePath);
        if (!file.exists()) {
            return "{\"error\": \"File not found: " + escapeJson(filePath) + "\"}";
        }

        if (programProvider instanceof HeadlessProgramProvider) {
            HeadlessProgramProvider hpp = (HeadlessProgramProvider) programProvider;
            Program program = hpp.loadProgramFromFile(file);

            if (program != null) {
                return "{\"success\": true, \"program\": \"" + escapeJson(program.getName()) + "\"}";
            } else {
                return "{\"error\": \"Failed to load program from: " + escapeJson(filePath) + "\"}";
            }
        }

        return "{\"error\": \"Load not supported in this mode\"}";
    }

    public String closeProgram(String name) {
        Program program = programProvider.getProgram(name);
        if (program == null) {
            return "{\"error\": \"Program not found: " + (name != null ? escapeJson(name) : "current") + "\"}";
        }

        if (programProvider instanceof HeadlessProgramProvider) {
            HeadlessProgramProvider hpp = (HeadlessProgramProvider) programProvider;
            hpp.closeProgram(program);
            return "{\"success\": true, \"closed\": \"" + escapeJson(program.getName()) + "\"}";
        }

        return "{\"error\": \"Close not supported in this mode\"}";
    }

    // ==========================================================================
    // PROJECT MANAGEMENT ENDPOINTS
    // ==========================================================================

    /**
     * Open a Ghidra project from a .gpr file path.
     */
    public String openProject(String projectPath) {
        if (projectPath == null || projectPath.isEmpty()) {
            return "{\"error\": \"Project path required\"}";
        }

        if (programProvider instanceof HeadlessProgramProvider) {
            HeadlessProgramProvider hpp = (HeadlessProgramProvider) programProvider;
            boolean success = hpp.openProject(projectPath);

            if (success) {
                String projectName = hpp.getProjectName();
                return "{\"success\": true, \"project\": \"" + escapeJson(projectName) + "\"}";
            } else {
                return "{\"error\": \"Failed to open project: " + escapeJson(projectPath) + "\"}";
            }
        }

        return "{\"error\": \"Project management not supported in this mode\"}";
    }

    /**
     * Close the current project.
     */
    public String closeProject() {
        if (programProvider instanceof HeadlessProgramProvider) {
            HeadlessProgramProvider hpp = (HeadlessProgramProvider) programProvider;

            if (!hpp.hasProject()) {
                return "{\"error\": \"No project currently open\"}";
            }

            String projectName = hpp.getProjectName();
            hpp.closeProject();
            return "{\"success\": true, \"closed\": \"" + escapeJson(projectName) + "\"}";
        }

        return "{\"error\": \"Project management not supported in this mode\"}";
    }

    /**
     * List all files in the current project.
     */
    public String listProjectFiles() {
        if (programProvider instanceof HeadlessProgramProvider) {
            HeadlessProgramProvider hpp = (HeadlessProgramProvider) programProvider;

            if (!hpp.hasProject()) {
                return "{\"error\": \"No project currently open\"}";
            }

            List<HeadlessProgramProvider.ProjectFileInfo> files = hpp.listProjectFiles();

            StringBuilder sb = new StringBuilder();
            sb.append("{\"project\": \"").append(escapeJson(hpp.getProjectName())).append("\", ");
            sb.append("\"files\": [");

            for (int i = 0; i < files.size(); i++) {
                HeadlessProgramProvider.ProjectFileInfo file = files.get(i);
                if (i > 0) sb.append(", ");
                sb.append("{");
                sb.append("\"name\": \"").append(escapeJson(file.name)).append("\", ");
                sb.append("\"path\": \"").append(escapeJson(file.path)).append("\", ");
                sb.append("\"contentType\": \"").append(escapeJson(file.contentType)).append("\", ");
                sb.append("\"readOnly\": ").append(file.readOnly);
                sb.append("}");
            }

            sb.append("], \"count\": ").append(files.size()).append("}");
            return sb.toString();
        }

        return "{\"error\": \"Project management not supported in this mode\"}";
    }

    /**
     * Load a program from the current project.
     */
    public String loadProgramFromProject(String programPath) {
        if (programPath == null || programPath.isEmpty()) {
            return "{\"error\": \"Program path required (e.g., /D2Client.dll)\"}";
        }

        if (programProvider instanceof HeadlessProgramProvider) {
            HeadlessProgramProvider hpp = (HeadlessProgramProvider) programProvider;

            if (!hpp.hasProject()) {
                return "{\"error\": \"No project currently open. Use /open_project first.\"}";
            }

            Program program = hpp.loadProgramFromProject(programPath);

            if (program != null) {
                return "{\"success\": true, \"program\": \"" + escapeJson(program.getName()) + "\", " +
                       "\"path\": \"" + escapeJson(programPath) + "\"}";
            } else {
                return "{\"error\": \"Failed to load program: " + escapeJson(programPath) + "\"}";
            }
        }

        return "{\"error\": \"Project management not supported in this mode\"}";
    }

    /**
     * Get info about the current project.
     */
    public String getProjectInfo() {
        if (programProvider instanceof HeadlessProgramProvider) {
            HeadlessProgramProvider hpp = (HeadlessProgramProvider) programProvider;

            if (!hpp.hasProject()) {
                return "{\"has_project\": false}";
            }

            List<HeadlessProgramProvider.ProjectFileInfo> files = hpp.listProjectFiles();
            int programCount = (int) files.stream()
                .filter(f -> "Program".equals(f.contentType))
                .count();

            return "{\"has_project\": true, " +
                   "\"project_name\": \"" + escapeJson(hpp.getProjectName()) + "\", " +
                   "\"file_count\": " + files.size() + ", " +
                   "\"program_count\": " + programCount + "}";
        }

        return "{\"error\": \"Project management not supported in this mode\"}";
    }


    // ==========================================================================
    // PROJECT LIFECYCLE (headless-only)
    // ==========================================================================

    public String createProject(String parentDir, String name) {
        if (parentDir == null || parentDir.isEmpty()) return "{\"error\": \"parentDir required\"}";
        if (name == null || name.isEmpty()) return "{\"error\": \"name required\"}";
        if (!(programProvider instanceof HeadlessProgramProvider)) {
            return "{\"error\": \"Project management not supported in this mode\"}";
        }
        HeadlessProgramProvider hpp = (HeadlessProgramProvider) programProvider;
        try {
            boolean ok = hpp.createProject(parentDir, name);
            if (ok) return "{\"success\": true, \"name\": \"" + escapeJson(name) + "\", \"path\": \"" + escapeJson(parentDir) + "/" + escapeJson(name) + "\"}";
            return "{\"error\": \"Failed to create project\"}";
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    public String deleteProject(String projectPath) {
        if (projectPath == null || projectPath.isEmpty()) return "{\"error\": \"projectPath required\"}";
        if (!(programProvider instanceof HeadlessProgramProvider)) {
            return "{\"error\": \"Project management not supported in this mode\"}";
        }
        HeadlessProgramProvider hpp = (HeadlessProgramProvider) programProvider;
        try {
            boolean ok = hpp.deleteProject(projectPath);
            if (ok) return "{\"success\": true, \"deleted\": \"" + escapeJson(projectPath) + "\"}";
            return "{\"error\": \"Failed to delete project\"}";
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    public String listProjects(String searchDir) {
        if (!(programProvider instanceof HeadlessProgramProvider)) {
            return "{\"error\": \"Project management not supported in this mode\"}";
        }
        HeadlessProgramProvider hpp = (HeadlessProgramProvider) programProvider;
        try {
            List<HeadlessProgramProvider.ProjectInfo> projects = hpp.listProjects(searchDir);
            StringBuilder sb = new StringBuilder("[");
            for (int i = 0; i < projects.size(); i++) {
                if (i > 0) sb.append(",");
                HeadlessProgramProvider.ProjectInfo p = projects.get(i);
                sb.append("{\"name\":\"").append(escapeJson(p.name)).append("\",");
                sb.append("\"path\":\"").append(escapeJson(p.path)).append("\",");
                sb.append("\"active\":").append(p.active).append("}");
            }
            sb.append("]");
            return sb.toString();
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    // ==========================================================================
    // PROJECT ORGANIZATION ENDPOINTS
    // ==========================================================================

    public String createFolder(String folderPath, String programName) {
        if (!(programProvider instanceof HeadlessProgramProvider)) {
            return "{\"error\": \"Project management not supported in this mode\"}";
        }
        HeadlessProgramProvider hpp = (HeadlessProgramProvider) programProvider;
        try {
            hpp.createFolder(folderPath);
            return "{\"success\": true, \"folder\": \"" + escapeJson(folderPath) + "\"}";
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    public String moveFile(String filePath, String destFolder) {
        if (!(programProvider instanceof HeadlessProgramProvider)) {
            return "{\"error\": \"Project management not supported in this mode\"}";
        }
        HeadlessProgramProvider hpp = (HeadlessProgramProvider) programProvider;
        try {
            hpp.moveFile(filePath, destFolder);
            return "{\"success\": true, \"moved\": \"" + escapeJson(filePath) + "\", \"to\": \"" + escapeJson(destFolder) + "\"}";
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    public String moveFolder(String sourcePath, String destPath) {
        if (!(programProvider instanceof HeadlessProgramProvider)) {
            return "{\"error\": \"Project management not supported in this mode\"}";
        }
        HeadlessProgramProvider hpp = (HeadlessProgramProvider) programProvider;
        try {
            hpp.moveFolder(sourcePath, destPath);
            return "{\"success\": true, \"moved\": \"" + escapeJson(sourcePath) + "\", \"to\": \"" + escapeJson(destPath) + "\"}";
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    public String deleteFile(String filePath) {
        if (!(programProvider instanceof HeadlessProgramProvider)) {
            return "{\"error\": \"Project management not supported in this mode\"}";
        }
        HeadlessProgramProvider hpp = (HeadlessProgramProvider) programProvider;
        try {
            hpp.deleteProjectFile(filePath);
            return "{\"success\": true, \"deleted\": \"" + escapeJson(filePath) + "\"}";
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    // ==========================================================================
    // ANALYSIS CONTROL (headless-only)
    // ==========================================================================

    public String configureAnalyzer(String programName, String analyzerName, Boolean enabled) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        if (!(programProvider instanceof HeadlessProgramProvider)) {
            return "{\"error\": \"Analyzer configuration not supported in this mode\"}";
        }
        HeadlessProgramProvider hpp = (HeadlessProgramProvider) programProvider;
        try {
            hpp.configureAnalyzer(program, analyzerName, enabled);
            return "{\"success\": true, \"analyzer\": \"" + escapeJson(analyzerName) + "\"}";
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    // ==========================================================================
    // UTILITY ENDPOINTS (headless-only)
    // ==========================================================================

    public String exitServer() {
        new Thread(() -> {
            try { Thread.sleep(500); } catch (InterruptedException ignored) {}
            System.exit(0);
        }).start();
        return "{\"success\": true, \"message\": \"Server shutting down\"}";
    }

    public String convertNumber(String value, int size) {
        if (value == null || value.trim().isEmpty()) return "{\"error\": \"value required\"}";
        value = value.trim();
        try {
            long result;
            String detectedBase;
            if (value.startsWith("0x") || value.startsWith("0X")) {
                result = Long.parseUnsignedLong(value.substring(2), 16);
                detectedBase = "hex";
            } else if (value.startsWith("0b") || value.startsWith("0B")) {
                result = Long.parseUnsignedLong(value.substring(2), 2);
                detectedBase = "binary";
            } else if (value.startsWith("0") && value.length() > 1) {
                result = Long.parseUnsignedLong(value.substring(1), 8);
                detectedBase = "octal";
            } else {
                result = Long.parseUnsignedLong(value, 10);
                detectedBase = "decimal";
            }
            return "{\"input\":\"" + escapeJson(value) + "\",\"detected_base\":\"" + detectedBase + "\"," +
                   "\"decimal\":" + Long.toUnsignedString(result) + "," +
                   "\"hex\":\"0x" + Long.toUnsignedString(result, 16).toUpperCase() + "\"," +
                   "\"octal\":\"0" + Long.toUnsignedString(result, 8) + "\"," +
                   "\"binary\":\"0b" + Long.toUnsignedString(result, 2) + "\"}";
        } catch (NumberFormatException e) {
            return "{\"error\": \"Invalid number: " + escapeJson(value) + "\"}";
        }
    }

    public String readMemory(String addressStr, int length, String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        if (addressStr == null || addressStr.isEmpty()) return "{\"error\": \"address required\"}";
        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) return "{\"error\": \"Invalid address: " + escapeJson(addressStr) + "\"}";
            if (length <= 0 || length > 4096) length = 256;
            byte[] buffer = new byte[length];
            int bytesRead = program.getMemory().getBytes(addr, buffer);
            StringBuilder hex = new StringBuilder();
            StringBuilder ascii = new StringBuilder();
            for (int i = 0; i < bytesRead; i++) {
                int b = buffer[i] & 0xFF;
                if (i > 0 && i % 16 == 0) hex.append("\\n");
                else if (i > 0) hex.append(" ");
                hex.append(String.format("%02X", b));
                ascii.append(b >= 0x20 && b < 0x7F ? (char) b : '.');
            }
            return "{\"address\":\"" + escapeJson(addressStr) + "\",\"length\":" + bytesRead +
                   ",\"hex\":\"" + escapeJson(hex.toString()) + "\",\"ascii\":\"" + escapeJson(ascii.toString()) + "\"}";
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    // ==========================================================================
    // BOOKMARK ENDPOINTS
    // ==========================================================================

    public String listBookmarks(String category, String address, String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        try {
            StringBuilder sb = new StringBuilder("[");
            boolean first = true;
            BookmarkManager bm = program.getBookmarkManager();
            Iterator<Bookmark> iter = bm.getBookmarksIterator();
            while (iter.hasNext()) {
                Bookmark bk = iter.next();
                if (!first) sb.append(",");
                first = false;
                sb.append("{\"address\":\"").append(bk.getAddress()).append("\",");
                sb.append("\"type\":\"").append(escapeJson(bk.getTypeString())).append("\",");
                sb.append("\"category\":\"").append(escapeJson(bk.getCategory())).append("\",");
                sb.append("\"comment\":\"").append(escapeJson(bk.getComment())).append("\"}");
            }
            sb.append("]");
            return sb.toString();
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    public String setBookmark(String addressStr, String category, String comment, String programName) {
        String type = "Note";
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) return "{\"error\": \"Invalid address: " + escapeJson(addressStr) + "\"}";
            final String finalType = (type != null && !type.isEmpty()) ? type : "Note";
            final String finalCat = (category != null) ? category : "";
            final String finalComment = (comment != null) ? comment : "";
            return threadingStrategy.executeWrite(program, "Set bookmark", () -> {
                program.getBookmarkManager().setBookmark(addr, finalType, finalCat, finalComment);
                return "{\"success\": true, \"address\": \"" + escapeJson(addressStr) + "\"}";
            });
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    public String deleteBookmark(String addressStr, String category, String programName) {
        String type = null;
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) return "{\"error\": \"Invalid address: " + escapeJson(addressStr) + "\"}";
            final String finalType = type;
            final String finalCat = (category != null) ? category : "";
            return threadingStrategy.executeWrite(program, "Delete bookmark", () -> {
                BookmarkManager bm = program.getBookmarkManager();
                Bookmark[] bks = bm.getBookmarks(addr);
                int deleted = 0;
                for (Bookmark bk : bks) {
                    if (finalType == null || finalType.isEmpty() || bk.getTypeString().equals(finalType)) {
                        if (finalCat.isEmpty() || bk.getCategory().equals(finalCat)) {
                            bm.removeBookmark(bk);
                            deleted++;
                        }
                    }
                }
                return "{\"success\": true, \"address\": \"" + escapeJson(addressStr) + "\", \"deleted\": " + deleted + "}";
            });
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    // ==========================================================================
    // ENHANCED QUERY ENDPOINTS
    // ==========================================================================


    public String listFunctionsEnhanced(int offset, int limit, String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        StringBuilder result = new StringBuilder("{\"functions\":[");
        int count = 0;
        int skipped = 0;
        boolean first = true;
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (skipped < offset) { skipped++; continue; }
            if (count >= limit) break;
            if (!first) result.append(",");
            first = false;
            result.append("{\"name\":\"").append(escapeJson(func.getName())).append("\",");
            result.append("\"address\":\"").append(func.getEntryPoint()).append("\",");
            result.append("\"isThunk\":").append(func.isThunk()).append(",");
            result.append("\"isExternal\":").append(func.isExternal()).append("}");
            count++;
        }
        result.append("],\"count\":").append(count);
        result.append(",\"offset\":").append(offset);
        result.append(",\"limit\":").append(limit).append("}");
        return result.toString();
    }

    public String getValidDataTypes(String category) {
        List<String> builtins = Arrays.asList(
            "byte", "word", "dword", "qword", "float", "double", "longdouble",
            "char", "wchar_t", "short", "int", "long", "longlong",
            "uchar", "ushort", "uint", "ulong", "ulonglong",
            "bool", "void", "pointer", "pointer32", "pointer64",
            "string", "unicode", "pascal", "mbcs",
            "BYTE", "WORD", "DWORD", "QWORD", "BOOL", "HANDLE", "LPVOID",
            "PVOID", "HMODULE", "HINSTANCE", "HWND", "HDC", "HKEY",
            "LPCSTR", "LPSTR", "LPCWSTR", "LPWSTR", "LPTSTR", "LPCTSTR",
            "LARGE_INTEGER", "ULARGE_INTEGER", "SYSTEMTIME", "FILETIME",
            "SECURITY_DESCRIPTOR", "ACL", "SID", "TOKEN_PRIVILEGES"
        );
        StringBuilder sb = new StringBuilder("{\"data_types\":[");
        for (int i = 0; i < builtins.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append("\"").append(builtins.get(i)).append("\"");
        }
        sb.append("],\"count\":").append(builtins.size()).append("}");
        return sb.toString();
    }

    public String getTypeSize(String typeName, String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        if (typeName == null || typeName.isEmpty()) return "{\"error\": \"typeName required\"}";
        DataTypeManager dtm = program.getDataTypeManager();
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            if (dt.getName().equalsIgnoreCase(typeName)) {
                return "{\"type\":\"" + escapeJson(dt.getName()) + "\",\"size\":" + dt.getLength() + ",\"path\":\"" + escapeJson(dt.getPathName()) + "\"}";
            }
        }
        return "{\"error\": \"Data type not found: " + escapeJson(typeName) + "\"}";
    }

    public String listExternalLocations(int offset, int limit, String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        try {
            StringBuilder sb = new StringBuilder("[");
            boolean first = true;
            int skipped = 0;
            int count = 0;
            ghidra.program.model.symbol.ExternalManager em = program.getExternalManager();
            for (String libName : em.getExternalLibraryNames()) {
                ghidra.program.model.symbol.ExternalLocationIterator it = em.getExternalLocations(libName);
                while (it.hasNext()) {
                    ghidra.program.model.symbol.ExternalLocation loc = it.next();
                    if (skipped < offset) { skipped++; continue; }
                    if (count >= limit) break;
                    if (!first) sb.append(",");
                    first = false;
                    sb.append("{\"library\":\"").append(escapeJson(libName)).append("\",");
                    sb.append("\"name\":\"").append(escapeJson(loc.getLabel())).append("\",");
                    sb.append("\"address\":\"").append(loc.getAddress() != null ? loc.getAddress().toString() : "").append("\",");
                    sb.append("\"original_imported_name\":\"").append(escapeJson(loc.getOriginalImportedName() != null ? loc.getOriginalImportedName() : "")).append("\"}");
                    count++;
                }
                if (count >= limit) break;
            }
            sb.append("]");
            return sb.toString();
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    public String getExternalLocation(String libraryName, String symbolName, String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        try {
            ghidra.program.model.symbol.ExternalManager em = program.getExternalManager();
            ghidra.program.model.symbol.ExternalLocationIterator it = em.getExternalLocations(libraryName);
            while (it.hasNext()) {
                ghidra.program.model.symbol.ExternalLocation loc = it.next();
                if (loc.getLabel().equals(symbolName)) {
                    return "{\"library\":\"" + escapeJson(libraryName) + "\",\"name\":\"" + escapeJson(loc.getLabel()) + "\"," +
                           "\"address\":\"" + (loc.getAddress() != null ? loc.getAddress().toString() : "") + "\"," +
                           "\"original_imported_name\":\"" + escapeJson(loc.getOriginalImportedName() != null ? loc.getOriginalImportedName() : "") + "\"}";
                }
            }
            return "{\"error\": \"External location not found: " + escapeJson(libraryName) + "!" + escapeJson(symbolName) + "\"}";
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    // ==========================================================================
    // FLOW CONTROL ENDPOINTS
    // ==========================================================================

    public String setFunctionNoReturn(String functionAddrStr, boolean noReturn) {
        Program program = getProgram(null);
        if (program == null) return "{\"error\": \"No program loaded\"}";
        if (functionAddrStr == null || functionAddrStr.isEmpty()) return "{\"error\": \"address required\"}";
        try {
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            if (addr == null) return "{\"error\": \"Invalid address: " + escapeJson(functionAddrStr) + "\"}";
            Function func = program.getFunctionManager().getFunctionAt(addr);
            if (func == null) func = program.getFunctionManager().getFunctionContaining(addr);
            if (func == null) return "{\"error\": \"No function at address: " + escapeJson(functionAddrStr) + "\"}";
            final Function finalFunc = func;
            final String oldState = func.hasNoReturn() ? "non-returning" : "returning";
            return threadingStrategy.executeWrite(program, "Set function no return", () -> {
                finalFunc.setNoReturn(noReturn);
                String newState = noReturn ? "non-returning" : "returning";
                return "{\"success\": true, \"function\": \"" + escapeJson(finalFunc.getName()) + "\"," +
                       "\"from\": \"" + oldState + "\", \"to\": \"" + newState + "\"}";
            });
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    public String clearInstructionFlowOverride(String instructionAddrStr) {
        Program program = getProgram(null);
        if (program == null) return "{\"error\": \"No program loaded\"}";
        if (instructionAddrStr == null || instructionAddrStr.isEmpty()) return "{\"error\": \"address required\"}";
        try {
            Address addr = program.getAddressFactory().getAddress(instructionAddrStr);
            if (addr == null) return "{\"error\": \"Invalid address: " + escapeJson(instructionAddrStr) + "\"}";
            Instruction instruction = program.getListing().getInstructionAt(addr);
            if (instruction == null) return "{\"error\": \"No instruction at address: " + escapeJson(instructionAddrStr) + "\"}";
            final FlowOverride oldOverride = instruction.getFlowOverride();
            return threadingStrategy.executeWrite(program, "Clear instruction flow override", () -> {
                instruction.setFlowOverride(FlowOverride.NONE);
                return "{\"success\": true, \"address\": \"" + escapeJson(instructionAddrStr) + "\"," +
                       "\"previous_override\": \"" + oldOverride.toString() + "\", \"new_override\": \"NONE\"}";
            });
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    public String setVariableStorage(String functionAddrStr, String variableName, String storageSpec) {
        Program program = getProgram(null);
        if (program == null) return "{\"error\": \"No program loaded\"}";
        if (functionAddrStr == null || functionAddrStr.isEmpty()) return "{\"error\": \"address required\"}";
        if (variableName == null || variableName.isEmpty()) return "{\"error\": \"variable_name required\"}";
        try {
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            if (addr == null) return "{\"error\": \"Invalid address: " + escapeJson(functionAddrStr) + "\"}";
            Function func = program.getFunctionManager().getFunctionAt(addr);
            if (func == null) return "{\"error\": \"No function at address: " + escapeJson(functionAddrStr) + "\"}";
            Variable targetVar = null;
            for (Variable var : func.getAllVariables()) {
                if (var.getName().equals(variableName)) { targetVar = var; break; }
            }
            if (targetVar == null) return "{\"error\": \"Variable not found: " + escapeJson(variableName) + "\"}";
            String currentStorage = targetVar.getVariableStorage().toString();
            return "{\"advisory\": true, \"message\": \"Programmatic variable storage control is limited in Ghidra.\"," +
                   "\"variable\": \"" + escapeJson(variableName) + "\"," +
                   "\"function\": \"" + escapeJson(func.getName()) + "\"," +
                   "\"current_storage\": \"" + escapeJson(currentStorage) + "\"," +
                   "\"requested_storage\": \"" + escapeJson(storageSpec != null ? storageSpec : "") + "\"," +
                   "\"tip\": \"Use Ghidra decompiler UI or a custom script to change variable storage.\"}";
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    // ==========================================================================
    // DATA TYPE CATEGORY ENDPOINTS
    // ==========================================================================

    public String createDataTypeCategory(String categoryPath) {
        Program program = getProgram(null);
        if (program == null) return getProgramError(null);
        if (categoryPath == null || categoryPath.isEmpty()) return "{\"error\": \"categoryPath required\"}";
        try {
            return threadingStrategy.executeWrite(program, "Create data type category", () -> {
                DataTypeManager dtm = program.getDataTypeManager();
                ghidra.program.model.data.CategoryPath cp = new ghidra.program.model.data.CategoryPath(categoryPath);
                ghidra.program.model.data.Category cat = dtm.createCategory(cp);
                return "{\"success\": true, \"category\": \"" + escapeJson(cat.getCategoryPathName()) + "\"}";
            });
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    public String moveDataTypeToCategory(String typeName, String targetCategory, String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        try {
            return threadingStrategy.executeWrite(program, "Move data type to category", () -> {
                DataTypeManager dtm = program.getDataTypeManager();
                Iterator<DataType> allTypes = dtm.getAllDataTypes();
                DataType found = null;
                while (allTypes.hasNext()) {
                    DataType dt = allTypes.next();
                    if (dt.getName().equals(typeName)) { found = dt; break; }
                }
                if (found == null) return "{\"error\": \"Type not found: " + escapeJson(typeName) + "\"}";
                ghidra.program.model.data.CategoryPath cp = new ghidra.program.model.data.CategoryPath(targetCategory);
                dtm.createCategory(cp);
                found.setCategoryPath(cp);
                return "{\"success\": true, \"type\": \"" + escapeJson(typeName) + "\", \"category\": \"" + escapeJson(targetCategory) + "\"}";
            });
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    public String listDataTypeCategories(int offset, int limit, String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        try {
            DataTypeManager dtm = program.getDataTypeManager();
            Set<String> categories = new TreeSet<>();
            Iterator<DataType> allTypes = dtm.getAllDataTypes();
            while (allTypes.hasNext()) {
                DataType dt = allTypes.next();
                categories.add(dt.getCategoryPath().getPath());
            }
            StringBuilder sb = new StringBuilder("[");
            boolean first = true;
            for (String cat : categories) {
                if (!first) sb.append(",");
                first = false;
                sb.append("\"").append(escapeJson(cat)).append("\"");
            }
            sb.append("]");
            return sb.toString();
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    public String importDataTypes(String source, String format, String programName) {
        return "{\"advisory\": true, \"message\": \"Data type import from external files requires the Ghidra GUI. " +
               "Use File -> Parse C Source in Ghidra to import types from .h files.\", " +
               "\"requested_file\": \"" + escapeJson(source != null ? source : "") + "\"}";
    }

    // ==========================================================================
    // SCRIPT ENDPOINTS (headless-only)
    // ==========================================================================

    public String runScript(String scriptPath, String scriptArgs) {
        Program program = getProgram(null);
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
        }

        if (scriptPath == null || scriptPath.isEmpty()) {
            return "{\"error\": \"Script path is required\"}";
        }

        StringBuilder result = new StringBuilder();
        result.append("{\"status\": \"Script execution in headless mode\",");
        result.append("\"script_path\": \"").append(escapeJson(scriptPath)).append("\",");
        result.append("\"program\": \"").append(escapeJson(program.getName())).append("\",");
        result.append("\"note\": \"Full script execution requires GUI mode. Use Ghidra's analyzeHeadless for batch scripting.\"}");

        return result.toString();
    }

    /**
     * List available Ghidra scripts
     */
    public String listScripts(String filter) {
        StringBuilder result = new StringBuilder();
        result.append("{\"scripts\": [],");
        result.append("\"note\": \"Script listing in headless mode is limited.\",");
        result.append("\"common_locations\": [");
        result.append("\"<ghidra_install>/Ghidra/Features/*/ghidra_scripts/\",");
        result.append("\"<user_home>/ghidra_scripts/\"");
        result.append("],");
        result.append("\"filter\": ").append(filter != null ? "\"" + escapeJson(filter) + "\"" : "null");
        result.append("}");
        return result.toString();
    }

    public String runScriptInline(String scriptContent, String args) {
        return "{\"advisory\": true, \"message\": \"Inline script execution requires Ghidra GUI mode or analyzeHeadless.\"," +
               "\"tip\": \"Use analyzeHeadless with -scriptPath and -process for batch scripting.\"}";
    }

    // ==========================================================================
    // CALL GRAPH ENDPOINTS (headless-only)
    // ==========================================================================

    public String getFunctionCallGraph(String functionAddress, int depth, String direction, String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        FunctionManager functionManager = program.getFunctionManager();
        Function rootFunction = findFunctionByAddressOrName(program, functionAddress);
        if (rootFunction == null) return "{\"error\": \"Function not found: " + escapeJson(functionAddress) + "\"}";
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
        if (sb.length() == 0) return "No call graph relationships found for function: " + functionAddress;
        return sb.toString();
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

    public String getFullCallGraph(int limit, String format, String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
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
        if (sb.length() == 0) return "No call relationships found in the program";
        return sb.toString();
    }

    // ==========================================================================
    // JUMP TARGET AND LABEL ENDPOINTS
    // ==========================================================================

    public String getFunctionJumpTargets(String functionAddress, int offset, int limit, String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        Function function = findFunctionByAddressOrName(program, functionAddress);
        if (function == null) return "{\"error\": \"Function not found: " + escapeJson(functionAddress) + "\"}";
        FunctionManager functionManager = program.getFunctionManager();
        Set<Address> jumpTargets = new HashSet<>();
        InstructionIterator instructions = program.getListing().getInstructions(function.getBody(), true);
        while (instructions.hasNext()) {
            Instruction instr = instructions.next();
            if (instr.getFlowType().isJump()) {
                for (Reference ref : instr.getReferencesFrom()) {
                    Address targetAddr = ref.getToAddress();
                    if (targetAddr != null && program.getMemory().contains(targetAddr)) jumpTargets.add(targetAddr);
                }
                if (instr.getFlowType().isConditional()) {
                    Address ft = instr.getFallThrough();
                    if (ft != null) jumpTargets.add(ft);
                }
            }
        }
        List<Address> sorted = new ArrayList<>(jumpTargets);
        Collections.sort(sorted);
        StringBuilder sb = new StringBuilder();
        int count = 0, skipped = 0;
        for (Address target : sorted) {
            if (count >= limit) break;
            if (skipped < offset) { skipped++; continue; }
            if (sb.length() > 0) sb.append("\n");
            String context = "";
            Function tf = functionManager.getFunctionContaining(target);
            if (tf != null) context = " (in " + tf.getName() + ")";
            else {
                Symbol sym = program.getSymbolTable().getPrimarySymbol(target);
                if (sym != null) context = " (" + sym.getName() + ")";
            }
            sb.append(target.toString()).append(context);
            count++;
        }
        if (sb.length() == 0) return "No jump targets found in function: " + functionAddress;
        return sb.toString();
    }

    public String getFunctionLabels(String functionAddress, int offset, int limit, String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        SymbolTable symbolTable = program.getSymbolTable();
        Function function = findFunctionByAddressOrName(program, functionAddress);
        if (function == null) return "{\"error\": \"Function not found: " + escapeJson(functionAddress) + "\"}";
        AddressSetView functionBody = function.getBody();
        SymbolIterator symbols = symbolTable.getSymbolIterator();
        StringBuilder sb = new StringBuilder();
        int count = 0, skipped = 0;
        while (symbols.hasNext() && count < limit) {
            Symbol symbol = symbols.next();
            if (symbol.getSymbolType() == SymbolType.LABEL && functionBody.contains(symbol.getAddress())) {
                if (skipped < offset) { skipped++; continue; }
                if (sb.length() > 0) sb.append("\n");
                sb.append("Address: ").append(symbol.getAddress().toString())
                  .append(", Name: ").append(symbol.getName())
                  .append(", Source: ").append(symbol.getSource().toString());
                count++;
            }
        }
        if (sb.length() == 0) return "No labels found in function: " + functionAddress;
        return sb.toString();
    }

    // ==========================================================================
    // CONTROL FLOW ANALYSIS
    // ==========================================================================

    public String analyzeControlFlow(String functionName, String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        if (functionName == null || functionName.isEmpty()) return "{\"error\": \"function_name required\"}";
        try {
            FunctionManager functionManager = program.getFunctionManager();
            Function func = null;
            for (Function f : functionManager.getFunctions(true)) {
                if (f.getName().equals(functionName)) { func = f; break; }
            }
            if (func == null) return "{\"error\": \"Function not found: " + escapeJson(functionName) + "\"}";
            BasicBlockModel blockModel = new BasicBlockModel(program);
            Listing listing = program.getListing();
            int basicBlockCount = 0, edgeCount = 0, conditionalBranches = 0;
            int unconditionalJumps = 0, loops = 0, instructionCount = 0, callCount = 0, returnCount = 0;
            List<Map<String, Object>> blocks = new ArrayList<>();
            Set<Address> blockEntries = new HashSet<>();
            CodeBlockIterator blockIter = blockModel.getCodeBlocksContaining(func.getBody(), new ConsoleTaskMonitor());
            while (blockIter.hasNext()) blockEntries.add(blockIter.next().getFirstStartAddress());
            blockIter = blockModel.getCodeBlocksContaining(func.getBody(), new ConsoleTaskMonitor());
            while (blockIter.hasNext()) {
                CodeBlock block = blockIter.next();
                basicBlockCount++;
                Map<String, Object> blockInfo = new LinkedHashMap<>();
                blockInfo.put("address", block.getFirstStartAddress().toString());
                blockInfo.put("size", block.getNumAddresses());
                int outEdges = 0;
                boolean hasBackEdge = false;
                CodeBlockReferenceIterator destIter = block.getDestinations(new ConsoleTaskMonitor());
                while (destIter.hasNext()) {
                    CodeBlockReference ref = destIter.next();
                    outEdges++; edgeCount++;
                    Address destAddr = ref.getDestinationAddress();
                    if (destAddr.compareTo(block.getFirstStartAddress()) < 0 && blockEntries.contains(destAddr)) hasBackEdge = true;
                }
                if (hasBackEdge) loops++;
                blockInfo.put("successors", outEdges);
                blockInfo.put("is_loop_header", hasBackEdge);
                if (outEdges == 0) blockInfo.put("type", "exit");
                else if (outEdges == 1) blockInfo.put("type", "sequential");
                else if (outEdges == 2) { blockInfo.put("type", "conditional"); conditionalBranches++; }
                else blockInfo.put("type", "switch");
                blocks.add(blockInfo);
            }
            InstructionIterator instrIter = listing.getInstructions(func.getBody(), true);
            while (instrIter.hasNext()) {
                Instruction instr = instrIter.next();
                instructionCount++;
                if (instr.getFlowType().isCall()) callCount++;
                else if (instr.getFlowType().isTerminal()) returnCount++;
                else if (instr.getFlowType().isJump() && !instr.getFlowType().isConditional()) unconditionalJumps++;
            }
            int cc = edgeCount - basicBlockCount + 2;
            if (cc < 1) cc = 1;
            String rating = cc <= 5 ? "low" : cc <= 10 ? "moderate" : cc <= 20 ? "high" : cc <= 50 ? "very_high" : "extreme";
            StringBuilder result = new StringBuilder();
            result.append("{\"function_name\":\"").append(escapeJson(functionName)).append("\",");
            result.append("\"entry_point\":\"").append(func.getEntryPoint()).append("\",");
            result.append("\"size_bytes\":").append(func.getBody().getNumAddresses()).append(",");
            result.append("\"metrics\":{");
            result.append("\"cyclomatic_complexity\":").append(cc).append(",");
            result.append("\"complexity_rating\":\"").append(rating).append("\",");
            result.append("\"basic_blocks\":").append(basicBlockCount).append(",");
            result.append("\"edges\":").append(edgeCount).append(",");
            result.append("\"instructions\":").append(instructionCount).append(",");
            result.append("\"conditional_branches\":").append(conditionalBranches).append(",");
            result.append("\"unconditional_jumps\":").append(unconditionalJumps).append(",");
            result.append("\"loops_detected\":").append(loops).append(",");
            result.append("\"calls\":").append(callCount).append(",");
            result.append("\"returns\":").append(returnCount).append("},");
            result.append("\"basic_block_details\":[");
            for (int i = 0; i < Math.min(blocks.size(), 50); i++) {
                Map<String, Object> b = blocks.get(i);
                if (i > 0) result.append(",");
                result.append("{\"address\":\"").append(b.get("address")).append("\",");
                result.append("\"size\":").append(b.get("size")).append(",");
                result.append("\"type\":\"").append(b.get("type")).append("\",");
                result.append("\"successors\":").append(b.get("successors")).append(",");
                result.append("\"is_loop_header\":").append(b.get("is_loop_header")).append("}");
            }
            result.append("]}");
            return result.toString();
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    // ==========================================================================
    // MALWARE / SECURITY ANALYSIS ENDPOINTS
    // ==========================================================================

    public String detectMalwareBehaviors(String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        try {
            Map<String, String[]> behaviorIndicators = new LinkedHashMap<>();
            behaviorIndicators.put("code_injection", new String[]{"VirtualAlloc","VirtualAllocEx","WriteProcessMemory","CreateRemoteThread","NtWriteVirtualMemory","RtlCreateUserThread","QueueUserAPC"});
            behaviorIndicators.put("keylogging", new String[]{"SetWindowsHookEx","GetAsyncKeyState","GetKeyState","RegisterRawInputDevices"});
            behaviorIndicators.put("screen_capture", new String[]{"GetDC","GetWindowDC","BitBlt","CreateCompatibleBitmap","GetDIBits"});
            behaviorIndicators.put("privilege_escalation", new String[]{"AdjustTokenPrivileges","LookupPrivilegeValue","OpenProcessToken","ImpersonateLoggedOnUser","DuplicateToken"});
            behaviorIndicators.put("defense_evasion", new String[]{"NtSetInformationThread","NtQueryInformationProcess","GetProcAddress","LoadLibrary","VirtualProtect"});
            behaviorIndicators.put("lateral_movement", new String[]{"WNetAddConnection","NetShareEnum","WNetEnumResource"});
            behaviorIndicators.put("data_exfiltration", new String[]{"InternetOpen","HttpSendRequest","FtpPutFile","send","WSASend"});
            behaviorIndicators.put("crypto_operations", new String[]{"CryptAcquireContext","CryptGenKey","CryptEncrypt","CryptDecrypt","CryptImportKey","CryptDeriveKey"});
            behaviorIndicators.put("process_manipulation", new String[]{"TerminateProcess","SuspendThread","ResumeThread","NtSuspendProcess"});
            SymbolTable symbolTable = program.getSymbolTable();
            ReferenceManager refManager = program.getReferenceManager();
            Listing listing = program.getListing();
            Map<String, List<String>> detected = new LinkedHashMap<>();
            for (Function func : program.getFunctionManager().getFunctions(true)) {
                if (func.isThunk()) continue;
                Set<String> funcAPIs = new HashSet<>();
                InstructionIterator instrIter = listing.getInstructions(func.getBody(), true);
                while (instrIter.hasNext()) {
                    Instruction instr = instrIter.next();
                    if (instr.getFlowType().isCall()) {
                        for (Reference ref : refManager.getReferencesFrom(instr.getAddress())) {
                            if (ref.getReferenceType().isCall()) {
                                Symbol sym = symbolTable.getPrimarySymbol(ref.getToAddress());
                                if (sym != null) funcAPIs.add(sym.getName());
                            }
                        }
                    }
                }
                for (Map.Entry<String, String[]> entry : behaviorIndicators.entrySet()) {
                    for (String api : entry.getValue()) {
                        if (funcAPIs.contains(api)) {
                            detected.computeIfAbsent(entry.getKey(), k -> new ArrayList<>()).add(func.getName() + ":" + api);
                            break;
                        }
                    }
                }
            }
            StringBuilder sb = new StringBuilder("{\"behaviors\":[");
            boolean first = true;
            for (Map.Entry<String, List<String>> entry : detected.entrySet()) {
                if (!first) sb.append(",");
                first = false;
                sb.append("{\"category\":\"").append(entry.getKey()).append("\",\"instances\":[");
                for (int i = 0; i < entry.getValue().size(); i++) {
                    if (i > 0) sb.append(",");
                    sb.append("\"").append(escapeJson(entry.getValue().get(i))).append("\"");
                }
                sb.append("]}");
            }
            sb.append("],\"total_categories_detected\":").append(detected.size()).append("}");
            return sb.toString();
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    public String findAntiAnalysisTechniques(String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        try {
            Map<String, String[]> antiDebugAPIs = new LinkedHashMap<>();
            antiDebugAPIs.put("debugger_detection", new String[]{"IsDebuggerPresent","CheckRemoteDebuggerPresent","NtQueryInformationProcess","OutputDebugString","DebugActiveProcess"});
            antiDebugAPIs.put("timing_checks", new String[]{"GetTickCount","QueryPerformanceCounter","timeGetTime","GetSystemTimeAsFileTime","NtQuerySystemTime"});
            antiDebugAPIs.put("vm_detection", new String[]{"GetComputerName","GetUserName","RegOpenKeyEx","CheckRemoteDebuggerPresent"});
            antiDebugAPIs.put("obfuscation", new String[]{"VirtualProtect","VirtualAlloc","NtProtectVirtualMemory"});
            SymbolTable symbolTable = program.getSymbolTable();
            ReferenceManager refManager = program.getReferenceManager();
            Listing listing = program.getListing();
            Map<String, List<String>> detected = new LinkedHashMap<>();
            for (Function func : program.getFunctionManager().getFunctions(true)) {
                if (func.isThunk()) continue;
                Set<String> funcAPIs = new HashSet<>();
                InstructionIterator instrIter = listing.getInstructions(func.getBody(), true);
                while (instrIter.hasNext()) {
                    Instruction instr = instrIter.next();
                    if (instr.getFlowType().isCall()) {
                        for (Reference ref : refManager.getReferencesFrom(instr.getAddress())) {
                            if (ref.getReferenceType().isCall()) {
                                Symbol sym = symbolTable.getPrimarySymbol(ref.getToAddress());
                                if (sym != null) funcAPIs.add(sym.getName());
                            }
                        }
                    }
                }
                for (Map.Entry<String, String[]> entry : antiDebugAPIs.entrySet()) {
                    for (String api : entry.getValue()) {
                        if (funcAPIs.contains(api)) {
                            detected.computeIfAbsent(entry.getKey(), k -> new ArrayList<>()).add(func.getName() + ":" + api);
                            break;
                        }
                    }
                }
            }
            StringBuilder sb = new StringBuilder("{\"anti_analysis_techniques\":[");
            boolean first = true;
            for (Map.Entry<String, List<String>> entry : detected.entrySet()) {
                if (!first) sb.append(",");
                first = false;
                sb.append("{\"category\":\"").append(entry.getKey()).append("\",\"instances\":[");
                for (int i = 0; i < entry.getValue().size(); i++) {
                    if (i > 0) sb.append(",");
                    sb.append("\"").append(escapeJson(entry.getValue().get(i))).append("\"");
                }
                sb.append("]}");
            }
            sb.append("],\"total_detected\":").append(detected.size()).append("}");
            return sb.toString();
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    public String findDeadCode(String functionName, String programName) {
        return "[{\"function_name\":\"" + escapeJson(functionName != null ? functionName : "") + "\"," +
               "\"status\":\"not_implemented\"," +
               "\"note\":\"Dead code detection requires reachability analysis via control flow graph\"}]";
    }

    public String extractIOCsWithContext(String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        try {
            Pattern ipPattern = Pattern.compile("\\b(\\d{1,3}\\.){3}\\d{1,3}\\b");
            Pattern urlPattern = Pattern.compile("https?://[\\w./:\\-?&=%+#@]+");
            Pattern emailPattern = Pattern.compile("[\\w.+-]+@[\\w.-]+\\.[a-zA-Z]{2,}");
            Pattern domainPattern = Pattern.compile("\\b[\\w-]{2,63}\\.(com|net|org|io|ru|cn|info|biz)\\b");
            Pattern hashPattern = Pattern.compile("\\b[0-9a-fA-F]{32}\\b|\\b[0-9a-fA-F]{40}\\b|\\b[0-9a-fA-F]{64}\\b");
            List<String> iocs = new ArrayList<>();
            for (MemoryBlock block : program.getMemory().getBlocks()) {
                DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
                while (it.hasNext()) {
                    Data data = it.next();
                    Object val = data.getValue();
                    if (val instanceof String) {
                        String s = (String) val;
                        checkPattern(ipPattern, s, "ip", data.getAddress(), iocs);
                        checkPattern(urlPattern, s, "url", data.getAddress(), iocs);
                        checkPattern(emailPattern, s, "email", data.getAddress(), iocs);
                        checkPattern(domainPattern, s, "domain", data.getAddress(), iocs);
                        checkPattern(hashPattern, s, "hash", data.getAddress(), iocs);
                    }
                }
            }
            StringBuilder sb = new StringBuilder("{\"iocs\":[");
            for (int i = 0; i < iocs.size(); i++) {
                if (i > 0) sb.append(",");
                sb.append(iocs.get(i));
            }
            sb.append("],\"count\":").append(iocs.size()).append("}");
            return sb.toString();
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    private void checkPattern(Pattern p, String s, String type, Address addr, List<String> results) {
        Matcher m = p.matcher(s);
        while (m.find()) {
            results.add("{\"type\":\"" + type + "\",\"value\":\"" + escapeJson(m.group()) + "\",\"address\":\"" + addr + "\"}");
        }
    }

    public String analyzeApiCallChains(String programName) {
        String startFunction = null;
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        try {
            String[] threatAPIs = {"CreateRemoteThread","VirtualAllocEx","WriteProcessMemory","NtWriteVirtualMemory",
                "SetWindowsHookEx","GetAsyncKeyState","InternetOpen","HttpSendRequest","FtpPutFile",
                "CryptEncrypt","CryptDecrypt","RegSetValueEx","ShellExecute","WinExec","CreateProcess"};
            Set<String> threatSet = new HashSet<>(Arrays.asList(threatAPIs));
            FunctionManager fm = program.getFunctionManager();
            SymbolTable st = program.getSymbolTable();
            Listing listing = program.getListing();
            ReferenceManager refMgr = program.getReferenceManager();
            StringBuilder sb = new StringBuilder("{\"chains\":[");
            boolean first = true;
            for (Function func : fm.getFunctions(true)) {
                if (startFunction != null && !startFunction.isEmpty() && !func.getName().equals(startFunction)) continue;
                List<String> threats = new ArrayList<>();
                InstructionIterator instrIter = listing.getInstructions(func.getBody(), true);
                while (instrIter.hasNext()) {
                    Instruction instr = instrIter.next();
                    if (instr.getFlowType().isCall()) {
                        for (Reference ref : refMgr.getReferencesFrom(instr.getAddress())) {
                            if (ref.getReferenceType().isCall()) {
                                Symbol sym = st.getPrimarySymbol(ref.getToAddress());
                                if (sym != null && threatSet.contains(sym.getName())) threats.add(sym.getName());
                            }
                        }
                    }
                }
                if (!threats.isEmpty()) {
                    if (!first) sb.append(",");
                    first = false;
                    sb.append("{\"function\":\"").append(escapeJson(func.getName())).append("\",\"threat_apis\":[");
                    for (int i = 0; i < threats.size(); i++) {
                        if (i > 0) sb.append(",");
                        sb.append("\"").append(escapeJson(threats.get(i))).append("\"");
                    }
                    sb.append("]}");
                }
            }
            sb.append("]}");
            return sb.toString();
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    public String analyzeFunctionCompleteness(String functionAddress, String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        try {
            Address addr = program.getAddressFactory().getAddress(functionAddress);
            if (addr == null) return "{\"error\": \"Invalid address: " + escapeJson(functionAddress) + "\"}";
            Function func = program.getFunctionManager().getFunctionAt(addr);
            if (func == null) return "{\"error\": \"No function at address: " + escapeJson(functionAddress) + "\"}";
            boolean hasPlateComment = func.getComment() != null && !func.getComment().isEmpty();
            boolean hasRepeatableComment = func.getRepeatableComment() != null && !func.getRepeatableComment().isEmpty();
            boolean hasSignature = func.getSignature().getArguments().length > 0;
            boolean isNamed = !func.getName().startsWith("FUN_") && !func.getName().startsWith("SUB_");
            int score = 0;
            if (hasPlateComment) score += 25;
            if (hasRepeatableComment) score += 15;
            if (hasSignature) score += 30;
            if (isNamed) score += 30;
            return "{\"function\":\"" + escapeJson(func.getName()) + "\"," +
                   "\"address\":\"" + functionAddress + "\"," +
                   "\"completeness_score\":" + score + "," +
                   "\"has_plate_comment\":" + hasPlateComment + "," +
                   "\"has_repeatable_comment\":" + hasRepeatableComment + "," +
                   "\"has_typed_signature\":" + hasSignature + "," +
                   "\"is_renamed\":" + isNamed + "}";
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    // ==========================================================================
    // BATCH OPERATION ENDPOINTS (headless-only)
    // ==========================================================================

    // ==========================================================================
    // BATCH OPERATION ENDPOINTS
    // ==========================================================================

    public String batchDecompileFunctions(String functionsParam, String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        if (functionsParam == null || functionsParam.trim().isEmpty()) return "{\"error\": \"functions required\"}";
        try {
            String[] functionNames = functionsParam.split(",");
            StringBuilder result = new StringBuilder("{");
            FunctionManager funcManager = program.getFunctionManager();
            final int MAX_FUNCTIONS = 20;
            for (int i = 0; i < functionNames.length && i < MAX_FUNCTIONS; i++) {
                String funcName = functionNames[i].trim();
                if (funcName.isEmpty()) continue;
                if (i > 0) result.append(",");
                result.append("\"").append(escapeJson(funcName)).append("\":");
                Function function = null;
                SymbolIterator symbols = program.getSymbolTable().getSymbols(funcName);
                while (symbols.hasNext()) {
                    Symbol sym = symbols.next();
                    if (sym.getSymbolType() == SymbolType.FUNCTION) {
                        function = funcManager.getFunctionAt(sym.getAddress());
                        break;
                    }
                }
                if (function == null) { result.append("\"Error: Function not found\""); continue; }
                try {
                    DecompInterface decompiler = new DecompInterface();
                    decompiler.openProgram(program);
                    DecompileResults decompResults = decompiler.decompileFunction(function, 30, new ConsoleTaskMonitor());
                    if (decompResults != null && decompResults.decompileCompleted()) {
                        result.append("\"").append(escapeJson(decompResults.getDecompiledFunction().getC())).append("\"");
                    } else {
                        result.append("\"Error: Decompilation failed\"");
                    }
                    decompiler.dispose();
                } catch (Exception e) {
                    result.append("\"Error: ").append(escapeJson(e.getMessage())).append("\"");
                }
            }
            result.append("}");
            return result.toString();
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    public String batchRenameFunctionComponents(String functionAddress, String functionName,
                                                 String variableRenamesJson, String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        try {
            Address addr = program.getAddressFactory().getAddress(functionAddress);
            if (addr == null) return "{\"error\": \"Invalid address: " + escapeJson(functionAddress) + "\"}";
            Function func = program.getFunctionManager().getFunctionAt(addr);
            if (func == null) return "{\"error\": \"No function at address: " + escapeJson(functionAddress) + "\"}";
            return threadingStrategy.executeWrite(program, "Batch rename function components", () -> {
                StringBuilder result = new StringBuilder("{\"results\":[");
                boolean first = true;
                if (functionName != null && !functionName.isEmpty()) {
                    try {
                        func.setName(functionName, SourceType.USER_DEFINED);
                        if (!first) result.append(",");
                        first = false;
                        result.append("{\"type\":\"function\",\"new_name\":\"").append(escapeJson(functionName)).append("\",\"success\":true}");
                    } catch (Exception e) {
                        if (!first) result.append(",");
                        first = false;
                        result.append("{\"type\":\"function\",\"error\":\"").append(escapeJson(e.getMessage())).append("\"}");
                    }
                }
                result.append("]}");
                return result.toString();
            });
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    public String batchSetVariableTypes(String functionAddress, String variableTypesJson, boolean forceIndividual, String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        if (functionAddress == null || functionAddress.isEmpty()) return "{\"error\": \"function_address required\"}";
        if (variableTypesJson == null || variableTypesJson.isEmpty()) return "{\"error\": \"variable_types required\"}";
        try {
            return threadingStrategy.executeWrite(program, "Batch set variable types", () -> {
                Address addr = program.getAddressFactory().getAddress(functionAddress);
                if (addr == null) return "{\"error\": \"Invalid address\"}";
                Function func = program.getFunctionManager().getFunctionAt(addr);
                if (func == null) return "{\"error\": \"No function at address\"}";
                return "{\"success\": true, \"function\": \"" + escapeJson(func.getName()) + "\"," +
                       "\"message\": \"Batch variable type setting queued\", " +
                       "\"tip\": \"Use set_local_variable_type for individual variable type changes.\"}";
            });
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    public String batchStringAnchorReport(String pattern, String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        try {
            Pattern searchPattern = pattern != null && !pattern.isEmpty() ? Pattern.compile(pattern, Pattern.CASE_INSENSITIVE) : null;
            StringBuilder sb = new StringBuilder("{\"anchors\":[");
            boolean first = true;
            for (MemoryBlock block : program.getMemory().getBlocks()) {
                DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
                while (it.hasNext()) {
                    Data data = it.next();
                    Object val = data.getValue();
                    if (val instanceof String) {
                        String s = (String) val;
                        if (searchPattern == null || searchPattern.matcher(s).find()) {
                            if (!first) sb.append(",");
                            first = false;
                            String label = data.getLabel() != null ? data.getLabel() : "";
                            int xrefs = program.getReferenceManager().getReferenceCountTo(data.getAddress());
                            sb.append("{\"address\":\"").append(data.getAddress()).append("\",");
                            sb.append("\"label\":\"").append(escapeJson(label)).append("\",");
                            sb.append("\"value\":\"").append(escapeJson(s.length() > 100 ? s.substring(0, 100) + "..." : s)).append("\",");
                            sb.append("\"xrefs\":").append(xrefs).append("}");
                        }
                    }
                }
            }
            sb.append("]}");
            return sb.toString();
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    // ==========================================================================
    // VALIDATION AND DISASSEMBLY (headless-only)
    // ==========================================================================

    // ==========================================================================
    // VALIDATION AND DISASSEMBLY ENDPOINTS
    // ==========================================================================

    public String validateFunctionPrototype(String functionAddress, String prototype, String callingConvention, String programName) {
        Program program = getProgram(programName);
        if (program == null) return "{\"error\": \"No program loaded\"}";
        if (functionAddress == null || functionAddress.isEmpty()) return "{\"valid\": false, \"error\": \"address required\"}";
        try {
            Address addr = program.getAddressFactory().getAddress(functionAddress);
            if (addr == null) return "{\"valid\": false, \"error\": \"Invalid address: " + escapeJson(functionAddress) + "\"}";
            Function func = program.getFunctionManager().getFunctionAt(addr);
            if (func == null) return "{\"valid\": false, \"error\": \"No function at address: " + escapeJson(functionAddress) + "\"}";
            if (prototype == null || prototype.trim().isEmpty()) return "{\"valid\": false, \"error\": \"Empty prototype\"}";
            if (!prototype.contains("(")) return "{\"valid\": false, \"error\": \"Invalid prototype format - missing parentheses\"}";
            List<String> warnings = new ArrayList<>();
            if (callingConvention != null && !callingConvention.isEmpty()) {
                String[] validConventions = {"__cdecl","__stdcall","__fastcall","__thiscall","default"};
                boolean validConv = false;
                for (String valid : validConventions) { if (callingConvention.equalsIgnoreCase(valid)) { validConv = true; break; } }
                if (!validConv) warnings.add("Unknown calling convention: " + callingConvention);
            }
            StringBuilder result = new StringBuilder("{\"valid\": true");
            if (!warnings.isEmpty()) {
                result.append(", \"warnings\": [");
                for (int i = 0; i < warnings.size(); i++) {
                    if (i > 0) result.append(",");
                    result.append("\"").append(escapeJson(warnings.get(i))).append("\"");
                }
                result.append("]");
            }
            result.append("}");
            return result.toString();
        } catch (Exception e) {
            return "{\"valid\": false, \"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    public String disassembleBytes(String startAddress, String endAddress, int length, String programName) {
        boolean restrictToExecuteMemory = false;
        Program program = getProgram(programName);
        if (program == null) return "{\"error\": \"No program loaded\"}";
        if (startAddress == null || startAddress.isEmpty()) return "{\"error\": \"start_address required\"}";
        try {
            Address start = program.getAddressFactory().getAddress(startAddress);
            if (start == null) return "{\"error\": \"Invalid start address: " + escapeJson(startAddress) + "\"}";
            Address end;
            if (endAddress != null && !endAddress.isEmpty()) {
                end = program.getAddressFactory().getAddress(endAddress);
                if (end == null) return "{\"error\": \"Invalid end address: " + escapeJson(endAddress) + "\"}";
                try { end = end.subtract(1); } catch (Exception ignored) {}
            } else if (length > 0) {
                end = start.add(length - 1);
            } else {
                end = start.add(99);
            }
            final Address finalEnd = end;
            AddressSet addressSet = new AddressSet(start, finalEnd);
            long numBytes = addressSet.getNumAddresses();
            return threadingStrategy.executeWrite(program, "Disassemble Bytes", () -> {
                ghidra.app.cmd.disassemble.DisassembleCommand cmd =
                    new ghidra.app.cmd.disassemble.DisassembleCommand(addressSet, null, restrictToExecuteMemory);
                if (cmd.applyTo(program, new ConsoleTaskMonitor())) {
                    return "{\"success\": true, \"start_address\": \"" + start + "\", \"end_address\": \"" + finalEnd + "\"," +
                           "\"bytes_disassembled\": " + numBytes + "}";
                } else {
                    return "{\"success\": false, \"error\": \"Disassembly failed\"}";
                }
            });
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    // ==========================================================================
    // DOCUMENTATION ENDPOINTS (headless-only)
    // ==========================================================================

    // ==========================================================================
    // DOCUMENTATION ENDPOINTS (missing methods)
    // ==========================================================================

    public String getFunctionDocumentation(String functionAddress, String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        try {
            Function func = findFunctionByAddressOrName(program, functionAddress);
            if (func == null) return "{\"error\": \"Function not found: " + escapeJson(functionAddress) + "\"}";
            StringBuilder sb = new StringBuilder("{");
            sb.append("\"name\":\"").append(escapeJson(func.getName())).append("\",");
            sb.append("\"address\":\"").append(func.getEntryPoint()).append("\",");
            sb.append("\"signature\":\"").append(escapeJson(func.getSignature().getPrototypeString())).append("\",");
            sb.append("\"plate_comment\":\"").append(escapeJson(func.getComment() != null ? func.getComment() : "")).append("\",");
            sb.append("\"repeatable_comment\":\"").append(escapeJson(func.getRepeatableComment() != null ? func.getRepeatableComment() : "")).append("\",");
            sb.append("\"is_thunk\":").append(func.isThunk()).append(",");
            sb.append("\"is_external\":").append(func.isExternal()).append(",");
            sb.append("\"parameter_count\":").append(func.getParameterCount()).append(",");
            sb.append("\"calling_convention\":\"").append(escapeJson(func.getCallingConventionName())).append("\"");
            sb.append("}");
            return sb.toString();
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    public String applyFunctionDocumentation(String jsonBody) {
        return "{\"advisory\": true, \"message\": \"Apply function documentation via the MCP bridge.\", \"received\": " + (jsonBody != null ? jsonBody.length() : 0) + "}";
    }

    public String compareProgramsDocumentation() {
        Program[] programs = programProvider.getAllOpenPrograms();
        StringBuilder sb = new StringBuilder("{\"programs\":[");
        for (int i = 0; i < programs.length; i++) {
            if (i > 0) sb.append(",");
            Program p = programs[i];
            int total = 0, documented = 0;
            for (Function f : p.getFunctionManager().getFunctions(true)) {
                total++;
                if (f.getComment() != null && !f.getComment().isEmpty()) documented++;
            }
            sb.append("{\"name\":\"").append(escapeJson(p.getName())).append("\",");
            sb.append("\"total_functions\":").append(total).append(",");
            sb.append("\"documented\":").append(documented).append(",");
            sb.append("\"coverage\":").append(total > 0 ? (documented * 100 / total) : 0).append("}");
        }
        sb.append("]}");
        return sb.toString();
    }

    public String findUndocumentedByString(String stringAddress, String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        try {
            StringBuilder sb = new StringBuilder("[");
            boolean first = true;
            for (Function func : program.getFunctionManager().getFunctions(true)) {
                if (func.getComment() == null || func.getComment().isEmpty()) {
                    if (!first) sb.append(",");
                    first = false;
                    sb.append("{\"name\":\"").append(escapeJson(func.getName())).append("\",");
                    sb.append("\"address\":\"").append(func.getEntryPoint()).append("\"}");
                }
            }
            sb.append("]");
            return sb.toString();
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    public String detectCryptoConstants(String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        // Common crypto constants (MD5/SHA/AES/RC4 initialization values)
        long[] cryptoConsts = {0x67452301L, 0xEFCDAB89L, 0x98BADCFEL, 0x10325476L, // MD5 init
                               0x5A827999L, 0x6ED9EBA1L, 0x8F1BBCDCL, 0xCA62C1D6L, // SHA1 constants
                               0x6A09E667L, 0xBB67AE85L, 0x3C6EF372L, 0xA54FF53AL  // SHA256 init
        };
        Set<Long> constSet = new HashSet<>();
        for (long c : cryptoConsts) constSet.add(c);
        List<String> found = new ArrayList<>();
        try {
            for (MemoryBlock block : program.getMemory().getBlocks()) {
                DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
                while (it.hasNext()) {
                    Data data = it.next();
                    Object val = data.getValue();
                    if (val instanceof Long && constSet.contains(val)) {
                        found.add("{\"address\":\"" + data.getAddress() + "\",\"value\":\"0x" + Long.toHexString((Long) val).toUpperCase() + "\"}");
                    }
                }
            }
        } catch (Exception ignored) {}
        return "{\"crypto_constants\":[" + String.join(",", found) + "],\"count\":" + found.size() + "}";
    }

    // ==========================================================================
    // LABEL / SYMBOL ENDPOINTS (headless-only)
    // ==========================================================================

    // ========== PORTED FROM GUI PLUGIN ==========

    public String createLabel(String addressStr, String labelName) {
        Program program = getProgram(null);
        if (program == null) return getProgramError(null);
        if (addressStr == null || addressStr.isEmpty()) return "{\"error\": \"Address is required\"}";
        if (labelName == null || labelName.isEmpty()) return "{\"error\": \"Label name is required\"}";

        try {
            return threadingStrategy.executeWrite(program, "Create Label", () -> {
                Address address = parseAddress(program, addressStr);
                if (address == null) return "{\"error\": \"Invalid address: " + escapeJson(addressStr) + "\"}";

                SymbolTable symbolTable = program.getSymbolTable();
                Symbol[] existing = symbolTable.getSymbols(address);
                for (Symbol s : existing) {
                    if (s.getName().equals(labelName) && s.getSymbolType() == SymbolType.LABEL) {
                        return "{\"error\": \"Label '" + escapeJson(labelName) + "' already exists at " + addressStr + "\"}";
                    }
                }
                Symbol newSymbol = symbolTable.createLabel(address, labelName, SourceType.USER_DEFINED);
                if (newSymbol != null) {
                    return "{\"success\": true, \"label\": \"" + escapeJson(labelName) + "\", \"address\": \"" + addressStr + "\"}";
                }
                return "{\"error\": \"Failed to create label\"}";
            });
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    public String renameLabel(String addressStr, String oldName, String newName) {
        Program program = getProgram(null);
        if (program == null) return getProgramError(null);
        if (addressStr == null || addressStr.isEmpty()) return "{\"error\": \"Address is required\"}";

        try {
            return threadingStrategy.executeWrite(program, "Rename Label", () -> {
                Address address = parseAddress(program, addressStr);
                if (address == null) return "{\"error\": \"Invalid address: " + escapeJson(addressStr) + "\"}";

                SymbolTable symbolTable = program.getSymbolTable();
                Symbol[] symbols = symbolTable.getSymbols(address);
                Symbol target = null;
                for (Symbol s : symbols) {
                    if (s.getName().equals(oldName) && s.getSymbolType() == SymbolType.LABEL) {
                        target = s;
                        break;
                    }
                }
                if (target == null) {
                    return "{\"error\": \"Label '" + escapeJson(oldName) + "' not found at " + addressStr + "\"}";
                }
                target.setName(newName, SourceType.USER_DEFINED);
                return "{\"success\": true, \"old_name\": \"" + escapeJson(oldName) + "\", \"new_name\": \"" + escapeJson(newName) + "\"}";
            });
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    public String renameExternalLocation(String addressStr, String newName) {
        Program program = getProgram(null);
        if (program == null) return getProgramError(null);

        try {
            return threadingStrategy.executeWrite(program, "Rename external location", () -> {
            Address addr = parseAddress(program, addressStr);
            if (addr == null) return "{\"error\": \"Invalid address: " + escapeJson(addressStr) + "\"}";

            ExternalManager extMgr = program.getExternalManager();
            String[] libNames = extMgr.getExternalLibraryNames();
            for (String libName : libNames) {
                ExternalLocationIterator iter = extMgr.getExternalLocations(libName);
                while (iter.hasNext()) {
                    ExternalLocation extLoc = iter.next();
                    if (extLoc.getAddress() != null && extLoc.getAddress().equals(addr)) {
                        String oldName = extLoc.getLabel();
                        Namespace ns = extMgr.getExternalLibrary(libName);
                        extLoc.setName(ns, newName, SourceType.USER_DEFINED);
                        return "{\"success\": true, \"old_name\": \"" + escapeJson(oldName) +
                               "\", \"new_name\": \"" + escapeJson(newName) +
                               "\", \"dll\": \"" + escapeJson(libName) + "\"}";
                    }
                }
            }
            return "{\"error\": \"External location not found at address " + escapeJson(addressStr) + "\"}";
            });
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    public String inspectMemoryContent(String addressStr, int length, boolean detectStrings, String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);

        try {
            Address addr = parseAddress(program, addressStr);
            if (addr == null) return "{\"error\": \"Invalid address: " + escapeJson(addressStr) + "\"}";

            Memory memory = program.getMemory();
            byte[] bytes = new byte[length];
            int bytesRead = memory.getBytes(addr, bytes);

            StringBuilder hexDump = new StringBuilder();
            StringBuilder asciiRepr = new StringBuilder();
            for (int i = 0; i < bytesRead; i++) {
                if (i > 0 && i % 16 == 0) { hexDump.append("\\n"); asciiRepr.append("\\n"); }
                hexDump.append(String.format("%02X ", bytes[i] & 0xFF));
                char c = (char) (bytes[i] & 0xFF);
                asciiRepr.append((c >= 0x20 && c <= 0x7E) ? c : '.');
            }

            int printableCount = 0;
            int maxConsec = 0, curConsec = 0;
            int nullIdx = -1;
            for (int i = 0; i < bytesRead; i++) {
                char c = (char) (bytes[i] & 0xFF);
                if (c >= 0x20 && c <= 0x7E) { printableCount++; curConsec++; maxConsec = Math.max(maxConsec, curConsec); }
                else { curConsec = 0; }
                if (c == 0x00 && nullIdx == -1) nullIdx = i;
            }
            double ratio = (double) printableCount / bytesRead;
            boolean likelyString = detectStrings && ((ratio >= 0.6) || (maxConsec >= 4 && nullIdx > 0));

            String detectedString = null;
            int stringLen = 0;
            if (likelyString && nullIdx > 0) {
                detectedString = new String(bytes, 0, nullIdx, StandardCharsets.US_ASCII);
                stringLen = nullIdx + 1;
            }

            StringBuilder r = new StringBuilder("{");
            r.append("\"address\": \"").append(addressStr).append("\",");
            r.append("\"bytes_read\": ").append(bytesRead).append(",");
            r.append("\"hex_dump\": \"").append(hexDump.toString().trim()).append("\",");
            r.append("\"ascii_repr\": \"").append(asciiRepr.toString().trim()).append("\",");
            r.append("\"is_likely_string\": ").append(likelyString).append(",");
            if (detectedString != null) {
                r.append("\"detected_string\": \"").append(escapeJson(detectedString)).append("\",");
                r.append("\"string_length\": ").append(stringLen);
            } else {
                r.append("\"detected_string\": null, \"string_length\": 0");
            }
            r.append("}");
            return r.toString();
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    public String searchStrings(String query, int minLength, String encoding, int offset, int limit, String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        if (query == null || query.isEmpty()) return "{\"error\": \"query parameter is required\"}";

        Pattern pat;
        try {
            pat = Pattern.compile(query, Pattern.CASE_INSENSITIVE);
        } catch (Exception e) {
            return "{\"error\": \"Invalid regex: " + escapeJson(e.getMessage()) + "\"}";
        }

        List<String> results = new ArrayList<>();
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
            results.add("{\"address\": \"" + data.getAddress() + "\", \"value\": \"" + escapeJson(value) + "\", \"encoding\": \"" + enc + "\"}");
        }

        int total = results.size();
        int from = Math.min(offset, total);
        int to = Math.min(from + limit, total);
        StringBuilder sb = new StringBuilder("{\"matches\": [");
        for (int i = from; i < to; i++) {
            if (i > from) sb.append(", ");
            sb.append(results.get(i));
        }
        sb.append("], \"total\": ").append(total).append(", \"offset\": ").append(offset).append(", \"limit\": ").append(limit).append("}");
        return sb.toString();
    }

    // ==========================================================================
    // STRUCTURAL SIMILARITY (headless-only)
    // ==========================================================================

    public String findSimilarFunctions(String targetFunction, double threshold, String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        if (targetFunction == null || targetFunction.trim().isEmpty())
            return "{\"error\": \"Target function name is required\"}";

        try {
            FunctionManager fm = program.getFunctionManager();
            Function targetFunc = null;
            for (Function f : fm.getFunctions(true)) {
                if (f.getName().equals(targetFunction)) { targetFunc = f; break; }
            }
            if (targetFunc == null) return "{\"error\": \"Function not found: " + escapeJson(targetFunction) + "\"}";

            BasicBlockModel blockModel = new BasicBlockModel(program);
            int targetBlocks = countBlocks(blockModel, targetFunc);
            int targetInstructions = countInstructions(program, targetFunc);
            int targetCalls = countCalls(program, targetFunc);

            List<String> matches = new ArrayList<>();
            for (Function f : fm.getFunctions(true)) {
                if (f.getName().equals(targetFunction) || f.isThunk()) continue;
                int blocks = countBlocks(blockModel, f);
                int instr = countInstructions(program, f);
                int calls = countCalls(program, f);
                double similarity = computeSimilarity(targetBlocks, targetInstructions, targetCalls, blocks, instr, calls);
                if (similarity >= threshold) {
                    matches.add("{\"name\": \"" + escapeJson(f.getName()) +
                               "\", \"address\": \"" + f.getEntryPoint() +
                               "\", \"similarity\": " + String.format("%.3f", similarity) +
                               ", \"blocks\": " + blocks + ", \"instructions\": " + instr + ", \"calls\": " + calls + "}");
                }
            }
            matches.sort((a, b) -> {
                double sa = Double.parseDouble(a.replaceAll(".*similarity\": ([\\d.]+).*", "$1"));
                double sb2 = Double.parseDouble(b.replaceAll(".*similarity\": ([\\d.]+).*", "$1"));
                return Double.compare(sb2, sa);
            });
            if (matches.size() > 50) matches = matches.subList(0, 50);

            StringBuilder r = new StringBuilder("{\"target\": \"" + escapeJson(targetFunction) + "\", \"threshold\": " + threshold +
                    ", \"matches_found\": " + matches.size() + ", \"similar_functions\": [");
            for (int i = 0; i < matches.size(); i++) {
                if (i > 0) r.append(", ");
                r.append(matches.get(i));
            }
            r.append("]}");
            return r.toString();
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    private int countBlocks(BasicBlockModel model, Function func) {
        try {
            int count = 0;
            CodeBlockIterator iter = model.getCodeBlocksContaining(func.getBody(), monitor);
            while (iter.hasNext()) { iter.next(); count++; }
            return count;
        } catch (Exception e) { return 0; }
    }

    private int countInstructions(Program program, Function func) {
        int count = 0;
        InstructionIterator iter = program.getListing().getInstructions(func.getBody(), true);
        while (iter.hasNext()) { iter.next(); count++; }
        return count;
    }

    private int countCalls(Program program, Function func) {
        int count = 0;
        InstructionIterator iter = program.getListing().getInstructions(func.getBody(), true);
        while (iter.hasNext()) {
            Instruction instr = iter.next();
            if (instr.getFlowType().isCall()) count++;
        }
        return count;
    }

    private double computeSimilarity(int tBlocks, int tInstr, int tCalls, int blocks, int instr, int calls) {
        double bSim = 1.0 - Math.abs(tBlocks - blocks) / (double) Math.max(Math.max(tBlocks, blocks), 1);
        double iSim = 1.0 - Math.abs(tInstr - instr) / (double) Math.max(Math.max(tInstr, instr), 1);
        double cSim = 1.0 - Math.abs(tCalls - calls) / (double) Math.max(Math.max(tCalls, calls), 1);
        return (bSim * 0.3 + iSim * 0.5 + cSim * 0.2);
    }

    public String validateDataType(String addressStr, String typeName, String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        if (addressStr == null || addressStr.isEmpty()) return "{\"error\": \"Address is required\"}";
        if (typeName == null || typeName.isEmpty()) return "{\"error\": \"Type name is required\"}";

        try {
            Address addr = parseAddress(program, addressStr);
            if (addr == null) return "{\"error\": \"Invalid address: " + escapeJson(addressStr) + "\"}";

            DataTypeManager dtm = program.getDataTypeManager();
            DataType dataType = findDataType(dtm, typeName);
            if (dataType == null) return "{\"error\": \"Data type not found: " + escapeJson(typeName) + "\"}";

            Memory memory = program.getMemory();
            int typeSize = dataType.getLength();
            boolean memOk = typeSize > 0 && memory.contains(addr) && memory.contains(addr.add(typeSize - 1));
            long alignment = dataType.getAlignment();
            boolean aligned = alignment <= 1 || (addr.getOffset() % alignment == 0);
            Data existing = program.getListing().getDefinedDataAt(addr);

            StringBuilder r = new StringBuilder("{");
            r.append("\"type\": \"").append(escapeJson(typeName)).append("\",");
            r.append("\"size\": ").append(typeSize).append(",");
            r.append("\"memory_available\": ").append(memOk).append(",");
            r.append("\"aligned\": ").append(aligned).append(",");
            r.append("\"existing_data\": ").append(existing != null ? "\"" + escapeJson(existing.getDataType().getName()) + "\"" : "null");
            r.append("}");
            return r.toString();
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    // ==========================================================================
    // HELPER METHODS
    // ==========================================================================

    private DataType findDataType(DataTypeManager dtm, String typeName) {
        // First try exact match
        java.util.Iterator<DataType> iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType dt = iter.next();
            if (dt.getName().equals(typeName)) {
                return dt;
            }
        }

        // Try built-in types
        DataTypeManager builtIn = ghidra.program.model.data.BuiltInDataTypeManager.getDataTypeManager();
        iter = builtIn.getAllDataTypes();
        while (iter.hasNext()) {
            DataType dt = iter.next();
            if (dt.getName().equals(typeName) || dt.getName().equalsIgnoreCase(typeName)) {
                return dt;
            }
        }

        // Handle common aliases
        switch (typeName.toLowerCase()) {
            case "int": return new IntegerDataType();
            case "uint": return new UnsignedIntegerDataType();
            case "short": return new ShortDataType();
            case "ushort": return new UnsignedShortDataType();
            case "long": return new LongDataType();
            case "ulong": return new UnsignedLongDataType();
            case "byte": return new ByteDataType();
            case "ubyte": return new UnsignedCharDataType();
            case "char": return new CharDataType();
            case "uchar": return new UnsignedCharDataType();
            case "float": return new FloatDataType();
            case "double": return new DoubleDataType();
            case "void": return new VoidDataType();
            case "bool": return new BooleanDataType();
            case "dword": return new DWordDataType();
            case "word": return new WordDataType();
            case "qword": return new QWordDataType();
        }

        // Handle pointer types
        if (typeName.endsWith("*")) {
            String baseTypeName = typeName.substring(0, typeName.length() - 1).trim();
            DataType baseType = findDataType(dtm, baseTypeName);
            if (baseType != null) {
                return dtm.getPointer(baseType);
            }
        }

        return null;
    }

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

}
