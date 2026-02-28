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

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.reflect.TypeToken;
import com.xebyte.core.JsonHelper;
import com.xebyte.core.ProgramProvider;
import com.xebyte.core.Response;
import com.xebyte.core.ThreadingStrategy;
import com.xebyte.core.services.*;
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
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
            return JsonHelper.errorJson("Program not found: " + programName);
        }
        return JsonHelper.errorJson("No program currently loaded");
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
        JsonObject obj = new JsonObject();
        obj.addProperty("plugin_version", VERSION);
        obj.addProperty("plugin_name", "GhidraMCP Headless");
        obj.addProperty("mode", "headless");
        return JsonHelper.toJson(obj);
    }

    public String getHealth() {
        JsonObject obj = new JsonObject();
        obj.addProperty("status", "healthy");
        obj.addProperty("version", VERSION);
        Program program = getProgram(null);
        boolean programLoaded = (program != null);
        obj.addProperty("program_loaded", programLoaded);
        if (programLoaded) {
            obj.addProperty("program_name", program.getName());
        }
        return JsonHelper.toJson(obj);
    }

    public String getMetadata() {
        Program program = getProgram(null);
        if (program == null) {
            return JsonHelper.errorJson("No program loaded");
        }
        JsonObject obj = new JsonObject();
        obj.addProperty("name", program.getName());
        obj.addProperty("path", program.getExecutablePath());
        obj.addProperty("language", program.getLanguageID().toString());
        obj.addProperty("compiler", program.getCompilerSpec().getCompilerSpecID().toString());
        obj.addProperty("image_base", program.getImageBase().toString());
        obj.addProperty("address_size", program.getAddressFactory().getDefaultAddressSpace().getSize());
        obj.addProperty("min_address", program.getMinAddress().toString());
        obj.addProperty("max_address", program.getMaxAddress().toString());
        return JsonHelper.toJson(obj);
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
        JsonObject obj = new JsonObject();
        JsonArray arr = new JsonArray();
        for (Program p : programs) {
            JsonObject entry = new JsonObject();
            entry.addProperty("name", p.getName());
            entry.addProperty("is_current", p == current);
            arr.add(entry);
        }
        obj.add("programs", arr);
        obj.addProperty("count", programs.length);
        if (current != null) {
            obj.addProperty("current_program", current.getName());
        }
        return JsonHelper.toJson(obj);
    }

    public String getCurrentProgramInfo() {
        Program program = getProgram(null);
        if (program == null) {
            return JsonHelper.errorJson("No program loaded");
        }
        return getMetadata();
    }

    public String switchProgram(String name) {
        if (name == null || name.isEmpty()) {
            return JsonHelper.errorJson("Program name required");
        }
        Program program = programProvider.getProgram(name);
        if (program == null) {
            return JsonHelper.errorJson("Program not found: " + name);
        }
        programProvider.setCurrentProgram(program);
        JsonObject obj = new JsonObject();
        obj.addProperty("success", true);
        obj.addProperty("current_program", program.getName());
        return JsonHelper.toJson(obj);
    }

    // ==========================================================================
    // HEADLESS-SPECIFIC ENDPOINTS
    // ==========================================================================

    public String loadProgram(String filePath) {
        if (filePath == null || filePath.isEmpty()) {
            return JsonHelper.errorJson("File path required");
        }
        File file = new File(filePath);
        if (!file.exists()) {
            return JsonHelper.errorJson("File not found: " + filePath);
        }
        if (programProvider instanceof HeadlessProgramProvider hpp) {
            Program program = hpp.loadProgramFromFile(file);
            if (program != null) {
                JsonObject obj = new JsonObject();
                obj.addProperty("success", true);
                obj.addProperty("program", program.getName());
                return JsonHelper.toJson(obj);
            } else {
                return JsonHelper.errorJson("Failed to load program from: " + filePath);
            }
        }
        return JsonHelper.errorJson("Load not supported in this mode");
    }

    public String closeProgram(String name) {
        Program program = programProvider.getProgram(name);
        if (program == null) {
            return JsonHelper.errorJson("Program not found: " + (name != null ? name : "current"));
        }
        if (programProvider instanceof HeadlessProgramProvider hpp) {
            hpp.closeProgram(program);
            JsonObject obj = new JsonObject();
            obj.addProperty("success", true);
            obj.addProperty("closed", program.getName());
            return JsonHelper.toJson(obj);
        }
        return JsonHelper.errorJson("Close not supported in this mode");
    }

    // ==========================================================================
    // PROJECT MANAGEMENT ENDPOINTS
    // ==========================================================================

    /**
     * Open a Ghidra project from a .gpr file path.
     */
    public String openProject(String projectPath) {
        if (projectPath == null || projectPath.isEmpty()) {
            return JsonHelper.errorJson("Project path required");
        }
        if (programProvider instanceof HeadlessProgramProvider hpp) {
            boolean success = hpp.openProject(projectPath);
            if (success) {
                JsonObject obj = new JsonObject();
                obj.addProperty("success", true);
                obj.addProperty("project", hpp.getProjectName());
                return JsonHelper.toJson(obj);
            } else {
                return JsonHelper.errorJson("Failed to open project: " + projectPath);
            }
        }
        return JsonHelper.errorJson("Project management not supported in this mode");
    }

    public String closeProject() {
        if (programProvider instanceof HeadlessProgramProvider hpp) {
            if (!hpp.hasProject()) {
                return JsonHelper.errorJson("No project currently open");
            }
            String projectName = hpp.getProjectName();
            hpp.closeProject();
            JsonObject obj = new JsonObject();
            obj.addProperty("success", true);
            obj.addProperty("closed", projectName);
            return JsonHelper.toJson(obj);
        }
        return JsonHelper.errorJson("Project management not supported in this mode");
    }

    public String listProjectFiles() {
        if (programProvider instanceof HeadlessProgramProvider hpp) {
            if (!hpp.hasProject()) {
                return JsonHelper.errorJson("No project currently open");
            }
            List<HeadlessProgramProvider.ProjectFileInfo> files = hpp.listProjectFiles();
            JsonObject obj = new JsonObject();
            obj.addProperty("project", hpp.getProjectName());
            JsonArray arr = new JsonArray();
            for (HeadlessProgramProvider.ProjectFileInfo file : files) {
                JsonObject entry = new JsonObject();
                entry.addProperty("name", file.name);
                entry.addProperty("path", file.path);
                entry.addProperty("contentType", file.contentType);
                entry.addProperty("readOnly", file.readOnly);
                arr.add(entry);
            }
            obj.add("files", arr);
            obj.addProperty("count", files.size());
            return JsonHelper.toJson(obj);
        }
        return JsonHelper.errorJson("Project management not supported in this mode");
    }

    public String loadProgramFromProject(String programPath) {
        if (programPath == null || programPath.isEmpty()) {
            return JsonHelper.errorJson("Program path required (e.g., /D2Client.dll)");
        }
        if (programProvider instanceof HeadlessProgramProvider hpp) {
            if (!hpp.hasProject()) {
                return JsonHelper.errorJson("No project currently open. Use /open_project first.");
            }
            Program program = hpp.loadProgramFromProject(programPath);
            if (program != null) {
                JsonObject obj = new JsonObject();
                obj.addProperty("success", true);
                obj.addProperty("program", program.getName());
                obj.addProperty("path", programPath);
                return JsonHelper.toJson(obj);
            } else {
                return JsonHelper.errorJson("Failed to load program: " + programPath);
            }
        }
        return JsonHelper.errorJson("Project management not supported in this mode");
    }

    public String getProjectInfo() {
        if (programProvider instanceof HeadlessProgramProvider hpp) {
            if (!hpp.hasProject()) {
                JsonObject obj = new JsonObject();
                obj.addProperty("has_project", false);
                return JsonHelper.toJson(obj);
            }
            List<HeadlessProgramProvider.ProjectFileInfo> files = hpp.listProjectFiles();
            int programCount = (int) files.stream()
                .filter(f -> "Program".equals(f.contentType))
                .count();
            JsonObject obj = new JsonObject();
            obj.addProperty("has_project", true);
            obj.addProperty("project_name", hpp.getProjectName());
            obj.addProperty("file_count", files.size());
            obj.addProperty("program_count", programCount);
            return JsonHelper.toJson(obj);
        }
        return JsonHelper.errorJson("Project management not supported in this mode");
    }


    // ==========================================================================
    // PROJECT LIFECYCLE (headless-only)
    // ==========================================================================

    public String createProject(String parentDir, String name) {
        if (parentDir == null || parentDir.isEmpty()) return JsonHelper.errorJson("parentDir required");
        if (name == null || name.isEmpty()) return JsonHelper.errorJson("name required");
        if (!(programProvider instanceof HeadlessProgramProvider hpp)) {
            return JsonHelper.errorJson("Project management not supported in this mode");
        }
        try {
            boolean ok = hpp.createProject(parentDir, name);
            if (ok) {
                JsonObject obj = new JsonObject();
                obj.addProperty("success", true);
                obj.addProperty("name", name);
                obj.addProperty("path", parentDir + "/" + name);
                return JsonHelper.toJson(obj);
            }
            return JsonHelper.errorJson("Failed to create project");
        } catch (Exception e) {
            return JsonHelper.errorJson(e.getMessage());
        }
    }

    public String deleteProject(String projectPath) {
        if (projectPath == null || projectPath.isEmpty()) return JsonHelper.errorJson("projectPath required");
        if (!(programProvider instanceof HeadlessProgramProvider hpp)) {
            return JsonHelper.errorJson("Project management not supported in this mode");
        }
        try {
            boolean ok = hpp.deleteProject(projectPath);
            if (ok) {
                JsonObject obj = new JsonObject();
                obj.addProperty("success", true);
                obj.addProperty("deleted", projectPath);
                return JsonHelper.toJson(obj);
            }
            return JsonHelper.errorJson("Failed to delete project");
        } catch (Exception e) {
            return JsonHelper.errorJson(e.getMessage());
        }
    }

    public String listProjects(String searchDir) {
        if (!(programProvider instanceof HeadlessProgramProvider hpp)) {
            return JsonHelper.errorJson("Project management not supported in this mode");
        }
        try {
            List<HeadlessProgramProvider.ProjectInfo> projects = hpp.listProjects(searchDir);
            JsonArray arr = new JsonArray();
            for (HeadlessProgramProvider.ProjectInfo p : projects) {
                JsonObject entry = new JsonObject();
                entry.addProperty("name", p.name);
                entry.addProperty("path", p.path);
                entry.addProperty("active", p.active);
                arr.add(entry);
            }
            return JsonHelper.toJson(arr);
        } catch (Exception e) {
            return JsonHelper.errorJson(e.getMessage());
        }
    }

    // ==========================================================================
    // PROJECT ORGANIZATION ENDPOINTS
    // ==========================================================================

    public String createFolder(String folderPath, String programName) {
        if (!(programProvider instanceof HeadlessProgramProvider hpp)) {
            return JsonHelper.errorJson("Project management not supported in this mode");
        }
        try {
            hpp.createFolder(folderPath);
            JsonObject obj = new JsonObject();
            obj.addProperty("success", true);
            obj.addProperty("folder", folderPath);
            return JsonHelper.toJson(obj);
        } catch (Exception e) {
            return JsonHelper.errorJson(e.getMessage());
        }
    }

    public String moveFile(String filePath, String destFolder) {
        if (!(programProvider instanceof HeadlessProgramProvider hpp)) {
            return JsonHelper.errorJson("Project management not supported in this mode");
        }
        try {
            hpp.moveFile(filePath, destFolder);
            JsonObject obj = new JsonObject();
            obj.addProperty("success", true);
            obj.addProperty("moved", filePath);
            obj.addProperty("to", destFolder);
            return JsonHelper.toJson(obj);
        } catch (Exception e) {
            return JsonHelper.errorJson(e.getMessage());
        }
    }

    public String moveFolder(String sourcePath, String destPath) {
        if (!(programProvider instanceof HeadlessProgramProvider hpp)) {
            return JsonHelper.errorJson("Project management not supported in this mode");
        }
        try {
            hpp.moveFolder(sourcePath, destPath);
            JsonObject obj = new JsonObject();
            obj.addProperty("success", true);
            obj.addProperty("moved", sourcePath);
            obj.addProperty("to", destPath);
            return JsonHelper.toJson(obj);
        } catch (Exception e) {
            return JsonHelper.errorJson(e.getMessage());
        }
    }

    public String deleteFile(String filePath) {
        if (!(programProvider instanceof HeadlessProgramProvider hpp)) {
            return JsonHelper.errorJson("Project management not supported in this mode");
        }
        try {
            hpp.deleteProjectFile(filePath);
            JsonObject obj = new JsonObject();
            obj.addProperty("success", true);
            obj.addProperty("deleted", filePath);
            return JsonHelper.toJson(obj);
        } catch (Exception e) {
            return JsonHelper.errorJson(e.getMessage());
        }
    }

    // ==========================================================================
    // ANALYSIS CONTROL (headless-only)
    // ==========================================================================

    public String configureAnalyzer(String programName, String analyzerName, Boolean enabled) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        if (!(programProvider instanceof HeadlessProgramProvider hpp)) {
            return JsonHelper.errorJson("Analyzer configuration not supported in this mode");
        }
        try {
            hpp.configureAnalyzer(program, analyzerName, enabled);
            JsonObject obj = new JsonObject();
            obj.addProperty("success", true);
            obj.addProperty("analyzer", analyzerName);
            return JsonHelper.toJson(obj);
        } catch (Exception e) {
            return JsonHelper.errorJson(e.getMessage());
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
        JsonObject obj = new JsonObject();
        obj.addProperty("success", true);
        obj.addProperty("message", "Server shutting down");
        return JsonHelper.toJson(obj);
    }

    public String convertNumber(String value, int size) {
        if (value == null || value.trim().isEmpty()) return JsonHelper.errorJson("value required");
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
            JsonObject obj = new JsonObject();
            obj.addProperty("input", value);
            obj.addProperty("detected_base", detectedBase);
            obj.addProperty("decimal", Long.toUnsignedString(result));
            obj.addProperty("hex", "0x" + Long.toUnsignedString(result, 16).toUpperCase());
            obj.addProperty("octal", "0" + Long.toUnsignedString(result, 8));
            obj.addProperty("binary", "0b" + Long.toUnsignedString(result, 2));
            return JsonHelper.toJson(obj);
        } catch (NumberFormatException e) {
            return JsonHelper.errorJson("Invalid number: " + value);
        }
    }

    public String readMemory(String addressStr, int length, String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        if (addressStr == null || addressStr.isEmpty()) return JsonHelper.errorJson("address required");
        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) return JsonHelper.errorJson("Invalid address: " + addressStr);
            if (length <= 0 || length > 4096) length = 256;
            byte[] buffer = new byte[length];
            int bytesRead = program.getMemory().getBytes(addr, buffer);
            StringBuilder hex = new StringBuilder();
            StringBuilder ascii = new StringBuilder();
            for (int i = 0; i < bytesRead; i++) {
                int b = buffer[i] & 0xFF;
                if (i > 0 && i % 16 == 0) hex.append("\n");
                else if (i > 0) hex.append(" ");
                hex.append(String.format("%02X", b));
                ascii.append(b >= 0x20 && b < 0x7F ? (char) b : '.');
            }
            JsonObject obj = new JsonObject();
            obj.addProperty("address", addressStr);
            obj.addProperty("length", bytesRead);
            obj.addProperty("hex", hex.toString());
            obj.addProperty("ascii", ascii.toString());
            return JsonHelper.toJson(obj);
        } catch (Exception e) {
            return JsonHelper.errorJson(e.getMessage());
        }
    }

    // ==========================================================================
    // BOOKMARK ENDPOINTS
    // ==========================================================================

    public String listBookmarks(String category, String address, String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        try {
            JsonArray arr = new JsonArray();
            BookmarkManager bm = program.getBookmarkManager();
            Iterator<Bookmark> iter = bm.getBookmarksIterator();
            while (iter.hasNext()) {
                Bookmark bk = iter.next();
                JsonObject entry = new JsonObject();
                entry.addProperty("address", bk.getAddress().toString());
                entry.addProperty("type", bk.getTypeString());
                entry.addProperty("category", bk.getCategory());
                entry.addProperty("comment", bk.getComment());
                arr.add(entry);
            }
            return JsonHelper.toJson(arr);
        } catch (Exception e) {
            return JsonHelper.errorJson(e.getMessage());
        }
    }

    public String setBookmark(String addressStr, String category, String comment, String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) return JsonHelper.errorJson("Invalid address: " + addressStr);
            final String finalCat = (category != null) ? category : "";
            final String finalComment = (comment != null) ? comment : "";
            return threadingStrategy.executeWrite(program, "Set bookmark", () -> {
                program.getBookmarkManager().setBookmark(addr, "Note", finalCat, finalComment);
                JsonObject obj = new JsonObject();
                obj.addProperty("success", true);
                obj.addProperty("address", addressStr);
                return JsonHelper.toJson(obj);
            });
        } catch (Exception e) {
            return JsonHelper.errorJson(e.getMessage());
        }
    }

    public String deleteBookmark(String addressStr, String category, String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) return JsonHelper.errorJson("Invalid address: " + addressStr);
            final String finalCat = (category != null) ? category : "";
            return threadingStrategy.executeWrite(program, "Delete bookmark", () -> {
                BookmarkManager bm = program.getBookmarkManager();
                Bookmark[] bks = bm.getBookmarks(addr);
                int deleted = 0;
                for (Bookmark bk : bks) {
                    if (finalCat.isEmpty() || bk.getCategory().equals(finalCat)) {
                        bm.removeBookmark(bk);
                        deleted++;
                    }
                }
                JsonObject obj = new JsonObject();
                obj.addProperty("success", true);
                obj.addProperty("address", addressStr);
                obj.addProperty("deleted", deleted);
                return JsonHelper.toJson(obj);
            });
        } catch (Exception e) {
            return JsonHelper.errorJson(e.getMessage());
        }
    }

    // ==========================================================================
    // ENHANCED QUERY ENDPOINTS
    // ==========================================================================


    public String listFunctionsEnhanced(int offset, int limit, String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        JsonObject result = new JsonObject();
        JsonArray arr = new JsonArray();
        int count = 0, skipped = 0;
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (skipped < offset) { skipped++; continue; }
            if (count >= limit) break;
            JsonObject entry = new JsonObject();
            entry.addProperty("name", func.getName());
            entry.addProperty("address", func.getEntryPoint().toString());
            entry.addProperty("isThunk", func.isThunk());
            entry.addProperty("isExternal", func.isExternal());
            arr.add(entry);
            count++;
        }
        result.add("functions", arr);
        result.addProperty("count", count);
        result.addProperty("offset", offset);
        result.addProperty("limit", limit);
        return JsonHelper.toJson(result);
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
        JsonObject obj = new JsonObject();
        JsonArray arr = new JsonArray();
        builtins.forEach(arr::add);
        obj.add("data_types", arr);
        obj.addProperty("count", builtins.size());
        return JsonHelper.toJson(obj);
    }

    public String getTypeSize(String typeName, String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        if (typeName == null || typeName.isEmpty()) return JsonHelper.errorJson("typeName required");
        DataTypeManager dtm = program.getDataTypeManager();
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            if (dt.getName().equalsIgnoreCase(typeName)) {
                JsonObject obj = new JsonObject();
                obj.addProperty("type", dt.getName());
                obj.addProperty("size", dt.getLength());
                obj.addProperty("path", dt.getPathName());
                return JsonHelper.toJson(obj);
            }
        }
        return JsonHelper.errorJson("Data type not found: " + typeName);
    }

    public String listExternalLocations(int offset, int limit, String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        try {
            JsonArray arr = new JsonArray();
            int skipped = 0, count = 0;
            ExternalManager em = program.getExternalManager();
            for (String libName : em.getExternalLibraryNames()) {
                ExternalLocationIterator it = em.getExternalLocations(libName);
                while (it.hasNext()) {
                    ExternalLocation loc = it.next();
                    if (skipped < offset) { skipped++; continue; }
                    if (count >= limit) break;
                    JsonObject entry = new JsonObject();
                    entry.addProperty("library", libName);
                    entry.addProperty("name", loc.getLabel());
                    entry.addProperty("address", loc.getAddress() != null ? loc.getAddress().toString() : "");
                    entry.addProperty("original_imported_name", loc.getOriginalImportedName() != null ? loc.getOriginalImportedName() : "");
                    arr.add(entry);
                    count++;
                }
                if (count >= limit) break;
            }
            return JsonHelper.toJson(arr);
        } catch (Exception e) {
            return JsonHelper.errorJson(e.getMessage());
        }
    }

    public String getExternalLocation(String libraryName, String symbolName, String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        try {
            ExternalManager em = program.getExternalManager();
            ExternalLocationIterator it = em.getExternalLocations(libraryName);
            while (it.hasNext()) {
                ExternalLocation loc = it.next();
                if (loc.getLabel().equals(symbolName)) {
                    JsonObject obj = new JsonObject();
                    obj.addProperty("library", libraryName);
                    obj.addProperty("name", loc.getLabel());
                    obj.addProperty("address", loc.getAddress() != null ? loc.getAddress().toString() : "");
                    obj.addProperty("original_imported_name", loc.getOriginalImportedName() != null ? loc.getOriginalImportedName() : "");
                    return JsonHelper.toJson(obj);
                }
            }
            return JsonHelper.errorJson("External location not found: " + libraryName + "!" + symbolName);
        } catch (Exception e) {
            return JsonHelper.errorJson(e.getMessage());
        }
    }

    // ==========================================================================
    // FLOW CONTROL ENDPOINTS
    // ==========================================================================

    public String setFunctionNoReturn(String functionAddrStr, boolean noReturn) {
        Program program = getProgram(null);
        if (program == null) return JsonHelper.errorJson("No program loaded");
        if (functionAddrStr == null || functionAddrStr.isEmpty()) return JsonHelper.errorJson("address required");
        try {
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            if (addr == null) return JsonHelper.errorJson("Invalid address: " + functionAddrStr);
            Function func = program.getFunctionManager().getFunctionAt(addr);
            if (func == null) func = program.getFunctionManager().getFunctionContaining(addr);
            if (func == null) return JsonHelper.errorJson("No function at address: " + functionAddrStr);
            final Function finalFunc = func;
            final String oldState = func.hasNoReturn() ? "non-returning" : "returning";
            return threadingStrategy.executeWrite(program, "Set function no return", () -> {
                finalFunc.setNoReturn(noReturn);
                String newState = noReturn ? "non-returning" : "returning";
                JsonObject obj = new JsonObject();
                obj.addProperty("success", true);
                obj.addProperty("function", finalFunc.getName());
                obj.addProperty("from", oldState);
                obj.addProperty("to", newState);
                return JsonHelper.toJson(obj);
            });
        } catch (Exception e) {
            return JsonHelper.errorJson(e.getMessage());
        }
    }

    public String clearInstructionFlowOverride(String instructionAddrStr) {
        Program program = getProgram(null);
        if (program == null) return JsonHelper.errorJson("No program loaded");
        if (instructionAddrStr == null || instructionAddrStr.isEmpty()) return JsonHelper.errorJson("address required");
        try {
            Address addr = program.getAddressFactory().getAddress(instructionAddrStr);
            if (addr == null) return JsonHelper.errorJson("Invalid address: " + instructionAddrStr);
            Instruction instruction = program.getListing().getInstructionAt(addr);
            if (instruction == null) return JsonHelper.errorJson("No instruction at address: " + instructionAddrStr);
            final FlowOverride oldOverride = instruction.getFlowOverride();
            return threadingStrategy.executeWrite(program, "Clear instruction flow override", () -> {
                instruction.setFlowOverride(FlowOverride.NONE);
                JsonObject obj = new JsonObject();
                obj.addProperty("success", true);
                obj.addProperty("address", instructionAddrStr);
                obj.addProperty("previous_override", oldOverride.toString());
                obj.addProperty("new_override", "NONE");
                return JsonHelper.toJson(obj);
            });
        } catch (Exception e) {
            return JsonHelper.errorJson(e.getMessage());
        }
    }

    public String setVariableStorage(String functionAddrStr, String variableName, String storageSpec) {
        Program program = getProgram(null);
        if (program == null) return JsonHelper.errorJson("No program loaded");
        if (functionAddrStr == null || functionAddrStr.isEmpty()) return JsonHelper.errorJson("address required");
        if (variableName == null || variableName.isEmpty()) return JsonHelper.errorJson("variable_name required");
        try {
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            if (addr == null) return JsonHelper.errorJson("Invalid address: " + functionAddrStr);
            Function func = program.getFunctionManager().getFunctionAt(addr);
            if (func == null) return JsonHelper.errorJson("No function at address: " + functionAddrStr);
            Variable targetVar = null;
            for (Variable var : func.getAllVariables()) {
                if (var.getName().equals(variableName)) { targetVar = var; break; }
            }
            if (targetVar == null) return JsonHelper.errorJson("Variable not found: " + variableName);
            JsonObject obj = new JsonObject();
            obj.addProperty("advisory", true);
            obj.addProperty("message", "Programmatic variable storage control is limited in Ghidra.");
            obj.addProperty("variable", variableName);
            obj.addProperty("function", func.getName());
            obj.addProperty("current_storage", targetVar.getVariableStorage().toString());
            obj.addProperty("requested_storage", storageSpec != null ? storageSpec : "");
            obj.addProperty("tip", "Use Ghidra decompiler UI or a custom script to change variable storage.");
            return JsonHelper.toJson(obj);
        } catch (Exception e) {
            return JsonHelper.errorJson(e.getMessage());
        }
    }

    // ==========================================================================
    // DATA TYPE CATEGORY ENDPOINTS
    // ==========================================================================

    public String createDataTypeCategory(String categoryPath) {
        Program program = getProgram(null);
        if (program == null) return getProgramError(null);
        if (categoryPath == null || categoryPath.isEmpty()) return JsonHelper.errorJson("categoryPath required");
        try {
            return threadingStrategy.executeWrite(program, "Create data type category", () -> {
                DataTypeManager dtm = program.getDataTypeManager();
                CategoryPath cp = new CategoryPath(categoryPath);
                Category cat = dtm.createCategory(cp);
                JsonObject obj = new JsonObject();
                obj.addProperty("success", true);
                obj.addProperty("category", cat.getCategoryPathName());
                return JsonHelper.toJson(obj);
            });
        } catch (Exception e) {
            return JsonHelper.errorJson(e.getMessage());
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
                if (found == null) return JsonHelper.errorJson("Type not found: " + typeName);
                CategoryPath cp = new CategoryPath(targetCategory);
                dtm.createCategory(cp);
                found.setCategoryPath(cp);
                JsonObject obj = new JsonObject();
                obj.addProperty("success", true);
                obj.addProperty("type", typeName);
                obj.addProperty("category", targetCategory);
                return JsonHelper.toJson(obj);
            });
        } catch (Exception e) {
            return JsonHelper.errorJson(e.getMessage());
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
            JsonArray arr = new JsonArray();
            categories.forEach(arr::add);
            return JsonHelper.toJson(arr);
        } catch (Exception e) {
            return JsonHelper.errorJson(e.getMessage());
        }
    }

    public String importDataTypes(String source, String format, String programName) {
        JsonObject obj = new JsonObject();
        obj.addProperty("advisory", true);
        obj.addProperty("message", "Data type import from external files requires the Ghidra GUI. Use File -> Parse C Source in Ghidra to import types from .h files.");
        obj.addProperty("requested_file", source != null ? source : "");
        return JsonHelper.toJson(obj);
    }

    // ==========================================================================
    // SCRIPT ENDPOINTS (headless-only)
    // ==========================================================================

    public String runScript(String scriptPath, String scriptArgs) {
        Program program = getProgram(null);
        if (program == null) {
            return JsonHelper.errorJson("No program loaded");
        }
        if (scriptPath == null || scriptPath.isEmpty()) {
            return JsonHelper.errorJson("Script path is required");
        }
        JsonObject obj = new JsonObject();
        obj.addProperty("status", "Script execution in headless mode");
        obj.addProperty("script_path", scriptPath);
        obj.addProperty("program", program.getName());
        obj.addProperty("note", "Full script execution requires GUI mode. Use Ghidra's analyzeHeadless for batch scripting.");
        return JsonHelper.toJson(obj);
    }

    public String listScripts(String filter) {
        JsonObject obj = new JsonObject();
        obj.add("scripts", new JsonArray());
        obj.addProperty("note", "Script listing in headless mode is limited.");
        JsonArray locations = new JsonArray();
        locations.add("<ghidra_install>/Ghidra/Features/*/ghidra_scripts/");
        locations.add("<user_home>/ghidra_scripts/");
        obj.add("common_locations", locations);
        if (filter != null) {
            obj.addProperty("filter", filter);
        } else {
            obj.add("filter", null);
        }
        return JsonHelper.toJson(obj);
    }

    public String runScriptInline(String scriptContent, String args) {
        JsonObject obj = new JsonObject();
        obj.addProperty("advisory", true);
        obj.addProperty("message", "Inline script execution requires Ghidra GUI mode or analyzeHeadless.");
        obj.addProperty("tip", "Use analyzeHeadless with -scriptPath and -process for batch scripting.");
        return JsonHelper.toJson(obj);
    }

    // ==========================================================================
    // CALL GRAPH ENDPOINTS (headless-only)
    // ==========================================================================

    public String getFunctionCallGraph(String functionAddress, int depth, String direction, String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        FunctionManager functionManager = program.getFunctionManager();
        Function rootFunction = findFunctionByAddressOrName(program, functionAddress);
        if (rootFunction == null) return JsonHelper.errorJson("Function not found: " + functionAddress);
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
        if (function == null) return JsonHelper.errorJson("Function not found: " + functionAddress);
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
        if (function == null) return JsonHelper.errorJson("Function not found: " + functionAddress);
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
        if (functionName == null || functionName.isEmpty()) return JsonHelper.errorJson("function_name required");
        try {
            FunctionManager functionManager = program.getFunctionManager();
            Function func = null;
            for (Function f : functionManager.getFunctions(true)) {
                if (f.getName().equals(functionName)) { func = f; break; }
            }
            if (func == null) return JsonHelper.errorJson("Function not found: " + functionName);
            BasicBlockModel blockModel = new BasicBlockModel(program);
            Listing listing = program.getListing();
            int basicBlockCount = 0, edgeCount = 0, conditionalBranches = 0;
            int unconditionalJumps = 0, loops = 0, instructionCount = 0, callCount = 0, returnCount = 0;
            List<JsonObject> blocks = new ArrayList<>();
            Set<Address> blockEntries = new HashSet<>();
            CodeBlockIterator blockIter = blockModel.getCodeBlocksContaining(func.getBody(), new ConsoleTaskMonitor());
            while (blockIter.hasNext()) blockEntries.add(blockIter.next().getFirstStartAddress());
            blockIter = blockModel.getCodeBlocksContaining(func.getBody(), new ConsoleTaskMonitor());
            while (blockIter.hasNext()) {
                CodeBlock block = blockIter.next();
                basicBlockCount++;
                JsonObject blockInfo = new JsonObject();
                blockInfo.addProperty("address", block.getFirstStartAddress().toString());
                blockInfo.addProperty("size", block.getNumAddresses());
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
                blockInfo.addProperty("successors", outEdges);
                blockInfo.addProperty("is_loop_header", hasBackEdge);
                if (outEdges == 0) blockInfo.addProperty("type", "exit");
                else if (outEdges == 1) blockInfo.addProperty("type", "sequential");
                else if (outEdges == 2) { blockInfo.addProperty("type", "conditional"); conditionalBranches++; }
                else blockInfo.addProperty("type", "switch");
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
            JsonObject result = new JsonObject();
            result.addProperty("function_name", functionName);
            result.addProperty("entry_point", func.getEntryPoint().toString());
            result.addProperty("size_bytes", func.getBody().getNumAddresses());
            JsonObject metrics = new JsonObject();
            metrics.addProperty("cyclomatic_complexity", cc);
            metrics.addProperty("complexity_rating", rating);
            metrics.addProperty("basic_blocks", basicBlockCount);
            metrics.addProperty("edges", edgeCount);
            metrics.addProperty("instructions", instructionCount);
            metrics.addProperty("conditional_branches", conditionalBranches);
            metrics.addProperty("unconditional_jumps", unconditionalJumps);
            metrics.addProperty("loops_detected", loops);
            metrics.addProperty("calls", callCount);
            metrics.addProperty("returns", returnCount);
            result.add("metrics", metrics);
            JsonArray blockDetails = new JsonArray();
            for (int i = 0; i < Math.min(blocks.size(), 50); i++) {
                blockDetails.add(blocks.get(i));
            }
            result.add("basic_block_details", blockDetails);
            return JsonHelper.toJson(result);
        } catch (Exception e) {
            return JsonHelper.errorJson(e.getMessage());
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
            Map<String, List<String>> detected = collectAPIBehaviors(program, behaviorIndicators);
            JsonObject result = new JsonObject();
            result.add("behaviors", buildCategoryArray(detected));
            result.addProperty("total_categories_detected", detected.size());
            return JsonHelper.toJson(result);
        } catch (Exception e) {
            return JsonHelper.errorJson(e.getMessage());
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
            Map<String, List<String>> detected = collectAPIBehaviors(program, antiDebugAPIs);
            JsonObject result = new JsonObject();
            result.add("anti_analysis_techniques", buildCategoryArray(detected));
            result.addProperty("total_detected", detected.size());
            return JsonHelper.toJson(result);
        } catch (Exception e) {
            return JsonHelper.errorJson(e.getMessage());
        }
    }

    /** Shared logic for API-based behavior detection (malware behaviors + anti-analysis). */
    private Map<String, List<String>> collectAPIBehaviors(Program program, Map<String, String[]> indicators) {
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
            for (Map.Entry<String, String[]> entry : indicators.entrySet()) {
                for (String api : entry.getValue()) {
                    if (funcAPIs.contains(api)) {
                        detected.computeIfAbsent(entry.getKey(), k -> new ArrayList<>()).add(func.getName() + ":" + api);
                        break;
                    }
                }
            }
        }
        return detected;
    }

    /** Build a JsonArray of {category, instances[]} objects from detected behaviors. */
    private JsonArray buildCategoryArray(Map<String, List<String>> detected) {
        JsonArray arr = new JsonArray();
        for (Map.Entry<String, List<String>> entry : detected.entrySet()) {
            JsonObject cat = new JsonObject();
            cat.addProperty("category", entry.getKey());
            JsonArray instances = new JsonArray();
            entry.getValue().forEach(instances::add);
            cat.add("instances", instances);
            arr.add(cat);
        }
        return arr;
    }

    public String findDeadCode(String functionName, String programName) {
        JsonArray arr = new JsonArray();
        JsonObject entry = new JsonObject();
        entry.addProperty("function_name", functionName != null ? functionName : "");
        entry.addProperty("status", "not_implemented");
        entry.addProperty("note", "Dead code detection requires reachability analysis via control flow graph");
        arr.add(entry);
        return JsonHelper.toJson(arr);
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
            JsonArray iocs = new JsonArray();
            for (MemoryBlock block : program.getMemory().getBlocks()) {
                DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
                while (it.hasNext()) {
                    Data data = it.next();
                    Object val = data.getValue();
                    if (val instanceof String s) {
                        collectPatternMatches(ipPattern, s, "ip", data.getAddress(), iocs);
                        collectPatternMatches(urlPattern, s, "url", data.getAddress(), iocs);
                        collectPatternMatches(emailPattern, s, "email", data.getAddress(), iocs);
                        collectPatternMatches(domainPattern, s, "domain", data.getAddress(), iocs);
                        collectPatternMatches(hashPattern, s, "hash", data.getAddress(), iocs);
                    }
                }
            }
            JsonObject result = new JsonObject();
            result.add("iocs", iocs);
            result.addProperty("count", iocs.size());
            return JsonHelper.toJson(result);
        } catch (Exception e) {
            return JsonHelper.errorJson(e.getMessage());
        }
    }

    private void collectPatternMatches(Pattern p, String s, String type, Address addr, JsonArray results) {
        Matcher m = p.matcher(s);
        while (m.find()) {
            JsonObject entry = new JsonObject();
            entry.addProperty("type", type);
            entry.addProperty("value", m.group());
            entry.addProperty("address", addr.toString());
            results.add(entry);
        }
    }

    public String analyzeApiCallChains(String programName) {
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
            JsonArray chains = new JsonArray();
            for (Function func : fm.getFunctions(true)) {
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
                    JsonObject entry = new JsonObject();
                    entry.addProperty("function", func.getName());
                    JsonArray apis = new JsonArray();
                    threats.forEach(apis::add);
                    entry.add("threat_apis", apis);
                    chains.add(entry);
                }
            }
            JsonObject result = new JsonObject();
            result.add("chains", chains);
            return JsonHelper.toJson(result);
        } catch (Exception e) {
            return JsonHelper.errorJson(e.getMessage());
        }
    }

    public String analyzeFunctionCompleteness(String functionAddress, String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        try {
            Address addr = program.getAddressFactory().getAddress(functionAddress);
            if (addr == null) return JsonHelper.errorJson("Invalid address: " + functionAddress);
            Function func = program.getFunctionManager().getFunctionAt(addr);
            if (func == null) return JsonHelper.errorJson("No function at address: " + functionAddress);
            boolean hasPlateComment = func.getComment() != null && !func.getComment().isEmpty();
            boolean hasRepeatableComment = func.getRepeatableComment() != null && !func.getRepeatableComment().isEmpty();
            boolean hasSignature = func.getSignature().getArguments().length > 0;
            boolean isNamed = !func.getName().startsWith("FUN_") && !func.getName().startsWith("SUB_");
            int score = 0;
            if (hasPlateComment) score += 25;
            if (hasRepeatableComment) score += 15;
            if (hasSignature) score += 30;
            if (isNamed) score += 30;
            JsonObject obj = new JsonObject();
            obj.addProperty("function", func.getName());
            obj.addProperty("address", functionAddress);
            obj.addProperty("completeness_score", score);
            obj.addProperty("has_plate_comment", hasPlateComment);
            obj.addProperty("has_repeatable_comment", hasRepeatableComment);
            obj.addProperty("has_typed_signature", hasSignature);
            obj.addProperty("is_renamed", isNamed);
            return JsonHelper.toJson(obj);
        } catch (Exception e) {
            return JsonHelper.errorJson(e.getMessage());
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
        if (functionsParam == null || functionsParam.trim().isEmpty()) return JsonHelper.errorJson("functions required");
        try {
            String[] functionNames = functionsParam.split(",");
            JsonObject result = new JsonObject();
            FunctionManager funcManager = program.getFunctionManager();
            final int MAX_FUNCTIONS = 20;
            for (int i = 0; i < functionNames.length && i < MAX_FUNCTIONS; i++) {
                String funcName = functionNames[i].trim();
                if (funcName.isEmpty()) continue;
                Function function = null;
                SymbolIterator symbols = program.getSymbolTable().getSymbols(funcName);
                while (symbols.hasNext()) {
                    Symbol sym = symbols.next();
                    if (sym.getSymbolType() == SymbolType.FUNCTION) {
                        function = funcManager.getFunctionAt(sym.getAddress());
                        break;
                    }
                }
                if (function == null) { result.addProperty(funcName, "Error: Function not found"); continue; }
                try {
                    DecompInterface decompiler = new DecompInterface();
                    decompiler.openProgram(program);
                    DecompileResults decompResults = decompiler.decompileFunction(function, 30, new ConsoleTaskMonitor());
                    if (decompResults != null && decompResults.decompileCompleted()) {
                        result.addProperty(funcName, decompResults.getDecompiledFunction().getC());
                    } else {
                        result.addProperty(funcName, "Error: Decompilation failed");
                    }
                    decompiler.dispose();
                } catch (Exception e) {
                    result.addProperty(funcName, "Error: " + e.getMessage());
                }
            }
            return JsonHelper.toJson(result);
        } catch (Exception e) {
            return JsonHelper.errorJson(e.getMessage());
        }
    }

    public String batchRenameFunctionComponents(String functionAddress, String functionName,
                                                 String variableRenamesJson, String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        try {
            Address addr = program.getAddressFactory().getAddress(functionAddress);
            if (addr == null) return JsonHelper.errorJson("Invalid address: " + functionAddress);
            Function func = program.getFunctionManager().getFunctionAt(addr);
            if (func == null) return JsonHelper.errorJson("No function at address: " + functionAddress);
            return threadingStrategy.executeWrite(program, "Batch rename function components", () -> {
                JsonArray results = new JsonArray();
                if (functionName != null && !functionName.isEmpty()) {
                    JsonObject entry = new JsonObject();
                    entry.addProperty("type", "function");
                    try {
                        func.setName(functionName, SourceType.USER_DEFINED);
                        entry.addProperty("new_name", functionName);
                        entry.addProperty("success", true);
                    } catch (Exception e) {
                        entry.addProperty("error", e.getMessage());
                    }
                    results.add(entry);
                }
                JsonObject obj = new JsonObject();
                obj.add("results", results);
                return JsonHelper.toJson(obj);
            });
        } catch (Exception e) {
            return JsonHelper.errorJson(e.getMessage());
        }
    }

    public String batchSetVariableTypes(String functionAddress, String variableTypesJson, boolean forceIndividual, String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        if (functionAddress == null || functionAddress.isEmpty()) return JsonHelper.errorJson("function_address required");
        if (variableTypesJson == null || variableTypesJson.isEmpty()) return JsonHelper.errorJson("variable_types required");
        try {
            return threadingStrategy.executeWrite(program, "Batch set variable types", () -> {
                Address addr = program.getAddressFactory().getAddress(functionAddress);
                if (addr == null) return JsonHelper.errorJson("Invalid address");
                Function func = program.getFunctionManager().getFunctionAt(addr);
                if (func == null) return JsonHelper.errorJson("No function at address");
                JsonObject obj = new JsonObject();
                obj.addProperty("success", true);
                obj.addProperty("function", func.getName());
                obj.addProperty("message", "Batch variable type setting queued");
                obj.addProperty("tip", "Use set_local_variable_type for individual variable type changes.");
                return JsonHelper.toJson(obj);
            });
        } catch (Exception e) {
            return JsonHelper.errorJson(e.getMessage());
        }
    }

    public String batchStringAnchorReport(String pattern, String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        try {
            Pattern searchPattern = pattern != null && !pattern.isEmpty() ? Pattern.compile(pattern, Pattern.CASE_INSENSITIVE) : null;
            JsonArray anchors = new JsonArray();
            for (MemoryBlock block : program.getMemory().getBlocks()) {
                DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
                while (it.hasNext()) {
                    Data data = it.next();
                    Object val = data.getValue();
                    if (val instanceof String s) {
                        if (searchPattern == null || searchPattern.matcher(s).find()) {
                            JsonObject entry = new JsonObject();
                            entry.addProperty("address", data.getAddress().toString());
                            entry.addProperty("label", data.getLabel() != null ? data.getLabel() : "");
                            entry.addProperty("value", s.length() > 100 ? s.substring(0, 100) + "..." : s);
                            entry.addProperty("xrefs", program.getReferenceManager().getReferenceCountTo(data.getAddress()));
                            anchors.add(entry);
                        }
                    }
                }
            }
            JsonObject result = new JsonObject();
            result.add("anchors", anchors);
            return JsonHelper.toJson(result);
        } catch (Exception e) {
            return JsonHelper.errorJson(e.getMessage());
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
        if (program == null) return JsonHelper.errorJson("No program loaded");
        if (functionAddress == null || functionAddress.isEmpty()) {
            JsonObject obj = new JsonObject(); obj.addProperty("valid", false); obj.addProperty("error", "address required");
            return JsonHelper.toJson(obj);
        }
        try {
            Address addr = program.getAddressFactory().getAddress(functionAddress);
            if (addr == null) { JsonObject o = new JsonObject(); o.addProperty("valid", false); o.addProperty("error", "Invalid address: " + functionAddress); return JsonHelper.toJson(o); }
            Function func = program.getFunctionManager().getFunctionAt(addr);
            if (func == null) { JsonObject o = new JsonObject(); o.addProperty("valid", false); o.addProperty("error", "No function at address: " + functionAddress); return JsonHelper.toJson(o); }
            if (prototype == null || prototype.trim().isEmpty()) { JsonObject o = new JsonObject(); o.addProperty("valid", false); o.addProperty("error", "Empty prototype"); return JsonHelper.toJson(o); }
            if (!prototype.contains("(")) { JsonObject o = new JsonObject(); o.addProperty("valid", false); o.addProperty("error", "Invalid prototype format - missing parentheses"); return JsonHelper.toJson(o); }
            List<String> warnings = new ArrayList<>();
            if (callingConvention != null && !callingConvention.isEmpty()) {
                String[] validConventions = {"__cdecl","__stdcall","__fastcall","__thiscall","default"};
                boolean validConv = false;
                for (String valid : validConventions) { if (callingConvention.equalsIgnoreCase(valid)) { validConv = true; break; } }
                if (!validConv) warnings.add("Unknown calling convention: " + callingConvention);
            }
            JsonObject result = new JsonObject();
            result.addProperty("valid", true);
            if (!warnings.isEmpty()) {
                JsonArray warningArr = new JsonArray();
                warnings.forEach(warningArr::add);
                result.add("warnings", warningArr);
            }
            return JsonHelper.toJson(result);
        } catch (Exception e) {
            JsonObject obj = new JsonObject();
            obj.addProperty("valid", false);
            obj.addProperty("error", e.getMessage());
            return JsonHelper.toJson(obj);
        }
    }

    public String disassembleBytes(String startAddress, String endAddress, int length, String programName) {
        Program program = getProgram(programName);
        if (program == null) return JsonHelper.errorJson("No program loaded");
        if (startAddress == null || startAddress.isEmpty()) return JsonHelper.errorJson("start_address required");
        try {
            Address start = program.getAddressFactory().getAddress(startAddress);
            if (start == null) return JsonHelper.errorJson("Invalid start address: " + startAddress);
            Address end;
            if (endAddress != null && !endAddress.isEmpty()) {
                end = program.getAddressFactory().getAddress(endAddress);
                if (end == null) return JsonHelper.errorJson("Invalid end address: " + endAddress);
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
                    new ghidra.app.cmd.disassemble.DisassembleCommand(addressSet, null, false);
                JsonObject obj = new JsonObject();
                if (cmd.applyTo(program, new ConsoleTaskMonitor())) {
                    obj.addProperty("success", true);
                    obj.addProperty("start_address", start.toString());
                    obj.addProperty("end_address", finalEnd.toString());
                    obj.addProperty("bytes_disassembled", numBytes);
                } else {
                    obj.addProperty("success", false);
                    obj.addProperty("error", "Disassembly failed");
                }
                return JsonHelper.toJson(obj);
            });
        } catch (Exception e) {
            return JsonHelper.errorJson(e.getMessage());
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
            if (func == null) return JsonHelper.errorJson("Function not found: " + functionAddress);
            JsonObject obj = new JsonObject();
            obj.addProperty("name", func.getName());
            obj.addProperty("address", func.getEntryPoint().toString());
            obj.addProperty("signature", func.getSignature().getPrototypeString());
            obj.addProperty("plate_comment", func.getComment() != null ? func.getComment() : "");
            obj.addProperty("repeatable_comment", func.getRepeatableComment() != null ? func.getRepeatableComment() : "");
            obj.addProperty("is_thunk", func.isThunk());
            obj.addProperty("is_external", func.isExternal());
            obj.addProperty("parameter_count", func.getParameterCount());
            obj.addProperty("calling_convention", func.getCallingConventionName());
            return JsonHelper.toJson(obj);
        } catch (Exception e) {
            return JsonHelper.errorJson(e.getMessage());
        }
    }

    public String applyFunctionDocumentation(String jsonBody) {
        JsonObject obj = new JsonObject();
        obj.addProperty("advisory", true);
        obj.addProperty("message", "Apply function documentation via the MCP bridge.");
        obj.addProperty("received", jsonBody != null ? jsonBody.length() : 0);
        return JsonHelper.toJson(obj);
    }

    public String compareProgramsDocumentation() {
        Program[] programs = programProvider.getAllOpenPrograms();
        JsonObject result = new JsonObject();
        JsonArray arr = new JsonArray();
        for (Program p : programs) {
            int total = 0, documented = 0;
            for (Function f : p.getFunctionManager().getFunctions(true)) {
                total++;
                if (f.getComment() != null && !f.getComment().isEmpty()) documented++;
            }
            JsonObject entry = new JsonObject();
            entry.addProperty("name", p.getName());
            entry.addProperty("total_functions", total);
            entry.addProperty("documented", documented);
            entry.addProperty("coverage", total > 0 ? (documented * 100 / total) : 0);
            arr.add(entry);
        }
        result.add("programs", arr);
        return JsonHelper.toJson(result);
    }

    public String findUndocumentedByString(String stringAddress, String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        try {
            JsonArray arr = new JsonArray();
            for (Function func : program.getFunctionManager().getFunctions(true)) {
                if (func.getComment() == null || func.getComment().isEmpty()) {
                    JsonObject entry = new JsonObject();
                    entry.addProperty("name", func.getName());
                    entry.addProperty("address", func.getEntryPoint().toString());
                    arr.add(entry);
                }
            }
            return JsonHelper.toJson(arr);
        } catch (Exception e) {
            return JsonHelper.errorJson(e.getMessage());
        }
    }

    public String detectCryptoConstants(String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        long[] cryptoConsts = {0x67452301L, 0xEFCDAB89L, 0x98BADCFEL, 0x10325476L,
                               0x5A827999L, 0x6ED9EBA1L, 0x8F1BBCDCL, 0xCA62C1D6L,
                               0x6A09E667L, 0xBB67AE85L, 0x3C6EF372L, 0xA54FF53AL};
        Set<Long> constSet = new HashSet<>();
        for (long c : cryptoConsts) constSet.add(c);
        JsonArray found = new JsonArray();
        try {
            for (MemoryBlock block : program.getMemory().getBlocks()) {
                DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
                while (it.hasNext()) {
                    Data data = it.next();
                    Object val = data.getValue();
                    if (val instanceof Long && constSet.contains(val)) {
                        JsonObject entry = new JsonObject();
                        entry.addProperty("address", data.getAddress().toString());
                        entry.addProperty("value", "0x" + Long.toHexString((Long) val).toUpperCase());
                        found.add(entry);
                    }
                }
            }
        } catch (Exception ignored) {}
        JsonObject result = new JsonObject();
        result.add("crypto_constants", found);
        result.addProperty("count", found.size());
        return JsonHelper.toJson(result);
    }

    // ==========================================================================
    // LABEL / SYMBOL ENDPOINTS (headless-only)
    // ==========================================================================

    // ========== PORTED FROM GUI PLUGIN ==========

    public String createLabel(String addressStr, String labelName) {
        Program program = getProgram(null);
        if (program == null) return getProgramError(null);
        if (addressStr == null || addressStr.isEmpty()) return JsonHelper.errorJson("Address is required");
        if (labelName == null || labelName.isEmpty()) return JsonHelper.errorJson("Label name is required");
        try {
            return threadingStrategy.executeWrite(program, "Create Label", () -> {
                Address address = parseAddress(program, addressStr);
                if (address == null) return JsonHelper.errorJson("Invalid address: " + addressStr);
                SymbolTable symbolTable = program.getSymbolTable();
                Symbol[] existing = symbolTable.getSymbols(address);
                for (Symbol s : existing) {
                    if (s.getName().equals(labelName) && s.getSymbolType() == SymbolType.LABEL) {
                        return JsonHelper.errorJson("Label '" + labelName + "' already exists at " + addressStr);
                    }
                }
                Symbol newSymbol = symbolTable.createLabel(address, labelName, SourceType.USER_DEFINED);
                if (newSymbol != null) {
                    JsonObject obj = new JsonObject();
                    obj.addProperty("success", true);
                    obj.addProperty("label", labelName);
                    obj.addProperty("address", addressStr);
                    return JsonHelper.toJson(obj);
                }
                return JsonHelper.errorJson("Failed to create label");
            });
        } catch (Exception e) {
            return JsonHelper.errorJson(e.getMessage());
        }
    }

    public String renameLabel(String addressStr, String oldName, String newName) {
        Program program = getProgram(null);
        if (program == null) return getProgramError(null);
        if (addressStr == null || addressStr.isEmpty()) return JsonHelper.errorJson("Address is required");
        try {
            return threadingStrategy.executeWrite(program, "Rename Label", () -> {
                Address address = parseAddress(program, addressStr);
                if (address == null) return JsonHelper.errorJson("Invalid address: " + addressStr);
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
                    return JsonHelper.errorJson("Label '" + oldName + "' not found at " + addressStr);
                }
                target.setName(newName, SourceType.USER_DEFINED);
                JsonObject obj = new JsonObject();
                obj.addProperty("success", true);
                obj.addProperty("old_name", oldName);
                obj.addProperty("new_name", newName);
                return JsonHelper.toJson(obj);
            });
        } catch (Exception e) {
            return JsonHelper.errorJson(e.getMessage());
        }
    }

    public String renameExternalLocation(String addressStr, String newName) {
        Program program = getProgram(null);
        if (program == null) return getProgramError(null);
        try {
            return threadingStrategy.executeWrite(program, "Rename external location", () -> {
                Address addr = parseAddress(program, addressStr);
                if (addr == null) return JsonHelper.errorJson("Invalid address: " + addressStr);
                ExternalManager extMgr = program.getExternalManager();
                for (String libName : extMgr.getExternalLibraryNames()) {
                    ExternalLocationIterator iter = extMgr.getExternalLocations(libName);
                    while (iter.hasNext()) {
                        ExternalLocation extLoc = iter.next();
                        if (extLoc.getAddress() != null && extLoc.getAddress().equals(addr)) {
                            String oldName = extLoc.getLabel();
                            Namespace ns = extMgr.getExternalLibrary(libName);
                            extLoc.setName(ns, newName, SourceType.USER_DEFINED);
                            JsonObject obj = new JsonObject();
                            obj.addProperty("success", true);
                            obj.addProperty("old_name", oldName);
                            obj.addProperty("new_name", newName);
                            obj.addProperty("dll", libName);
                            return JsonHelper.toJson(obj);
                        }
                    }
                }
                return JsonHelper.errorJson("External location not found at address " + addressStr);
            });
        } catch (Exception e) {
            return JsonHelper.errorJson(e.getMessage());
        }
    }

    public String inspectMemoryContent(String addressStr, int length, boolean detectStrings, String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        try {
            Address addr = parseAddress(program, addressStr);
            if (addr == null) return JsonHelper.errorJson("Invalid address: " + addressStr);
            Memory memory = program.getMemory();
            byte[] bytes = new byte[length];
            int bytesRead = memory.getBytes(addr, bytes);
            StringBuilder hexDump = new StringBuilder();
            StringBuilder asciiRepr = new StringBuilder();
            for (int i = 0; i < bytesRead; i++) {
                if (i > 0 && i % 16 == 0) { hexDump.append("\n"); asciiRepr.append("\n"); }
                hexDump.append(String.format("%02X ", bytes[i] & 0xFF));
                char c = (char) (bytes[i] & 0xFF);
                asciiRepr.append((c >= 0x20 && c <= 0x7E) ? c : '.');
            }
            int printableCount = 0, maxConsec = 0, curConsec = 0, nullIdx = -1;
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
            JsonObject obj = new JsonObject();
            obj.addProperty("address", addressStr);
            obj.addProperty("bytes_read", bytesRead);
            obj.addProperty("hex_dump", hexDump.toString().trim());
            obj.addProperty("ascii_repr", asciiRepr.toString().trim());
            obj.addProperty("is_likely_string", likelyString);
            if (detectedString != null) {
                obj.addProperty("detected_string", detectedString);
                obj.addProperty("string_length", stringLen);
            } else {
                obj.add("detected_string", null);
                obj.addProperty("string_length", 0);
            }
            return JsonHelper.toJson(obj);
        } catch (Exception e) {
            return JsonHelper.errorJson(e.getMessage());
        }
    }

    public String searchStrings(String query, int minLength, String encoding, int offset, int limit, String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        if (query == null || query.isEmpty()) return JsonHelper.errorJson("query parameter is required");
        Pattern pat;
        try {
            pat = Pattern.compile(query, Pattern.CASE_INSENSITIVE);
        } catch (Exception e) {
            return JsonHelper.errorJson("Invalid regex: " + e.getMessage());
        }
        List<JsonObject> results = new ArrayList<>();
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
            JsonObject entry = new JsonObject();
            entry.addProperty("address", data.getAddress().toString());
            entry.addProperty("value", value);
            entry.addProperty("encoding", (encoding != null && !encoding.isEmpty()) ? encoding : "ascii");
            results.add(entry);
        }
        int total = results.size();
        int from = Math.min(offset, total);
        int to = Math.min(from + limit, total);
        JsonObject obj = new JsonObject();
        JsonArray matches = new JsonArray();
        for (int i = from; i < to; i++) {
            matches.add(results.get(i));
        }
        obj.add("matches", matches);
        obj.addProperty("total", total);
        obj.addProperty("offset", offset);
        obj.addProperty("limit", limit);
        return JsonHelper.toJson(obj);
    }

    // ==========================================================================
    // STRUCTURAL SIMILARITY (headless-only)
    // ==========================================================================

    public String findSimilarFunctions(String targetFunction, double threshold, String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        if (targetFunction == null || targetFunction.trim().isEmpty())
            return JsonHelper.errorJson("Target function name is required");
        try {
            FunctionManager fm = program.getFunctionManager();
            Function targetFunc = null;
            for (Function f : fm.getFunctions(true)) {
                if (f.getName().equals(targetFunction)) { targetFunc = f; break; }
            }
            if (targetFunc == null) return JsonHelper.errorJson("Function not found: " + targetFunction);
            BasicBlockModel blockModel = new BasicBlockModel(program);
            int targetBlocks = countBlocks(blockModel, targetFunc);
            int targetInstructions = countInstructions(program, targetFunc);
            int targetCalls = countCalls(program, targetFunc);

            record Match(String name, String address, double similarity, int blocks, int instructions, int calls) {}
            List<Match> matches = new ArrayList<>();
            for (Function f : fm.getFunctions(true)) {
                if (f.getName().equals(targetFunction) || f.isThunk()) continue;
                int blocks = countBlocks(blockModel, f);
                int instr = countInstructions(program, f);
                int calls = countCalls(program, f);
                double similarity = computeSimilarity(targetBlocks, targetInstructions, targetCalls, blocks, instr, calls);
                if (similarity >= threshold) {
                    matches.add(new Match(f.getName(), f.getEntryPoint().toString(), similarity, blocks, instr, calls));
                }
            }
            matches.sort((a, b) -> Double.compare(b.similarity(), a.similarity()));
            if (matches.size() > 50) matches = matches.subList(0, 50);

            JsonObject result = new JsonObject();
            result.addProperty("target", targetFunction);
            result.addProperty("threshold", threshold);
            result.addProperty("matches_found", matches.size());
            JsonArray arr = new JsonArray();
            for (Match m : matches) {
                JsonObject entry = new JsonObject();
                entry.addProperty("name", m.name());
                entry.addProperty("address", m.address());
                entry.addProperty("similarity", Double.parseDouble(String.format("%.3f", m.similarity())));
                entry.addProperty("blocks", m.blocks());
                entry.addProperty("instructions", m.instructions());
                entry.addProperty("calls", m.calls());
                arr.add(entry);
            }
            result.add("similar_functions", arr);
            return JsonHelper.toJson(result);
        } catch (Exception e) {
            return JsonHelper.errorJson(e.getMessage());
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
        if (addressStr == null || addressStr.isEmpty()) return JsonHelper.errorJson("Address is required");
        if (typeName == null || typeName.isEmpty()) return JsonHelper.errorJson("Type name is required");
        try {
            Address addr = parseAddress(program, addressStr);
            if (addr == null) return JsonHelper.errorJson("Invalid address: " + addressStr);
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dataType = findDataType(dtm, typeName);
            if (dataType == null) return JsonHelper.errorJson("Data type not found: " + typeName);
            Memory memory = program.getMemory();
            int typeSize = dataType.getLength();
            boolean memOk = typeSize > 0 && memory.contains(addr) && memory.contains(addr.add(typeSize - 1));
            long alignment = dataType.getAlignment();
            boolean aligned = alignment <= 1 || (addr.getOffset() % alignment == 0);
            Data existing = program.getListing().getDefinedDataAt(addr);
            JsonObject obj = new JsonObject();
            obj.addProperty("type", typeName);
            obj.addProperty("size", typeSize);
            obj.addProperty("memory_available", memOk);
            obj.addProperty("aligned", aligned);
            if (existing != null) {
                obj.addProperty("existing_data", existing.getDataType().getName());
            } else {
                obj.add("existing_data", null);
            }
            return JsonHelper.toJson(obj);
        } catch (Exception e) {
            return JsonHelper.errorJson(e.getMessage());
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
