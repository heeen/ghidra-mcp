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
import com.xebyte.core.BinaryComparisonService;
import com.xebyte.core.JsonHelper;
import com.xebyte.core.ProgramProvider;
import com.xebyte.core.Response;
import com.xebyte.core.ThreadingStrategy;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Shared service for function hashing, fuzzy matching, diff operations,
 * and cross-binary documentation propagation.
 *
 * Provides normalized opcode hashing for exact matching, delegates to
 * {@link BinaryComparisonService} for fuzzy similarity and structured diffs.
 * Used by both GhidraMCPPlugin (GUI) and HeadlessEndpointHandler.
 */
public class ComparisonService extends BaseService {

    private static final int DECOMPILE_TIMEOUT_SECONDS = 60;

    public ComparisonService(ProgramProvider programProvider, ThreadingStrategy threadingStrategy) {
        super(programProvider, threadingStrategy);
    }

    // =========================================================================
    // PUBLIC METHODS — Hashing & Matching
    // =========================================================================

    /**
     * Compute normalized hash for a single function.
     */
    public Response getFunctionHash(String addressStr, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) {
                return Response.err("Invalid address: " + addressStr);
            }

            Function func = program.getFunctionManager().getFunctionAt(addr);
            if (func == null) {
                return Response.err("No function at address: " + addressStr);
            }

            String hash = computeNormalizedFunctionHash(program, func);
            int instructionCount = countFunctionInstructions(program, func);
            boolean hasCustomName = !func.getName().startsWith("FUN_") &&
                                   !func.getName().startsWith("thunk_");

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("function_name", func.getName());
            result.put("address", addr.toString());
            result.put("hash", hash);
            result.put("instruction_count", instructionCount);
            result.put("has_custom_name", hasCustomName);
            result.put("program", program.getName());

            return Response.ok(result);
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Get hashes for multiple functions with pagination and filtering.
     */
    public Response getBulkFunctionHashes(int offset, int limit, String filter, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        try {
            FunctionManager funcMgr = program.getFunctionManager();
            int total = 0;
            int skipped = 0;
            int added = 0;
            List<Map<String, Object>> functions = new ArrayList<>();

            for (Function func : funcMgr.getFunctions(true)) {
                boolean isDocumented = !func.getName().startsWith("FUN_") &&
                                       !func.getName().startsWith("thunk_") &&
                                       !func.getName().startsWith("switch");

                if ("documented".equals(filter) && !isDocumented) continue;
                if ("undocumented".equals(filter) && isDocumented) continue;

                total++;

                if (skipped < offset) {
                    skipped++;
                    continue;
                }

                if (added >= limit) continue;

                String hash = computeNormalizedFunctionHash(program, func);
                int instructionCount = countFunctionInstructions(program, func);

                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("name", func.getName());
                entry.put("address", func.getEntryPoint().toString());
                entry.put("hash", hash);
                entry.put("instruction_count", instructionCount);
                entry.put("has_custom_name", isDocumented);
                functions.add(entry);

                added++;
            }

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("program", program.getName());
            result.put("functions", functions);
            result.put("offset", offset);
            result.put("limit", limit);
            result.put("returned", added);
            result.put("total_matching", total);

            return Response.ok(result);
        } catch (Exception e) {
            return Response.err("Failed to get bulk hashes: " + e.getMessage());
        }
    }

    /**
     * Get function signature (feature vector) for fuzzy matching.
     */
    public Response getFunctionSignature(String addressStr, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) return programNotFoundError(programName);

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) return Response.err("Invalid address: " + addressStr);

            Function func = program.getFunctionManager().getFunctionAt(addr);
            if (func == null) return Response.err("No function at address: " + addressStr);

            BinaryComparisonService.FunctionSignature sig =
                BinaryComparisonService.computeFunctionSignature(program, func, monitor);
            return Response.text(sig.toJson());
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Find functions in target program similar to a source function.
     */
    public Response findSimilarFunctionsFuzzy(String addressStr, String sourceProgramName,
            String targetProgramName, double threshold, int limit) {
        Program srcProgram = resolveProgram(sourceProgramName);
        if (srcProgram == null) return programNotFoundError(sourceProgramName);

        if (targetProgramName == null || targetProgramName.trim().isEmpty()) {
            return Response.err("target_program parameter is required");
        }
        Program tgtProgram = resolveProgram(targetProgramName);
        if (tgtProgram == null) return programNotFoundError(targetProgramName);

        try {
            Address addr = srcProgram.getAddressFactory().getAddress(addressStr);
            if (addr == null) return Response.err("Invalid address: " + addressStr);

            Function srcFunc = srcProgram.getFunctionManager().getFunctionAt(addr);
            if (srcFunc == null) return Response.err("No function at address: " + addressStr);

            return Response.text(BinaryComparisonService.findSimilarFunctionsJson(
                srcProgram, srcFunc, tgtProgram, threshold, limit, monitor));
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Bulk fuzzy match: best match per source function in target program.
     */
    public Response bulkFuzzyMatch(String sourceProgramName, String targetProgramName,
            double threshold, int offset, int limit, String filter) {
        if (sourceProgramName == null || sourceProgramName.trim().isEmpty()) {
            return Response.err("source_program parameter is required");
        }
        Program srcProgram = resolveProgram(sourceProgramName);
        if (srcProgram == null) return programNotFoundError(sourceProgramName);

        if (targetProgramName == null || targetProgramName.trim().isEmpty()) {
            return Response.err("target_program parameter is required");
        }
        Program tgtProgram = resolveProgram(targetProgramName);
        if (tgtProgram == null) return programNotFoundError(targetProgramName);

        try {
            return Response.text(BinaryComparisonService.bulkFuzzyMatchJson(
                srcProgram, tgtProgram, threshold, offset, limit, filter, monitor));
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Structured diff between two functions (optionally from different programs).
     */
    public Response diffFunctions(String addressA, String addressB,
            String programAName, String programBName) {
        Program progA = resolveProgram(programAName);
        if (progA == null) return programNotFoundError(programAName);

        Program progB;
        if (programBName == null || programBName.trim().isEmpty()) {
            progB = progA;
        } else {
            progB = resolveProgram(programBName);
            if (progB == null) return programNotFoundError(programBName);
        }

        try {
            Address addrA = progA.getAddressFactory().getAddress(addressA);
            if (addrA == null) return Response.err("Invalid address_a: " + addressA);

            Address addrB = progB.getAddressFactory().getAddress(addressB);
            if (addrB == null) return Response.err("Invalid address_b: " + addressB);

            Function funcA = progA.getFunctionManager().getFunctionAt(addrA);
            if (funcA == null) return Response.err("No function at address_a: " + addressA);

            Function funcB = progB.getFunctionManager().getFunctionAt(addrB);
            if (funcB == null) return Response.err("No function at address_b: " + addressB);

            return Response.text(BinaryComparisonService.diffFunctionsJson(progA, funcA, progB, funcB, monitor));
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    // =========================================================================
    // PUBLIC METHODS — Documentation Propagation
    // =========================================================================

    /**
     * Export all documentation for a function (for use in cross-binary propagation).
     */
    public Response getFunctionDocumentation(String functionAddress) throws Exception {
        Program program = resolveProgram(null);
        if (program == null) {
            return Response.err("No program loaded");
        }

        Address addr = program.getAddressFactory().getAddress(functionAddress);
        if (addr == null) {
            return Response.err("Invalid address: " + functionAddress);
        }

        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            return Response.err("No function at address: " + functionAddress);
        }

        final var hash = computeDocumentationHash(program, func);
        final var sourceProg = program.getName();
        final var sourceAddr = addr.toString();
        final var funcName = func.getName();
        final var returnType = func.getReturnType().getName();
        final var callingConvention = func.getCallingConventionName() != null ? func.getCallingConventionName() : "";
        final var plateComment = func.getComment();

        // Parameters
        var paramList = new ArrayList<>();
        for (Parameter p : func.getParameters()) {
            JsonObject jo = new JsonObject();
            jo.addProperty("ordinal", p.getOrdinal());
            jo.addProperty("name", p.getName());
            jo.addProperty("type", p.getDataType().getName());
            jo.addProperty("comment", p.getComment());
            paramList.add(jo);
        }

        // Local variables (from decompilation if available)
        var localVarList = new ArrayList<>();
        DecompileResults decompResults = decompileFunction(func, program);
        if (decompResults != null && decompResults.decompileCompleted()) {
            ghidra.program.model.pcode.HighFunction highFunc = decompResults.getHighFunction();
            if (highFunc != null) {
                Iterator<ghidra.program.model.pcode.HighSymbol> symbols = highFunc.getLocalSymbolMap().getSymbols();
                while (symbols.hasNext()) {
                    ghidra.program.model.pcode.HighSymbol sym = symbols.next();
                    if (sym.isParameter()) continue;
                    ghidra.program.model.pcode.HighVariable highVar = sym.getHighVariable();
                    final var storage = (highVar != null && highVar.getRepresentative() != null)
                            ? highVar.getRepresentative().toString()
                            : null;
                    JsonObject jo = new JsonObject();
                    jo.addProperty("name", sym.getName());
                    jo.addProperty("type", sym.getDataType().getName());
                    jo.addProperty("var_storage", storage);
                    localVarList.add(jo);
                }
            }
        }

        // Inline comments (EOL and PRE comments within function body)
        var commentList = new ArrayList<>();
        AddressSetView functionBody = func.getBody();
        Listing listing = program.getListing();
        Address funcStart = func.getEntryPoint();
        for (Address cAddr : functionBody.getAddresses(true)) {
            String eolComment = listing.getComment(CodeUnit.EOL_COMMENT, cAddr);
            String preComment = listing.getComment(CodeUnit.PRE_COMMENT, cAddr);
            if (eolComment != null || preComment != null) {
                JsonObject jo = new JsonObject();
                jo.addProperty("relative_offset", cAddr.subtract(funcStart));
                jo.addProperty("eol_comment", eolComment);
                jo.addProperty("pre_comment", preComment);
                commentList.add(jo);
            }
        }

        // Labels within function
        var labelList = new ArrayList<>();
        SymbolTable symTable = program.getSymbolTable();
        for (Address lAddr : functionBody.getAddresses(true)) {
            Symbol[] symbols = symTable.getSymbols(lAddr);
            for (Symbol sym : symbols) {
                if (sym.getSymbolType() == SymbolType.LABEL && !sym.getName().equals(func.getName())) {
                    JsonObject jo = new JsonObject();
                    jo.addProperty("relative_offset", lAddr.subtract(funcStart));
                    jo.addProperty("name", sym.getName());
                    labelList.add(jo);
                }
            }
        }

        // Completeness score
        List<String> undefinedVars = new ArrayList<>();
        for (Parameter param : func.getParameters()) {
            if (param.getName().startsWith("param_")) {
                undefinedVars.add(param.getName());
            }
            if (param.getDataType().getName().startsWith("undefined")) {
                undefinedVars.add(param.getName());
            }
        }
        final var completenessScore = calculateCompletenessScore(func, undefinedVars.size(), 0, 0, 0, 0, 0, 0);

        JsonObject result = new JsonObject();
        result.addProperty("func_hash", hash);
        result.addProperty("source_program", sourceProg);
        result.addProperty("source_address", sourceAddr);
        result.addProperty("function_name", funcName);
        result.addProperty("return_type", returnType);
        result.addProperty("calling_convention", callingConvention);
        result.addProperty("plate_comment", plateComment);
        result.add("parameters", JsonHelper.gson().toJsonTree(paramList));
        result.add("local_variables", JsonHelper.gson().toJsonTree(localVarList));
        result.add("func_comments", JsonHelper.gson().toJsonTree(commentList));
        result.add("func_labels", JsonHelper.gson().toJsonTree(labelList));
        result.addProperty("doc_completeness_score", completenessScore);
        return new Response.Ok(result);
    }

    /**
     * Apply documentation from a source function to a target function.
     * Expects JSON body with: target_address, source_documentation (from getFunctionDocumentation)
     */
    public Response applyFunctionDocumentation(String jsonBody) throws Exception {
        Program program = resolveProgram(null);
        if (program == null) {
            return Response.err("No program loaded");
        }

        String targetAddress = extractJsonString(jsonBody, "target_address");
        String functionName = extractJsonString(jsonBody, "function_name");
        String returnType = extractJsonString(jsonBody, "return_type");
        String callingConvention = extractJsonString(jsonBody, "calling_convention");
        String plateComment = extractJsonString(jsonBody, "plate_comment");

        if (targetAddress == null) {
            return Response.err("target_address is required");
        }

        Address addr = program.getAddressFactory().getAddress(targetAddress);
        if (addr == null) {
            return Response.err("Invalid target address: " + targetAddress);
        }

        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            return Response.err("No function at target address: " + targetAddress);
        }

        final AtomicInteger changesApplied = new AtomicInteger(0);

        try {
            threadingStrategy.executeWrite(program, "Apply Function Documentation", () -> {
                // Apply function name
                if (functionName != null && !functionName.isEmpty() && !functionName.equals(func.getName())) {
                    try {
                        func.setName(functionName, SourceType.USER_DEFINED);
                        changesApplied.incrementAndGet();
                    } catch (Exception e) {
                        Msg.warn(ComparisonService.class, "Could not set function name: " + e.getMessage());
                    }
                }

                // Apply plate comment
                if (plateComment != null && !plateComment.isEmpty()) {
                    func.setComment(plateComment);
                    changesApplied.incrementAndGet();
                }

                // Apply calling convention
                if (callingConvention != null && !callingConvention.isEmpty()) {
                    try {
                        func.setCallingConvention(callingConvention);
                        changesApplied.incrementAndGet();
                    } catch (Exception e) {
                        Msg.warn(ComparisonService.class, "Could not set calling convention: " + e.getMessage());
                    }
                }

                // Apply return type
                if (returnType != null && !returnType.isEmpty()) {
                    DataType dt = findDataTypeByName(program.getDataTypeManager(), returnType);
                    if (dt != null) {
                        try {
                            func.setReturnType(dt, SourceType.USER_DEFINED);
                            changesApplied.incrementAndGet();
                        } catch (Exception e) {
                            Msg.warn(ComparisonService.class, "Could not set return type: " + e.getMessage());
                        }
                    }
                }

                // Apply parameter names and types from JSON array
                String paramsJson = extractJsonArray(jsonBody, "parameters");
                if (paramsJson != null) {
                    applyParameterDocumentation(func, program, paramsJson, changesApplied);
                }

                // Apply comments from JSON array
                String commentsJson = extractJsonArray(jsonBody, "comments");
                if (commentsJson != null) {
                    applyCommentsDocumentation(func, program, commentsJson, changesApplied);
                }

                // Apply labels from JSON array
                String labelsJson = extractJsonArray(jsonBody, "labels");
                if (labelsJson != null) {
                    applyLabelsDocumentation(func, program, labelsJson, changesApplied);
                }
            });
        } catch (Exception e) {
            return Response.err("Failed to apply documentation: " + e.getMessage());
        }

        JsonObject result = new JsonObject();
        result.addProperty("success", true);
        result.addProperty("changes_applied", changesApplied.get());
        result.addProperty("function", func.getName());
        result.addProperty("address", addr.toString());
        return new Response.Ok(result);
    }

    /**
     * Compare documentation status across all open programs.
     */
    public Response compareProgramsDocumentation() {
        try {
            Program[] allPrograms = programProvider.getAllOpenPrograms();
            Program currentProgram = programProvider.getCurrentProgram();

            List<Map<String, Object>> programs = new ArrayList<>();
            for (Program prog : allPrograms) {
                int documented = 0;
                int undocumented = 0;
                int total = 0;

                FunctionManager funcMgr = prog.getFunctionManager();
                for (Function func : funcMgr.getFunctions(true)) {
                    total++;
                    if (func.getName().startsWith("FUN_") || func.getName().startsWith("thunk_FUN_")) {
                        undocumented++;
                    } else {
                        documented++;
                    }
                }

                double docPercent = total > 0 ? (documented * 100.0 / total) : 0;

                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("name", prog.getName());
                entry.put("path", prog.getDomainFile().getPathname());
                entry.put("is_current", prog == currentProgram);
                entry.put("total_functions", total);
                entry.put("documented", documented);
                entry.put("undocumented", undocumented);
                entry.put("documentation_percent", Double.parseDouble(String.format("%.1f", docPercent)));
                programs.add(entry);
            }

            JsonObject result = new JsonObject();
            result.addProperty("count", allPrograms.length);
            return new Response.Ok(result);

        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Find undocumented (FUN_*) functions that reference a given string address.
     */
    public Response findUndocumentedByString(String stringAddress, String programName) {
        if (stringAddress == null || stringAddress.isEmpty()) {
            return Response.err("String address is required");
        }

        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        try {
            Address addr = program.getAddressFactory().getAddress(stringAddress);
            if (addr == null) {
                return Response.err("Invalid address format: " + stringAddress);
            }

            ReferenceManager refMgr = program.getReferenceManager();
            FunctionManager funcMgr = program.getFunctionManager();

            ReferenceIterator refIter = refMgr.getReferencesTo(addr);

            Set<String> seenFunctions = new HashSet<>();
            List<Map<String, String>> undocumentedFunctions = new ArrayList<>();
            int docCount = 0;

            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();

                Function func = funcMgr.getFunctionContaining(fromAddr);
                if (func != null) {
                    String funcName = func.getName();

                    if (!seenFunctions.contains(funcName)) {
                        seenFunctions.add(funcName);

                        if (funcName.startsWith("FUN_") || funcName.startsWith("thunk_FUN_")) {
                            Map<String, String> entry = new LinkedHashMap<>();
                            entry.put("name", funcName);
                            entry.put("address", func.getEntryPoint().toString());
                            entry.put("ref_address", fromAddr.toString());
                            entry.put("ref_type", ref.getReferenceType().getName());
                            undocumentedFunctions.add(entry);
                        } else {
                            docCount++;
                        }
                    }
                }
            }

            JsonObject result = new JsonObject();
            result.addProperty("string_address", stringAddress);
            result.addProperty("undocumented_count", undocumentedFunctions.size());
            result.addProperty("documented_count", docCount);
            result.addProperty("total_referencing_functions", seenFunctions.size());
            return new Response.Ok(result);

        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Generate a report of all strings matching a pattern and their referencing FUN_* functions.
     */
    public Response batchStringAnchorReport(String pattern, String programName) {
        if (pattern == null || pattern.isEmpty()) pattern = ".cpp";
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        String finalPattern = pattern;
        try {
            Listing listing = program.getListing();
            ReferenceManager refMgr = program.getReferenceManager();
            FunctionManager funcMgr = program.getFunctionManager();

            List<Map<String, Object>> anchors = new ArrayList<>();
            int totalUndocumented = 0;

            DataIterator dataIter = listing.getDefinedData(true);
            while (dataIter.hasNext()) {
                Data data = dataIter.next();

                if (data.getDataType() instanceof StringDataType ||
                    data.getDataType().getName().toLowerCase().contains("string")) {

                    Object value = data.getValue();
                    if (value instanceof String strValue) {

                        if (strValue.toLowerCase().contains(finalPattern.toLowerCase())) {
                            Address strAddr = data.getAddress();

                            ReferenceIterator refIter = refMgr.getReferencesTo(strAddr);
                            List<Map<String, String>> undocFuncList = new ArrayList<>();
                            List<String> docFuncList = new ArrayList<>();
                            Set<String> seenUndoc = new LinkedHashSet<>();
                            Set<String> seenDoc = new LinkedHashSet<>();

                            while (refIter.hasNext()) {
                                Reference ref = refIter.next();
                                Function func = funcMgr.getFunctionContaining(ref.getFromAddress());
                                if (func != null) {
                                    String funcName = func.getName();
                                    if (funcName.startsWith("FUN_") || funcName.startsWith("thunk_FUN_")) {
                                        String key = funcName + "@" + func.getEntryPoint().toString();
                                        if (seenUndoc.add(key)) {
                                            Map<String, String> fe = new LinkedHashMap<>();
                                            fe.put("name", funcName);
                                            fe.put("address", func.getEntryPoint().toString());
                                            undocFuncList.add(fe);
                                        }
                                    } else {
                                        if (seenDoc.add(funcName)) {
                                            docFuncList.add(funcName);
                                        }
                                    }
                                }
                            }

                            if (!undocFuncList.isEmpty() || !docFuncList.isEmpty()) {
                                totalUndocumented += undocFuncList.size();

                                Map<String, Object> anchor = new LinkedHashMap<>();
                                anchor.put("string", strValue);
                                anchor.put("address", strAddr.toString());
                                anchor.put("undocumented", undocFuncList);
                                anchor.put("documented", docFuncList);
                                anchor.put("undocumented_count", undocFuncList.size());
                                anchor.put("documented_count", docFuncList.size());
                                anchors.add(anchor);
                            }
                        }
                    }
                }
            }

            JsonObject result = new JsonObject();
            result.addProperty("pattern", finalPattern);
            result.addProperty("total_anchors", anchors.size());
            result.addProperty("total_undocumented_functions", totalUndocumented);
            return new Response.Ok(result);

        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Calculate documentation completeness score for a function.
     */
    public double calculateCompletenessScore(Function func, int undefinedCount,
            int plateCommentIssueCount, int hungarianViolationCount,
            int typeQualityIssueCount, int unrenamedGlobalsCount,
            int undocumentedOrdinalsCount, double commentDensity) {
        double score = 100.0;

        if (func.getName().startsWith("FUN_")) score -= 30;
        if (func.getSignature() == null) score -= 20;
        if (func.getCallingConvention() == null) score -= 10;
        if (func.getComment() == null) score -= 20;
        score -= (undefinedCount * 5);
        score -= (plateCommentIssueCount * 5);
        score -= (hungarianViolationCount * 3);
        score -= (typeQualityIssueCount * 15);
        score -= (unrenamedGlobalsCount * 3);
        score -= (undocumentedOrdinalsCount * 2);

        if (commentDensity < 1.0 && func.getComment() != null) {
            score -= 5;
        }

        return Math.max(0, score);
    }

    // =========================================================================
    // PRIVATE HELPERS — Hashing
    // =========================================================================

    /**
     * Compute a normalized opcode hash for function matching.
     * Normalizes addresses and large immediates so that functions compiled to
     * different base addresses still hash identically when structurally equivalent.
     */
    private String computeNormalizedFunctionHash(Program program, Function func) {
        StringBuilder normalized = new StringBuilder();
        Listing listing = program.getListing();
        AddressSetView functionBody = func.getBody();
        InstructionIterator instructions = listing.getInstructions(functionBody, true);

        while (instructions.hasNext()) {
            Instruction instr = instructions.next();
            normalized.append(instr.getMnemonicString()).append(":");

            int numOperands = instr.getNumOperands();
            for (int i = 0; i < numOperands; i++) {
                Object[] opObjects = instr.getOpObjects(i);
                if (opObjects.length > 0 && opObjects[0] instanceof ghidra.program.model.address.Address) {
                    ghidra.program.model.address.Address targetAddr = (ghidra.program.model.address.Address) opObjects[0];
                    if (functionBody.contains(targetAddr)) {
                        normalized.append("LOCAL");
                    } else {
                        Function targetFunc = program.getFunctionManager().getFunctionAt(targetAddr);
                        if (targetFunc != null) {
                            normalized.append("CALL_EXT");
                        } else {
                            normalized.append("DATA_EXT");
                        }
                    }
                } else if (opObjects.length > 0 && opObjects[0] instanceof ghidra.program.model.scalar.Scalar) {
                    ghidra.program.model.scalar.Scalar scalar = (ghidra.program.model.scalar.Scalar) opObjects[0];
                    long value = scalar.getValue();
                    if (Math.abs(value) < 0x10000) {
                        normalized.append("IMM:").append(value);
                    } else {
                        normalized.append("IMM_LARGE");
                    }
                } else {
                    normalized.append(instr.getDefaultOperandRepresentation(i));
                }

                if (i < numOperands - 1) {
                    normalized.append(",");
                }
            }
            normalized.append(";");
        }

        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(normalized.toString().getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            return Integer.toHexString(normalized.toString().hashCode());
        }
    }

    /**
     * Compute a normalized hash from function instructions for documentation propagation.
     * Uses operand type flags and reference types for more precise normalization
     * than the basic hash used for index lookups.
     */
    private String computeDocumentationHash(Program program, Function func) {
        StringBuilder normalized = new StringBuilder();
        Listing listing = program.getListing();
        AddressSetView functionBody = func.getBody();
        InstructionIterator instructions = listing.getInstructions(functionBody, true);

        Address funcStart = func.getEntryPoint();

        while (instructions.hasNext()) {
            Instruction instr = instructions.next();

            normalized.append(instr.getMnemonicString()).append(" ");

            int numOperands = instr.getNumOperands();
            for (int i = 0; i < numOperands; i++) {
                int opType = instr.getOperandType(i);

                boolean isAddressRef = (opType & ghidra.program.model.lang.OperandType.ADDRESS) != 0 ||
                                       (opType & ghidra.program.model.lang.OperandType.CODE) != 0 ||
                                       (opType & ghidra.program.model.lang.OperandType.DATA) != 0;

                if (isAddressRef) {
                    Reference[] refs = instr.getOperandReferences(i);
                    if (refs.length > 0) {
                        Address targetAddr = refs[0].getToAddress();
                        if (functionBody.contains(targetAddr)) {
                            long relOffset = targetAddr.subtract(funcStart);
                            normalized.append("REL+").append(relOffset);
                        } else {
                            RefType refType = refs[0].getReferenceType();
                            if (refType.isCall()) {
                                normalized.append("CALL_EXT");
                            } else if (refType.isData()) {
                                normalized.append("DATA_EXT");
                            } else {
                                normalized.append("EXT_REF");
                            }
                        }
                    } else {
                        normalized.append("ADDR");
                    }
                } else if ((opType & ghidra.program.model.lang.OperandType.REGISTER) != 0) {
                    normalized.append(instr.getDefaultOperandRepresentation(i));
                } else if ((opType & ghidra.program.model.lang.OperandType.SCALAR) != 0) {
                    Object[] opObjects = instr.getOpObjects(i);
                    if (opObjects.length > 0 && opObjects[0] instanceof ghidra.program.model.scalar.Scalar) {
                        ghidra.program.model.scalar.Scalar scalar = (ghidra.program.model.scalar.Scalar) opObjects[0];
                        long value = scalar.getValue();
                        if (Math.abs(value) < 0x10000) {
                            normalized.append("IMM:").append(value);
                        } else {
                            normalized.append("IMM_LARGE");
                        }
                    } else {
                        normalized.append(instr.getDefaultOperandRepresentation(i));
                    }
                } else {
                    normalized.append(instr.getDefaultOperandRepresentation(i));
                }

                if (i < numOperands - 1) {
                    normalized.append(",");
                }
            }

            normalized.append(";");
        }

        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(normalized.toString().getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (java.security.NoSuchAlgorithmException e) {
            return Integer.toHexString(normalized.toString().hashCode());
        }
    }

    /**
     * Count instructions in a function body.
     */
    private int countFunctionInstructions(Program program, Function func) {
        Listing listing = program.getListing();
        AddressSetView functionBody = func.getBody();
        InstructionIterator instructions = listing.getInstructions(functionBody, true);
        int count = 0;
        while (instructions.hasNext()) {
            instructions.next();
            count++;
        }
        return count;
    }

    // =========================================================================
    // PRIVATE HELPERS — Decompilation
    // =========================================================================

    private DecompileResults decompileFunction(Function func, Program program) {
        DecompInterface decomp = null;
        try {
            decomp = new DecompInterface();
            decomp.openProgram(program);
            decomp.setSimplificationStyle("decompile");
            DecompileResults results = decomp.decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS, monitor);
            if (results != null && results.decompileCompleted()) {
                return results;
            }
            return null;
        } catch (Exception e) {
            return null;
        } finally {
            if (decomp != null) {
                decomp.dispose();
            }
        }
    }

    // =========================================================================
    // PRIVATE HELPERS — Data Type Resolution
    // =========================================================================

    private DataType findDataTypeByName(DataTypeManager dtm, String typeName) {
        DataType result = searchByNameInAllCategories(dtm, typeName);
        if (result != null) {
            return result;
        }
        return searchByNameInAllCategories(dtm, typeName.toLowerCase());
    }

    private DataType searchByNameInAllCategories(DataTypeManager dtm, String name) {
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            if (dt.getName().equals(name)) {
                return dt;
            }
            if (dt.getName().equalsIgnoreCase(name)) {
                return dt;
            }
        }
        return null;
    }

    // =========================================================================
    // PRIVATE HELPERS — JSON Extraction (for documentation propagation)
    // =========================================================================

    private String extractJsonString(String json, String key) {
        String pattern = "\"" + key + "\"\\s*:\\s*\"([^\"]*)\"";
        java.util.regex.Pattern p = java.util.regex.Pattern.compile(pattern);
        java.util.regex.Matcher m = p.matcher(json);
        if (m.find()) {
            return m.group(1).replace("\\\"", "\"").replace("\\n", "\n");
        }
        pattern = "\"" + key + "\"\\s*:\\s*null";
        if (json.matches(".*" + pattern + ".*")) {
            return null;
        }
        return null;
    }

    private String extractJsonArray(String json, String key) {
        int startIdx = json.indexOf("\"" + key + "\"");
        if (startIdx < 0) return null;

        int arrayStart = json.indexOf('[', startIdx);
        if (arrayStart < 0) return null;

        int depth = 1;
        int arrayEnd = arrayStart + 1;
        while (arrayEnd < json.length() && depth > 0) {
            char c = json.charAt(arrayEnd);
            if (c == '[') depth++;
            else if (c == ']') depth--;
            arrayEnd++;
        }

        return json.substring(arrayStart, arrayEnd);
    }

    // =========================================================================
    // PRIVATE HELPERS — Documentation Application
    // =========================================================================

    private void applyParameterDocumentation(Function func, Program program, String paramsJson, AtomicInteger changesApplied) {
        java.util.regex.Pattern p = java.util.regex.Pattern.compile(
            "\\{\\s*\"ordinal\"\\s*:\\s*(\\d+).*?\"name\"\\s*:\\s*\"([^\"]*)\".*?\"type\"\\s*:\\s*\"([^\"]*)\"");
        java.util.regex.Matcher m = p.matcher(paramsJson);

        Parameter[] params = func.getParameters();
        while (m.find()) {
            try {
                int ordinal = Integer.parseInt(m.group(1));
                String name = m.group(2);
                String typeName = m.group(3);

                if (ordinal < params.length) {
                    Parameter param = params[ordinal];

                    if (!name.startsWith("param_") && !name.equals(param.getName())) {
                        try {
                            param.setName(name, SourceType.USER_DEFINED);
                            changesApplied.incrementAndGet();
                        } catch (Exception e) {
                            Msg.warn(ComparisonService.class, "Could not set parameter name: " + e.getMessage());
                        }
                    }

                    if (!typeName.startsWith("undefined") && !typeName.equals(param.getDataType().getName())) {
                        DataType dt = findDataTypeByName(program.getDataTypeManager(), typeName);
                        if (dt != null) {
                            try {
                                param.setDataType(dt, SourceType.USER_DEFINED);
                                changesApplied.incrementAndGet();
                            } catch (Exception e) {
                                Msg.warn(ComparisonService.class, "Could not set parameter type: " + e.getMessage());
                            }
                        }
                    }
                }
            } catch (Exception e) {
                // Skip this parameter
            }
        }
    }

    private void applyCommentsDocumentation(Function func, Program program, String commentsJson, AtomicInteger changesApplied) {
        java.util.regex.Pattern p = java.util.regex.Pattern.compile(
            "\\{\\s*\"relative_offset\"\\s*:\\s*(\\d+)");
        java.util.regex.Matcher m = p.matcher(commentsJson);

        Address funcStart = func.getEntryPoint();
        Listing listing = program.getListing();

        while (m.find()) {
            try {
                long relOffset = Long.parseLong(m.group(1));
                Address commentAddr = funcStart.add(relOffset);

                int entryStart = m.start();
                int entryEnd = commentsJson.indexOf('}', entryStart);
                if (entryEnd < 0) continue;
                String entry = commentsJson.substring(entryStart, entryEnd + 1);

                String eolComment = extractJsonString(entry, "eol_comment");
                String preComment = extractJsonString(entry, "pre_comment");

                CodeUnit cu = listing.getCodeUnitAt(commentAddr);
                if (cu != null) {
                    if (eolComment != null && !eolComment.isEmpty()) {
                        cu.setComment(CodeUnit.EOL_COMMENT, eolComment);
                        changesApplied.incrementAndGet();
                    }
                    if (preComment != null && !preComment.isEmpty()) {
                        cu.setComment(CodeUnit.PRE_COMMENT, preComment);
                        changesApplied.incrementAndGet();
                    }
                }
            } catch (Exception e) {
                // Skip this comment
            }
        }
    }

    private void applyLabelsDocumentation(Function func, Program program, String labelsJson, AtomicInteger changesApplied) {
        java.util.regex.Pattern p = java.util.regex.Pattern.compile(
            "\\{\\s*\"relative_offset\"\\s*:\\s*(\\d+).*?\"name\"\\s*:\\s*\"([^\"]*)\"");
        java.util.regex.Matcher m = p.matcher(labelsJson);

        Address funcStart = func.getEntryPoint();
        SymbolTable symTable = program.getSymbolTable();

        while (m.find()) {
            try {
                long relOffset = Long.parseLong(m.group(1));
                String labelName = m.group(2);

                Address labelAddr = funcStart.add(relOffset);

                Symbol existing = symTable.getPrimarySymbol(labelAddr);
                if (existing == null || existing.getSymbolType() != SymbolType.LABEL ||
                    !existing.getName().equals(labelName)) {
                    try {
                        symTable.createLabel(labelAddr, labelName, SourceType.USER_DEFINED);
                        changesApplied.incrementAndGet();
                    } catch (Exception e) {
                        Msg.warn(ComparisonService.class, "Could not create label: " + e.getMessage());
                    }
                }
            } catch (Exception e) {
                // Skip this label
            }
        }
    }
}
