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
import com.xebyte.core.JsonHelper;
import com.xebyte.core.ProgramProvider;
import com.xebyte.core.Response;
import com.xebyte.core.ThreadingStrategy;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
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
import ghidra.util.task.TaskMonitor;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Analysis service for byte pattern search, data region analysis, control flow,
 * malware analysis, similarity detection, memory inspection, and more.
 */
public class AnalysisService extends BaseService {

    private static final int MAX_STRUCT_FIELDS = 256;
    private static final int MAX_FIELD_OFFSET = 65536;
    private static final int DECOMPILE_TIMEOUT_SECONDS = 60;

    private final DataTypeService dataTypeService;
    private final ComparisonService comparisonService;

    public AnalysisService(ProgramProvider programProvider, ThreadingStrategy threadingStrategy) {
        this(programProvider, threadingStrategy, null, null);
    }

    public AnalysisService(ProgramProvider programProvider, ThreadingStrategy threadingStrategy,
                           DataTypeService dataTypeService, ComparisonService comparisonService) {
        super(programProvider, threadingStrategy);
        this.dataTypeService = dataTypeService;
        this.comparisonService = comparisonService;
    }

    // ========================================================================
    // Byte pattern search, data region, array bounds, assembly context,
    // struct field usage, field access context
    // ========================================================================

    /**
     * Search memory for hex byte patterns with wildcards (??)
     */
    public Response searchBytePatterns(String pattern, String mask) {
        Program program = resolveProgram(null);
        if (program == null) {
            return programNotFoundError(null);
        }

        if (pattern == null || pattern.trim().isEmpty()) {
            return Response.err("Pattern is required");
        }

        try {
            String cleanPattern = pattern.trim().toUpperCase().replaceAll("\\s+", "");

            int patternLen = cleanPattern.length() / 2;
            byte[] patternBytes = new byte[patternLen];
            byte[] maskBytes = new byte[patternLen];

            int byteIndex = 0;
            for (int i = 0; i < cleanPattern.length() && byteIndex < patternLen; i += 2) {
                if (cleanPattern.charAt(i) == '?' ||
                    (i + 1 < cleanPattern.length() && cleanPattern.charAt(i + 1) == '?')) {
                    patternBytes[byteIndex] = 0;
                    maskBytes[byteIndex] = 0;
                } else {
                    String hexByte = cleanPattern.substring(i, Math.min(i + 2, cleanPattern.length()));
                    patternBytes[byteIndex] = (byte) Integer.parseInt(hexByte, 16);
                    maskBytes[byteIndex] = (byte) 0xFF;
                }
                byteIndex++;
            }

            Memory memory = program.getMemory();
            List<Object> matches = new ArrayList<>();
            final int MAX_MATCHES = 1000;

            for (MemoryBlock block : memory.getBlocks()) {
                if (!block.isInitialized()) continue;

                Address blockStart = block.getStart();
                long blockSize = block.getSize();

                byte[] blockData = new byte[(int) Math.min(blockSize, Integer.MAX_VALUE)];
                try {
                    block.getBytes(blockStart, blockData);
                } catch (Exception e) {
                    continue;
                }

                for (int i = 0; i <= blockData.length - patternBytes.length; i++) {
                    boolean found = true;
                    for (int j = 0; j < patternBytes.length; j++) {
                        if (maskBytes[j] != 0 && blockData[i + j] != patternBytes[j]) {
                            found = false;
                            break;
                        }
                    }

                    if (found) {
                        Address matchAddr = blockStart.add(i);
                        matches.add(Map.of("address", matchAddr.toString()));

                        if (matches.size() >= MAX_MATCHES) {
                            matches.add(Map.of("note", "Limited to " + MAX_MATCHES + " matches"));
                            break;
                        }
                    }
                }

                if (matches.size() >= MAX_MATCHES) break;
            }

            if (matches.isEmpty()) {
                matches.add(Map.of("note", "No matches found"));
            }

            return Response.ok(matches);
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Analyze a data region comprehensively
     */
    public Response analyzeDataRegion(String startAddressStr, int maxScanBytes,
                                      boolean includeXrefMap, boolean includeAssemblyPatterns,
                                      boolean includeBoundaryDetection) {
        Program program = resolveProgram(null);
        if (program == null) {
            return programNotFoundError(null);
        }

        try {
            Address startAddr = program.getAddressFactory().getAddress(startAddressStr);
            if (startAddr == null) {
                return Response.err("Invalid address: " + startAddressStr);
            }

            ReferenceManager refMgr = program.getReferenceManager();
            Listing listing = program.getListing();

            Address endAddr = startAddr;
            Set<String> uniqueXrefs = new HashSet<>();
            int byteCount = 0;
            Map<String, List<String>> xrefMap = includeXrefMap ? new LinkedHashMap<>() : null;

            for (int i = 0; i < maxScanBytes; i++) {
                Address scanAddr = startAddr.add(i);

                if (includeBoundaryDetection) {
                    Symbol[] symbols = program.getSymbolTable().getSymbols(scanAddr);
                    if (symbols.length > 0 && i > 0) {
                        boolean hitBoundary = false;
                        for (Symbol sym : symbols) {
                            String name = sym.getName();
                            if (!name.startsWith("DAT_") && !name.equals(startAddr.toString())) {
                                endAddr = scanAddr.subtract(1);
                                byteCount = i;
                                hitBoundary = true;
                                break;
                            }
                        }
                        if (hitBoundary) break;
                    }
                }

                ReferenceIterator refIter = refMgr.getReferencesTo(scanAddr);
                List<String> refsAtThisByte = new ArrayList<>();

                while (refIter.hasNext()) {
                    Reference ref = refIter.next();
                    String fromAddr = ref.getFromAddress().toString();
                    refsAtThisByte.add(fromAddr);
                    uniqueXrefs.add(fromAddr);
                }

                if (includeXrefMap && !refsAtThisByte.isEmpty()) {
                    xrefMap.put(scanAddr.toString(), refsAtThisByte);
                }

                endAddr = scanAddr;
                byteCount = i + 1;
            }

            Data data = listing.getDataAt(startAddr);
            String currentName = (data != null && data.getLabel() != null) ?
                                data.getLabel() : "DAT_" + startAddr.toString().replace(":", "");
            String currentType = (data != null) ?
                                data.getDataType().getName() : "undefined";

            String classification = "PRIMITIVE";
            if (uniqueXrefs.size() > 3) {
                classification = "ARRAY";
            } else if (uniqueXrefs.size() > 1) {
                classification = "STRUCTURE";
            }

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("start_address", startAddr.toString());
            result.put("end_address", endAddr.toString());
            result.put("byte_span", byteCount);
            if (includeXrefMap) {
                result.put("xref_map", xrefMap);
            }
            result.put("unique_xref_addresses", new ArrayList<>(uniqueXrefs));
            result.put("xref_count", uniqueXrefs.size());
            result.put("classification_hint", classification);
            result.put("current_name", currentName);
            result.put("current_type", currentType);

            return Response.ok(result);
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Detect array bounds based on xref analysis
     */
    public Response detectArrayBounds(String addressStr, boolean analyzeLoopBounds,
                                      boolean analyzeIndexing, int maxScanRange) {
        Program program = resolveProgram(null);
        if (program == null) {
            return programNotFoundError(null);
        }

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) {
                return Response.err("Invalid address: " + addressStr);
            }

            ReferenceManager refMgr = program.getReferenceManager();
            int estimatedSize = 0;
            Address scanAddr = addr;

            for (int i = 0; i < maxScanRange; i++) {
                ReferenceIterator refIter = refMgr.getReferencesTo(scanAddr);
                if (refIter.hasNext()) {
                    estimatedSize = i + 1;
                }

                Symbol[] symbols = program.getSymbolTable().getSymbols(scanAddr);
                if (symbols.length > 0 && i > 0) {
                    for (Symbol sym : symbols) {
                        if (!sym.getName().startsWith("DAT_")) {
                            break;
                        }
                    }
                }

                scanAddr = scanAddr.add(1);
            }

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("address", addr.toString());
            result.put("estimated_size", estimatedSize);
            result.put("stride", 1);
            result.put("element_count", estimatedSize);
            result.put("confidence", "medium");
            result.put("detection_method", "xref_analysis");

            return Response.ok(result);
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Get assembly context around xref sources
     */
    public Response getAssemblyContext(String xrefSourcesStr, int contextInstructions, String includePatterns) {
        Program program = resolveProgram(null);
        if (program == null) {
            return programNotFoundError(null);
        }

        try {
            String[] addresses = xrefSourcesStr.split(",");
            Listing listing = program.getListing();
            Map<String, Object> result = new LinkedHashMap<>();

            for (String addrStr : addresses) {
                addrStr = addrStr.trim();
                if (addrStr.isEmpty()) continue;

                Map<String, Object> entry = new LinkedHashMap<>();
                try {
                    Address addr = program.getAddressFactory().getAddress(addrStr);
                    if (addr != null) {
                        Instruction instr = listing.getInstructionAt(addr);
                        entry.put("address", addrStr);

                        if (instr != null) {
                            entry.put("instruction", instr.toString());

                            List<String> contextBefore = new ArrayList<>();
                            Address prevAddr = addr;
                            for (int i = 0; i < contextInstructions; i++) {
                                Instruction prevInstr = listing.getInstructionBefore(prevAddr);
                                if (prevInstr == null) break;
                                prevAddr = prevInstr.getAddress();
                                contextBefore.add(prevAddr + ": " + prevInstr.toString());
                            }
                            entry.put("context_before", contextBefore);

                            List<String> contextAfter = new ArrayList<>();
                            Address nextAddr = addr;
                            for (int i = 0; i < contextInstructions; i++) {
                                Instruction nextInstr = listing.getInstructionAfter(nextAddr);
                                if (nextInstr == null) break;
                                nextAddr = nextInstr.getAddress();
                                contextAfter.add(nextAddr + ": " + nextInstr.toString());
                            }
                            entry.put("context_after", contextAfter);

                            entry.put("mnemonic", instr.getMnemonicString());
                        } else {
                            entry.put("error", "No instruction at address");
                        }
                    } else {
                        entry.put("error", "Invalid address");
                    }
                } catch (Exception e) {
                    entry.put("error", e.getMessage());
                }

                result.put(addrStr, entry);
            }

            return Response.ok(result);
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Analyze how structure fields are accessed
     */
    public Response analyzeStructFieldUsage(String addressStr, String structName, int maxFunctions) {
        Program program = resolveProgram(null);
        if (program == null) {
            return programNotFoundError(null);
        }

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) {
                return Response.err("Invalid address: " + addressStr);
            }

            ReferenceManager refMgr = program.getReferenceManager();
            ReferenceIterator refIter = refMgr.getReferencesTo(addr);

            List<String> referencingFunctions = new ArrayList<>();
            Set<String> uniqueFuncs = new HashSet<>();

            while (refIter.hasNext() && uniqueFuncs.size() < maxFunctions) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                Function func = program.getFunctionManager().getFunctionContaining(fromAddr);
                if (func != null && !uniqueFuncs.contains(func.getName())) {
                    uniqueFuncs.add(func.getName());
                    referencingFunctions.add(func.getName() + " @ " + func.getEntryPoint());
                }
            }

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("struct_address", addr.toString());
            result.put("struct_name", structName);
            result.put("functions_analyzed", referencingFunctions.size());
            result.put("referencing_functions", referencingFunctions);

            return Response.ok(result);
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Get field access context for a structure field
     */
    public Response getFieldAccessContext(String structAddressStr, int fieldOffset, int numExamples) {
        Program program = resolveProgram(null);
        if (program == null) {
            return programNotFoundError(null);
        }

        try {
            Address structAddr = program.getAddressFactory().getAddress(structAddressStr);
            if (structAddr == null) {
                return Response.err("Invalid address: " + structAddressStr);
            }

            Address fieldAddr = structAddr.add(fieldOffset);
            ReferenceManager refMgr = program.getReferenceManager();
            ReferenceIterator refIter = refMgr.getReferencesTo(fieldAddr);

            List<Map<String, String>> examples = new ArrayList<>();
            Listing listing = program.getListing();

            while (refIter.hasNext() && examples.size() < numExamples) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                Instruction instr = listing.getInstructionAt(fromAddr);
                Function func = program.getFunctionManager().getFunctionContaining(fromAddr);

                Map<String, String> example = new LinkedHashMap<>();
                example.put("from_address", fromAddr.toString());
                example.put("ref_type", ref.getReferenceType().getName());
                if (instr != null) {
                    example.put("instruction", instr.toString());
                }
                if (func != null) {
                    example.put("function", func.getName());
                }
                examples.add(example);
            }

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("struct_address", structAddr.toString());
            result.put("field_offset", fieldOffset);
            result.put("field_address", fieldAddr.toString());
            result.put("examples", examples);

            return Response.ok(result);
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    // ========================================================================
    // Analyzers and auto-analysis
    // ========================================================================

    /**
     * List all registered analyzers and their enabled/disabled state.
     */
    public Response listAnalyzers(String programName) {
        Program program = resolveProgram(programName);
        if (program == null) return programNotFoundError(programName);

        try {
            Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
            List<String> names = options.getOptionNames();
            List<Map<String, Object>> entries = new ArrayList<>();
            for (String name : names) {
                try {
                    boolean enabled = options.getBoolean(name, false);
                    entries.add(Map.of("name", name, "enabled", enabled));
                } catch (Exception ignored) {}
            }
            return Response.ok(Map.of("analyzers", entries, "count", entries.size()));
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Trigger auto-analysis on the current or named program.
     */
    public Response runAnalysis(String programName) {
        Program program = resolveProgram(programName);
        if (program == null) return programNotFoundError(programName);

        try {
            return threadingStrategy.executeWrite(program, "Run Auto Analysis", () -> {
                long start = System.currentTimeMillis();
                int before = program.getFunctionManager().getFunctionCount();

                ghidra.app.plugin.core.analysis.AutoAnalysisManager mgr =
                    ghidra.app.plugin.core.analysis.AutoAnalysisManager.getAnalysisManager(program);
                mgr.initializeOptions();
                mgr.reAnalyzeAll(program.getMemory().getLoadedAndInitializedAddressSet());
                mgr.startAnalysis(TaskMonitor.DUMMY);

                long duration = System.currentTimeMillis() - start;
                int after = program.getFunctionManager().getFunctionCount();
                Map<String, Object> result = new LinkedHashMap<>();
                result.put("success", true);
                result.put("duration_ms", duration);
                result.put("total_functions", after);
                result.put("new_functions", after - before);
                result.put("program", program.getName());
                return Response.ok(result);
            });
        } catch (Exception e) {
            return Response.err("Analysis failed: " + e.getMessage());
        }
    }

    // ========================================================================
    // Memory read and inspection
    // ========================================================================

    /**
     * Read raw memory bytes at an address.
     */
    public Response readMemory(String addressStr, int length, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) return programNotFoundError(programName);

        try {
            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                return Response.err("Invalid address: " + addressStr);
            }

            Memory memory = program.getMemory();
            byte[] bytes = new byte[length];
            int bytesRead = memory.getBytes(address, bytes);

            int[] dataInts = new int[bytesRead];
            StringBuilder hexBuilder = new StringBuilder();
            for (int i = 0; i < bytesRead; i++) {
                dataInts[i] = bytes[i] & 0xFF;
                hexBuilder.append(String.format("%02x", dataInts[i]));
            }

            JsonObject jo = new JsonObject();
            jo.addProperty("addr", address.toString());
            jo.addProperty("read_length", bytesRead);
            jo.add("data", JsonHelper.gson().toJsonTree(dataInts));
            jo.addProperty("hex", hexBuilder.toString());
            return new Response.Ok(jo);
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Memory content inspection with string detection heuristics.
     */
    public Response inspectMemoryContent(String addressStr, int length, boolean detectStrings) {
        Program program = resolveProgram(null);
        if (program == null) return Response.err("No program loaded");

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) {
                return Response.err("Invalid address: " + addressStr);
            }

            Memory memory = program.getMemory();
            byte[] bytes = new byte[length];
            int bytesRead = memory.getBytes(addr, bytes);

            StringBuilder hexDump = new StringBuilder();
            StringBuilder asciiRepr = new StringBuilder();

            for (int i = 0; i < bytesRead; i++) {
                if (i > 0 && i % 16 == 0) {
                    hexDump.append("\\n");
                    asciiRepr.append("\\n");
                }

                hexDump.append(String.format("%02X ", bytes[i] & 0xFF));

                char c = (char) (bytes[i] & 0xFF);
                if (c >= 0x20 && c <= 0x7E) {
                    asciiRepr.append(c);
                } else if (c == 0x00) {
                    asciiRepr.append("\\0");
                } else {
                    asciiRepr.append(".");
                }
            }

            boolean likelyString = false;
            int printableCount = 0;
            int nullTerminatorIndex = -1;
            int consecutivePrintable = 0;
            int maxConsecutivePrintable = 0;

            for (int i = 0; i < bytesRead; i++) {
                char c = (char) (bytes[i] & 0xFF);

                if (c >= 0x20 && c <= 0x7E) {
                    printableCount++;
                    consecutivePrintable++;
                    if (consecutivePrintable > maxConsecutivePrintable) {
                        maxConsecutivePrintable = consecutivePrintable;
                    }
                } else {
                    consecutivePrintable = 0;
                }

                if (c == 0x00 && nullTerminatorIndex == -1) {
                    nullTerminatorIndex = i;
                }
            }

            double printableRatio = (double) printableCount / bytesRead;

            if (detectStrings) {
                likelyString = (printableRatio >= 0.6) ||
                              (maxConsecutivePrintable >= 4 && nullTerminatorIndex > 0);
            }

            String detectedString = null;
            int stringLength = 0;
            if (likelyString && nullTerminatorIndex > 0) {
                detectedString = new String(bytes, 0, nullTerminatorIndex, StandardCharsets.US_ASCII);
                stringLength = nullTerminatorIndex + 1;
            } else if (likelyString && printableRatio >= 0.8) {
                int endIdx = bytesRead;
                for (int i = bytesRead - 1; i >= 0; i--) {
                    if ((bytes[i] & 0xFF) >= 0x20 && (bytes[i] & 0xFF) <= 0x7E) {
                        endIdx = i + 1;
                        break;
                    }
                }
                detectedString = new String(bytes, 0, endIdx, StandardCharsets.US_ASCII);
                stringLength = endIdx;
            }

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("address", addressStr);
            result.put("bytes_read", bytesRead);
            result.put("hex_dump", hexDump.toString().trim());
            result.put("ascii_repr", asciiRepr.toString().trim());
            result.put("printable_count", printableCount);
            result.put("printable_ratio", Double.parseDouble(String.format("%.2f", printableRatio)));
            result.put("null_terminator_at", nullTerminatorIndex);
            result.put("max_consecutive_printable", maxConsecutivePrintable);
            result.put("is_likely_string", likelyString);
            result.put("detected_string", detectedString);
            result.put("suggested_type", detectedString != null ? "char[" + stringLength + "]" : null);
            result.put("string_length", detectedString != null ? stringLength : 0);
            return new Response.Ok(result);
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    // ========================================================================
    // Crypto detection, function similarity, control flow analysis
    // ========================================================================

    /**
     * Detect cryptographic constants in the binary (AES S-boxes, SHA constants, etc.)
     */
    public Response detectCryptoConstants() {
        Program program = resolveProgram(null);
        if (program == null) {
            return Response.err("No program loaded");
        }

        Map<String, Object> placeholder = new LinkedHashMap<>();
        placeholder.put("algorithm", "Crypto Detection");
        placeholder.put("status", "Not yet implemented");
        placeholder.put("note", "This endpoint requires advanced pattern matching against known crypto constants");
        return new Response.Ok(List.of(placeholder));
    }

    /**
     * Find functions structurally similar to the target function.
     * Uses basic block count, instruction count, call count, and cyclomatic complexity.
     */
    public Response findSimilarFunctions(String targetFunction, double threshold) {
        Program program = resolveProgram(null);
        if (program == null) {
            return Response.err("No program loaded");
        }

        if (targetFunction == null || targetFunction.trim().isEmpty()) {
            return Response.err("Target function name is required");
        }

        try {
            FunctionManager functionManager = program.getFunctionManager();
            Function targetFunc = null;

            for (Function f : functionManager.getFunctions(true)) {
                if (f.getName().equals(targetFunction)) {
                    targetFunc = f;
                    break;
                }
            }

            if (targetFunc == null) {
                return Response.err("Function not found: " + targetFunction);
            }

            BasicBlockModel blockModel = new BasicBlockModel(program);
            FunctionMetrics targetMetrics = calculateFunctionMetrics(targetFunc, blockModel, program);

            List<Map<String, Object>> similarFunctions = new ArrayList<>();

            for (Function func : functionManager.getFunctions(true)) {
                if (func.getName().equals(targetFunction)) continue;
                if (func.isThunk()) continue;

                FunctionMetrics funcMetrics = calculateFunctionMetrics(func, blockModel, program);
                double similarity = calculateSimilarity(targetMetrics, funcMetrics);

                if (similarity >= threshold) {
                    Map<String, Object> match = new LinkedHashMap<>();
                    match.put("name", func.getName());
                    match.put("address", func.getEntryPoint().toString());
                    match.put("similarity", Math.round(similarity * 1000.0) / 1000.0);
                    match.put("basic_blocks", funcMetrics.basicBlockCount);
                    match.put("instructions", funcMetrics.instructionCount);
                    match.put("calls", funcMetrics.callCount);
                    match.put("complexity", funcMetrics.cyclomaticComplexity);
                    similarFunctions.add(match);
                }
            }

            similarFunctions.sort((a, b) -> Double.compare((Double)b.get("similarity"), (Double)a.get("similarity")));

            if (similarFunctions.size() > 50) {
                similarFunctions = similarFunctions.subList(0, 50);
            }

            Map<String, Object> targetMetricsMap = new LinkedHashMap<>();
            targetMetricsMap.put("basic_blocks", targetMetrics.basicBlockCount);
            targetMetricsMap.put("instructions", targetMetrics.instructionCount);
            targetMetricsMap.put("calls", targetMetrics.callCount);
            targetMetricsMap.put("complexity", targetMetrics.cyclomaticComplexity);

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("target_function", targetFunction);
            result.put("target_metrics", targetMetricsMap);
            result.put("threshold", threshold);
            result.put("matches_found", similarFunctions.size());
            result.put("similar_functions", similarFunctions);
            return new Response.Ok(result);
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Analyze function control flow complexity.
     * Calculates cyclomatic complexity, basic blocks, edges, and detailed metrics.
     */
    public Response analyzeControlFlow(String functionName) {
        Program program = resolveProgram(null);
        if (program == null) {
            return Response.err("No program loaded");
        }

        if (functionName == null || functionName.trim().isEmpty()) {
            return Response.err("Function name is required");
        }

        try {
            FunctionManager functionManager = program.getFunctionManager();
            Function func = null;

            for (Function f : functionManager.getFunctions(true)) {
                if (f.getName().equals(functionName)) {
                    func = f;
                    break;
                }
            }

            if (func == null) {
                return Response.err("Function not found: " + functionName);
            }

            BasicBlockModel blockModel = new BasicBlockModel(program);
            Listing listing = program.getListing();
            ReferenceManager refManager = program.getReferenceManager();

            int basicBlockCount = 0;
            int edgeCount = 0;
            int conditionalBranches = 0;
            int unconditionalJumps = 0;
            int loops = 0;
            int instructionCount = 0;
            int callCount = 0;
            int returnCount = 0;
            List<Map<String, Object>> blocks = new ArrayList<>();
            Set<Address> blockEntries = new HashSet<>();

            CodeBlockIterator blockIter = blockModel.getCodeBlocksContaining(func.getBody(), null);
            while (blockIter.hasNext()) {
                CodeBlock block = blockIter.next();
                blockEntries.add(block.getFirstStartAddress());
            }

            blockIter = blockModel.getCodeBlocksContaining(func.getBody(), null);
            while (blockIter.hasNext()) {
                CodeBlock block = blockIter.next();
                basicBlockCount++;

                Map<String, Object> blockInfo = new LinkedHashMap<>();
                blockInfo.put("address", block.getFirstStartAddress().toString());
                blockInfo.put("size", block.getNumAddresses());

                int outEdges = 0;
                boolean hasBackEdge = false;
                List<String> successors = new ArrayList<>();

                CodeBlockReferenceIterator destIter = block.getDestinations(null);
                while (destIter.hasNext()) {
                    CodeBlockReference ref = destIter.next();
                    outEdges++;
                    edgeCount++;
                    Address destAddr = ref.getDestinationAddress();
                    successors.add(destAddr.toString());

                    if (destAddr.compareTo(block.getFirstStartAddress()) < 0 &&
                        blockEntries.contains(destAddr)) {
                        hasBackEdge = true;
                    }
                }

                if (hasBackEdge) loops++;
                blockInfo.put("successors", successors.size());
                blockInfo.put("is_loop_header", hasBackEdge);

                if (outEdges == 0) {
                    blockInfo.put("type", "exit");
                } else if (outEdges == 1) {
                    blockInfo.put("type", "sequential");
                } else if (outEdges == 2) {
                    blockInfo.put("type", "conditional");
                    conditionalBranches++;
                } else {
                    blockInfo.put("type", "switch");
                }

                blocks.add(blockInfo);
            }

            InstructionIterator instrIter = listing.getInstructions(func.getBody(), true);
            while (instrIter.hasNext()) {
                Instruction instr = instrIter.next();
                instructionCount++;

                if (instr.getFlowType().isCall()) {
                    callCount++;
                } else if (instr.getFlowType().isTerminal()) {
                    returnCount++;
                } else if (instr.getFlowType().isJump()) {
                    if (!instr.getFlowType().isConditional()) {
                        unconditionalJumps++;
                    }
                }
            }

            int cyclomaticComplexity = edgeCount - basicBlockCount + 2;
            if (cyclomaticComplexity < 1) cyclomaticComplexity = 1;

            String complexityRating;
            if (cyclomaticComplexity <= 5) {
                complexityRating = "low";
            } else if (cyclomaticComplexity <= 10) {
                complexityRating = "moderate";
            } else if (cyclomaticComplexity <= 20) {
                complexityRating = "high";
            } else if (cyclomaticComplexity <= 50) {
                complexityRating = "very_high";
            } else {
                complexityRating = "extreme";
            }

            List<Map<String, Object>> blockDetails = blocks.subList(0, Math.min(blocks.size(), 100));
            if (blocks.size() > 100) {
                Map<String, Object> truncNote = new LinkedHashMap<>();
                truncNote.put("note", (blocks.size() - 100) + " additional blocks truncated");
                blockDetails = new ArrayList<>(blockDetails);
                blockDetails.add(truncNote);
            }

            Map<String, Object> metrics = new LinkedHashMap<>();
            metrics.put("cyclomatic_complexity", cyclomaticComplexity);
            metrics.put("complexity_rating", complexityRating);
            metrics.put("basic_blocks", basicBlockCount);
            metrics.put("edges", edgeCount);
            metrics.put("instructions", instructionCount);
            metrics.put("conditional_branches", conditionalBranches);
            metrics.put("unconditional_jumps", unconditionalJumps);
            metrics.put("loops_detected", loops);
            metrics.put("calls", callCount);
            metrics.put("returns", returnCount);

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("function_name", functionName);
            result.put("entry_point", func.getEntryPoint().toString());
            result.put("size_bytes", func.getBody().getNumAddresses());
            result.put("metrics", metrics);
            result.put("basic_block_details", blockDetails);
            return new Response.Ok(result);
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    // ========================================================================
    // Anti-analysis detection
    // ========================================================================

    /**
     * Detect anti-analysis and anti-debugging techniques.
     * Scans for known anti-debug APIs, timing checks, VM detection, and SEH tricks.
     */
    public Response findAntiAnalysisTechniques() {
        Program program = resolveProgram(null);
        if (program == null) {
            return Response.err("No program loaded");
        }

        try {
            Map<String, String[]> antiDebugAPIs = new LinkedHashMap<>();
            antiDebugAPIs.put("debugger_detection", new String[]{
                "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
                "OutputDebugString", "DebugActiveProcess", "CloseHandle", "NtClose"
            });
            antiDebugAPIs.put("timing_checks", new String[]{
                "GetTickCount", "GetTickCount64", "QueryPerformanceCounter",
                "GetSystemTimeAsFileTime", "timeGetTime", "NtQuerySystemTime"
            });
            antiDebugAPIs.put("process_enumeration", new String[]{
                "CreateToolhelp32Snapshot", "Process32First", "Process32Next",
                "EnumProcesses", "NtQuerySystemInformation", "OpenProcess"
            });
            antiDebugAPIs.put("vm_detection", new String[]{
                "GetSystemFirmwareTable", "EnumSystemFirmwareTable",
                "WMI", "SMBIOS", "ACPI"
            });
            antiDebugAPIs.put("exception_based", new String[]{
                "SetUnhandledExceptionFilter", "AddVectoredExceptionHandler",
                "RtlAddVectoredExceptionHandler", "NtSetInformationThread"
            });
            antiDebugAPIs.put("memory_checks", new String[]{
                "VirtualQuery", "NtQueryVirtualMemory", "ReadProcessMemory",
                "WriteProcessMemory"
            });

            String[] suspiciousInstructions = {"RDTSC", "CPUID", "INT 3", "INT 0x2d", "SIDT", "SGDT", "SLDT", "STR"};

            List<Map<String, Object>> findings = new ArrayList<>();
            FunctionManager functionManager = program.getFunctionManager();
            SymbolTable symbolTable = program.getSymbolTable();
            Listing listing = program.getListing();

            for (Map.Entry<String, String[]> category : antiDebugAPIs.entrySet()) {
                String categoryName = category.getKey();
                for (String apiName : category.getValue()) {
                    SymbolIterator symbols = symbolTable.getSymbolIterator("*" + apiName + "*", true);
                    while (symbols.hasNext()) {
                        Symbol sym = symbols.next();
                        ReferenceManager refManager = program.getReferenceManager();
                        ReferenceIterator refs = refManager.getReferencesTo(sym.getAddress());
                        while (refs.hasNext()) {
                            Reference ref = refs.next();
                            if (ref.getReferenceType().isCall()) {
                                Function callingFunc = functionManager.getFunctionContaining(ref.getFromAddress());
                                Map<String, Object> finding = new LinkedHashMap<>();
                                finding.put("category", categoryName);
                                finding.put("technique", apiName);
                                finding.put("address", ref.getFromAddress().toString());
                                finding.put("function", callingFunc != null ? callingFunc.getName() : "unknown");
                                finding.put("severity", getSeverity(categoryName));
                                findings.add(finding);
                            }
                        }
                    }
                }
            }

            for (Function func : functionManager.getFunctions(true)) {
                InstructionIterator instrIter = listing.getInstructions(func.getBody(), true);
                while (instrIter.hasNext()) {
                    Instruction instr = instrIter.next();
                    String mnemonic = instr.getMnemonicString().toUpperCase();

                    for (String suspicious : suspiciousInstructions) {
                        if (mnemonic.contains(suspicious.split(" ")[0])) {
                            Map<String, Object> finding = new LinkedHashMap<>();
                            finding.put("category", "suspicious_instruction");
                            finding.put("technique", suspicious);
                            finding.put("address", instr.getAddress().toString());
                            finding.put("function", func.getName());
                            finding.put("instruction", instr.toString());
                            finding.put("severity", "medium");
                            findings.add(finding);
                        }
                    }
                }
            }

            for (Function func : functionManager.getFunctions(true)) {
                InstructionIterator instrIter = listing.getInstructions(func.getBody(), true);
                boolean foundFsAccess = false;
                while (instrIter.hasNext()) {
                    Instruction instr = instrIter.next();
                    String instrStr = instr.toString().toUpperCase();
                    if (instrStr.contains("FS:") && (instrStr.contains("0X30") || instrStr.contains("0X18"))) {
                        if (!foundFsAccess) {
                            Map<String, Object> finding = new LinkedHashMap<>();
                            finding.put("category", "peb_teb_access");
                            finding.put("technique", "Direct PEB/TEB access");
                            finding.put("address", instr.getAddress().toString());
                            finding.put("function", func.getName());
                            finding.put("instruction", instr.toString());
                            finding.put("severity", "high");
                            finding.put("description", "Direct access to PEB/TEB can be used to detect debuggers");
                            findings.add(finding);
                            foundFsAccess = true;
                        }
                    }
                }
            }

            Map<String, Integer> categoryCounts = new LinkedHashMap<>();
            Map<String, Integer> severityCounts = new LinkedHashMap<>();
            for (Map<String, Object> finding : findings) {
                String cat = (String) finding.get("category");
                String sev = (String) finding.get("severity");
                categoryCounts.put(cat, categoryCounts.getOrDefault(cat, 0) + 1);
                severityCounts.put(sev, severityCounts.getOrDefault(sev, 0) + 1);
            }

            List<Map<String, Object>> findingsList = findings.subList(0, Math.min(findings.size(), 100));
            if (findings.size() > 100) {
                Map<String, Object> truncNote = new LinkedHashMap<>();
                truncNote.put("note", (findings.size() - 100) + " additional findings truncated");
                findingsList = new ArrayList<>(findingsList);
                findingsList.add(truncNote);
            }

            Map<String, Object> summary = new LinkedHashMap<>();
            summary.put("by_category", categoryCounts);
            summary.put("by_severity", severityCounts);

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("total_findings", findings.size());
            result.put("summary", summary);
            result.put("findings", findingsList);
            return new Response.Ok(result);
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    // ========================================================================
    // Batch decompile, dead code, auto-decrypt strings
    // ========================================================================

    /**
     * Batch decompile multiple functions.
     */
    public Response batchDecompileFunctions(String functionsParam) {
        Program program = resolveProgram(null);
        if (program == null) {
            return Response.err("No program loaded");
        }

        if (functionsParam == null || functionsParam.trim().isEmpty()) {
            return Response.err("Functions parameter is required");
        }

        try {
            String[] functionNames = functionsParam.split(",");
            Map<String, String> result = new LinkedHashMap<>();

            FunctionManager funcManager = program.getFunctionManager();
            final int MAX_FUNCTIONS = 20;

            for (int i = 0; i < functionNames.length && i < MAX_FUNCTIONS; i++) {
                String funcName = functionNames[i].trim();
                if (funcName.isEmpty()) continue;

                Function function = null;
                SymbolTable symbolTable = program.getSymbolTable();
                SymbolIterator symbols = symbolTable.getSymbols(funcName);

                while (symbols.hasNext()) {
                    Symbol symbol = symbols.next();
                    if (symbol.getSymbolType() == SymbolType.FUNCTION) {
                        function = funcManager.getFunctionAt(symbol.getAddress());
                        break;
                    }
                }

                if (function == null) {
                    result.put(funcName, "Error: Function not found");
                    continue;
                }

                try {
                    DecompInterface decompiler = new DecompInterface();
                    decompiler.openProgram(program);
                    DecompileResults decompResults = decompiler.decompileFunction(function, 30, null);

                    if (decompResults != null && decompResults.decompileCompleted()) {
                        result.put(funcName, decompResults.getDecompiledFunction().getC());
                    } else {
                        result.put(funcName, "Error: Decompilation failed");
                    }

                    decompiler.dispose();
                } catch (Exception e) {
                    result.put(funcName, "Error: " + e.getMessage());
                }
            }

            return new Response.Ok(result);
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Find potentially unreachable code blocks.
     */
    public Response findDeadCode(String functionName) {
        Program program = resolveProgram(null);
        if (program == null) {
            return Response.err("No program loaded");
        }

        if (functionName == null || functionName.trim().isEmpty()) {
            return Response.err("Function name is required");
        }

        Map<String, Object> placeholder = new LinkedHashMap<>();
        placeholder.put("function_name", functionName);
        placeholder.put("status", "Not yet implemented");
        placeholder.put("note", "This endpoint requires reachability analysis via control flow graph");
        return new Response.Ok(List.of(placeholder));
    }

    /**
     * Automatically identify and decrypt obfuscated strings.
     */
    public Response autoDecryptStrings() {
        Program program = resolveProgram(null);
        if (program == null) {
            return Response.err("No program loaded");
        }

        Map<String, Object> placeholder = new LinkedHashMap<>();
        placeholder.put("method", "String Decryption");
        placeholder.put("status", "Not yet implemented");
        placeholder.put("note", "This endpoint requires pattern detection and decryption of various encoding schemes");
        return new Response.Ok(List.of(placeholder));
    }

    // ========================================================================
    // API call chain analysis
    // ========================================================================

    /**
     * Identify and analyze suspicious API call chains.
     * Detects threat patterns like process injection, persistence, credential theft.
     */
    public Response analyzeAPICallChains() {
        Program program = resolveProgram(null);
        if (program == null) {
            return Response.err("No program loaded");
        }

        try {
            List<ThreatPattern> threatPatterns = new ArrayList<>();

            threatPatterns.add(new ThreatPattern("process_injection_classic",
                "Classic Process Injection", "critical",
                new String[]{"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"},
                "Allocates memory in remote process, writes code, and creates thread to execute"));

            threatPatterns.add(new ThreatPattern("process_injection_ntapi",
                "NT API Process Injection", "critical",
                new String[]{"NtOpenProcess", "NtAllocateVirtualMemory", "NtWriteVirtualMemory", "NtCreateThreadEx"},
                "Process injection using NT native APIs"));

            threatPatterns.add(new ThreatPattern("process_hollowing",
                "Process Hollowing", "critical",
                new String[]{"CreateProcess", "NtUnmapViewOfSection", "VirtualAllocEx", "WriteProcessMemory", "SetThreadContext", "ResumeThread"},
                "Creates suspended process, hollows it out, and replaces with malicious code"));

            threatPatterns.add(new ThreatPattern("dll_injection",
                "DLL Injection", "high",
                new String[]{"OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "LoadLibrary"},
                "Injects DLL into remote process"));

            threatPatterns.add(new ThreatPattern("registry_persistence",
                "Registry Persistence", "high",
                new String[]{"RegOpenKey", "RegSetValue"},
                "Modifies registry for persistence"));

            threatPatterns.add(new ThreatPattern("service_persistence",
                "Service Persistence", "high",
                new String[]{"OpenSCManager", "CreateService"},
                "Creates Windows service for persistence"));

            threatPatterns.add(new ThreatPattern("scheduled_task",
                "Scheduled Task Persistence", "high",
                new String[]{"CoCreateInstance", "ITaskScheduler"},
                "Creates scheduled task for persistence"));

            threatPatterns.add(new ThreatPattern("lsass_access",
                "LSASS Memory Access", "critical",
                new String[]{"OpenProcess", "ReadProcessMemory"},
                "May be accessing LSASS for credential extraction"));

            threatPatterns.add(new ThreatPattern("sam_access",
                "SAM Database Access", "critical",
                new String[]{"RegOpenKey", "SAM"},
                "May be accessing SAM database for password hashes"));

            threatPatterns.add(new ThreatPattern("socket_communication",
                "Network Communication", "medium",
                new String[]{"WSAStartup", "socket", "connect", "send", "recv"},
                "Establishes network connection"));

            threatPatterns.add(new ThreatPattern("http_communication",
                "HTTP Communication", "medium",
                new String[]{"InternetOpen", "InternetConnect", "HttpOpenRequest"},
                "Performs HTTP communication"));

            threatPatterns.add(new ThreatPattern("file_encryption",
                "Potential Ransomware", "critical",
                new String[]{"FindFirstFile", "FindNextFile", "CryptEncrypt"},
                "File enumeration combined with encryption"));

            FunctionManager functionManager = program.getFunctionManager();
            SymbolTable symbolTable = program.getSymbolTable();
            ReferenceManager refManager = program.getReferenceManager();

            List<Map<String, Object>> detectedPatterns = new ArrayList<>();

            Map<Function, Set<String>> functionAPIs = new LinkedHashMap<>();

            for (Function func : functionManager.getFunctions(true)) {
                if (func.isThunk()) continue;

                Set<String> apis = new HashSet<>();
                Listing listing = program.getListing();
                InstructionIterator instrIter = listing.getInstructions(func.getBody(), true);

                while (instrIter.hasNext()) {
                    Instruction instr = instrIter.next();
                    if (instr.getFlowType().isCall()) {
                        for (Reference ref : refManager.getReferencesFrom(instr.getAddress())) {
                            if (ref.getReferenceType().isCall()) {
                                Symbol sym = symbolTable.getPrimarySymbol(ref.getToAddress());
                                if (sym != null) {
                                    apis.add(sym.getName());
                                }
                            }
                        }
                    }
                }

                if (!apis.isEmpty()) {
                    functionAPIs.put(func, apis);
                }
            }

            for (Map.Entry<Function, Set<String>> entry : functionAPIs.entrySet()) {
                Function func = entry.getKey();
                Set<String> apis = entry.getValue();

                for (ThreatPattern pattern : threatPatterns) {
                    int matchCount = 0;
                    List<String> matchedAPIs = new ArrayList<>();

                    for (String requiredAPI : pattern.apis) {
                        for (String funcAPI : apis) {
                            if (funcAPI.toLowerCase().contains(requiredAPI.toLowerCase())) {
                                matchCount++;
                                matchedAPIs.add(funcAPI);
                                break;
                            }
                        }
                    }

                    if (matchCount >= Math.ceil(pattern.apis.length / 2.0) && matchCount >= 2) {
                        double confidence = (double) matchCount / pattern.apis.length;

                        Map<String, Object> detection = new LinkedHashMap<>();
                        detection.put("pattern_id", pattern.id);
                        detection.put("pattern_name", pattern.name);
                        detection.put("severity", pattern.severity);
                        detection.put("function", func.getName());
                        detection.put("address", func.getEntryPoint().toString());
                        detection.put("confidence", Math.round(confidence * 100.0) / 100.0);
                        detection.put("matched_apis", matchedAPIs);
                        detection.put("description", pattern.description);

                        detectedPatterns.add(detection);
                    }
                }
            }

            detectedPatterns.sort((a, b) -> {
                int sevCompare = getSeverityRank((String)a.get("severity")) - getSeverityRank((String)b.get("severity"));
                if (sevCompare != 0) return sevCompare;
                return Double.compare((Double)b.get("confidence"), (Double)a.get("confidence"));
            });

            Map<String, Integer> sevCounts = new LinkedHashMap<>();
            for (Map<String, Object> det : detectedPatterns) {
                String sev = (String) det.get("severity");
                sevCounts.put(sev, sevCounts.getOrDefault(sev, 0) + 1);
            }

            List<Map<String, Object>> patternList = detectedPatterns.subList(0, Math.min(detectedPatterns.size(), 50));

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("total_patterns_detected", detectedPatterns.size());
            result.put("severity_summary", sevCounts);
            result.put("detected_patterns", patternList);
            return new Response.Ok(result);
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    // ========================================================================
    // IOC extraction
    // ========================================================================

    /**
     * Enhanced IOC extraction with context and confidence scoring.
     */
    public Response extractIOCsWithContext() {
        Program program = resolveProgram(null);
        if (program == null) {
            return Response.err("No program loaded");
        }

        try {
            List<Map<String, Object>> iocs = new ArrayList<>();
            Listing listing = program.getListing();
            FunctionManager functionManager = program.getFunctionManager();

            Pattern ipv4Pattern = Pattern.compile("\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b");
            Pattern urlPattern = Pattern.compile("https?://[\\w\\-._~:/?#\\[\\]@!$&'()*+,;=%]+", Pattern.CASE_INSENSITIVE);
            Pattern domainPattern = Pattern.compile("\\b[a-zA-Z0-9][a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9]\\.[a-zA-Z]{2,}\\b");
            Pattern emailPattern = Pattern.compile("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}");
            Pattern registryPattern = Pattern.compile("(HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|HKCC)\\\\[\\w\\\\]+", Pattern.CASE_INSENSITIVE);
            Pattern filePathPattern = Pattern.compile("([a-zA-Z]:\\\\[^\"<>|*?\\n]+|\\\\\\\\[\\w.]+\\\\[^\"<>|*?\\n]+)");
            Pattern bitcoinPattern = Pattern.compile("\\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\\b");
            Pattern md5Pattern = Pattern.compile("\\b[a-fA-F0-9]{32}\\b");
            Pattern sha256Pattern = Pattern.compile("\\b[a-fA-F0-9]{64}\\b");

            DataIterator dataIter = listing.getDefinedData(true);
            while (dataIter.hasNext()) {
                Data data = dataIter.next();
                if (data.getDataType() instanceof StringDataType ||
                    data.getDataType().getName().toLowerCase().contains("string")) {

                    Object value = data.getValue();
                    if (value != null) {
                        String strValue = value.toString();
                        Address addr = data.getAddress();

                        Function containingFunc = functionManager.getFunctionContaining(addr);
                        String funcContext = containingFunc != null ? containingFunc.getName() : "global";

                        checkAndAddIOC(iocs, strValue, ipv4Pattern, "ipv4", addr, funcContext);
                        checkAndAddIOC(iocs, strValue, urlPattern, "url", addr, funcContext);
                        checkAndAddIOC(iocs, strValue, domainPattern, "domain", addr, funcContext);
                        checkAndAddIOC(iocs, strValue, emailPattern, "email", addr, funcContext);
                        checkAndAddIOC(iocs, strValue, registryPattern, "registry_key", addr, funcContext);
                        checkAndAddIOC(iocs, strValue, filePathPattern, "file_path", addr, funcContext);
                        checkAndAddIOC(iocs, strValue, bitcoinPattern, "bitcoin_address", addr, funcContext);
                        checkAndAddIOC(iocs, strValue, md5Pattern, "md5_hash", addr, funcContext);
                        checkAndAddIOC(iocs, strValue, sha256Pattern, "sha256_hash", addr, funcContext);
                    }
                }
            }

            for (Map<String, Object> ioc : iocs) {
                double confidence = calculateIOCConfidence(ioc, program);
                ioc.put("confidence", Math.round(confidence * 100.0) / 100.0);
            }

            iocs.sort((a, b) -> Double.compare((Double)b.get("confidence"), (Double)a.get("confidence")));

            Map<String, Integer> typeCounts = new LinkedHashMap<>();
            for (Map<String, Object> ioc : iocs) {
                String type = (String) ioc.get("type");
                typeCounts.put(type, typeCounts.getOrDefault(type, 0) + 1);
            }

            List<Object> iocList = new ArrayList<>(iocs.subList(0, Math.min(iocs.size(), 100)));
            if (iocs.size() > 100) {
                Map<String, Object> note = new LinkedHashMap<>();
                note.put("note", (iocs.size() - 100) + " additional IOCs truncated");
                iocList.add(note);
            }

            Map<String, Object> response = new LinkedHashMap<>();
            response.put("total_iocs", iocs.size());
            response.put("by_type", typeCounts);
            response.put("iocs", iocList);
            return new Response.Ok(response);
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    // ========================================================================
    // Malware behavior detection
    // ========================================================================

    /**
     * Detect common malware behaviors and techniques.
     */
    public Response detectMalwareBehaviors() {
        Program program = resolveProgram(null);
        if (program == null) {
            return Response.err("No program loaded");
        }

        try {
            List<Map<String, Object>> behaviors = new ArrayList<>();
            FunctionManager functionManager = program.getFunctionManager();
            SymbolTable symbolTable = program.getSymbolTable();
            ReferenceManager refManager = program.getReferenceManager();
            Listing listing = program.getListing();

            Map<String, String[]> behaviorIndicators = new LinkedHashMap<>();

            behaviorIndicators.put("code_injection", new String[]{
                "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                "NtWriteVirtualMemory", "RtlCreateUserThread", "QueueUserAPC"
            });
            behaviorIndicators.put("keylogging", new String[]{
                "SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState", "RegisterRawInputDevices"
            });
            behaviorIndicators.put("screen_capture", new String[]{
                "GetDC", "GetWindowDC", "BitBlt", "CreateCompatibleBitmap", "GetDIBits"
            });
            behaviorIndicators.put("privilege_escalation", new String[]{
                "AdjustTokenPrivileges", "LookupPrivilegeValue", "OpenProcessToken",
                "ImpersonateLoggedOnUser", "DuplicateToken"
            });
            behaviorIndicators.put("defense_evasion", new String[]{
                "NtSetInformationThread", "NtQueryInformationProcess", "GetProcAddress",
                "LoadLibrary", "VirtualProtect"
            });
            behaviorIndicators.put("lateral_movement", new String[]{
                "WNetAddConnection", "NetShareEnum", "WNetEnumResource"
            });
            behaviorIndicators.put("data_exfiltration", new String[]{
                "InternetOpen", "HttpSendRequest", "FtpPutFile", "send", "WSASend"
            });
            behaviorIndicators.put("crypto_operations", new String[]{
                "CryptAcquireContext", "CryptGenKey", "CryptEncrypt", "CryptDecrypt",
                "CryptImportKey", "CryptDeriveKey"
            });
            behaviorIndicators.put("process_manipulation", new String[]{
                "TerminateProcess", "SuspendThread", "ResumeThread", "NtSuspendProcess"
            });

            for (Function func : functionManager.getFunctions(true)) {
                if (func.isThunk()) continue;

                Set<String> funcAPIs = new HashSet<>();
                InstructionIterator instrIter = listing.getInstructions(func.getBody(), true);

                while (instrIter.hasNext()) {
                    Instruction instr = instrIter.next();
                    if (instr.getFlowType().isCall()) {
                        for (Reference ref : refManager.getReferencesFrom(instr.getAddress())) {
                            if (ref.getReferenceType().isCall()) {
                                Symbol sym = symbolTable.getPrimarySymbol(ref.getToAddress());
                                if (sym != null) {
                                    funcAPIs.add(sym.getName());
                                }
                            }
                        }
                    }
                }

                for (Map.Entry<String, String[]> entry : behaviorIndicators.entrySet()) {
                    String behaviorType = entry.getKey();
                    String[] indicators = entry.getValue();

                    List<String> matchedIndicators = new ArrayList<>();
                    for (String indicator : indicators) {
                        for (String api : funcAPIs) {
                            if (api.toLowerCase().contains(indicator.toLowerCase())) {
                                matchedIndicators.add(api);
                            }
                        }
                    }

                    if (matchedIndicators.size() >= 2) {
                        Map<String, Object> behavior = new LinkedHashMap<>();
                        behavior.put("behavior_type", behaviorType);
                        behavior.put("function", func.getName());
                        behavior.put("address", func.getEntryPoint().toString());
                        behavior.put("indicators", matchedIndicators);
                        behavior.put("indicator_count", matchedIndicators.size());
                        behavior.put("severity", getBehaviorSeverity(behaviorType));
                        behaviors.add(behavior);
                    }
                }
            }

            behaviors.sort((a, b) -> {
                int sevCompare = getSeverityRank((String)a.get("severity")) - getSeverityRank((String)b.get("severity"));
                if (sevCompare != 0) return sevCompare;
                return (Integer)b.get("indicator_count") - (Integer)a.get("indicator_count");
            });

            Map<String, Integer> behaviorCounts = new LinkedHashMap<>();
            for (Map<String, Object> behavior : behaviors) {
                String type = (String) behavior.get("behavior_type");
                behaviorCounts.put(type, behaviorCounts.getOrDefault(type, 0) + 1);
            }

            List<Object> behaviorList = new ArrayList<>(behaviors.subList(0, Math.min(behaviors.size(), 100)));
            if (behaviors.size() > 100) {
                Map<String, Object> note = new LinkedHashMap<>();
                note.put("note", (behaviors.size() - 100) + " additional behaviors truncated");
                behaviorList.add(note);
            }

            Map<String, Object> response = new LinkedHashMap<>();
            response.put("total_behaviors_detected", behaviors.size());
            response.put("by_behavior_type", behaviorCounts);
            response.put("behaviors", behaviorList);
            return new Response.Ok(response);
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    // ========================================================================
    // Suggest field names
    // ========================================================================

    /**
     * AI-assisted field name suggestions based on usage patterns.
     */
    public Response suggestFieldNames(String structAddressStr, int structSize) {
        if (structSize < 0 || structSize > MAX_FIELD_OFFSET) {
            return Response.err("structSize must be between 0 and " + MAX_FIELD_OFFSET);
        }

        Program program = resolveProgram(null);
        if (program == null) {
            return Response.err("No program loaded");
        }

        try {
            Address addr = program.getAddressFactory().getAddress(structAddressStr);
            if (addr == null) {
                return Response.err("Invalid address: " + structAddressStr);
            }

            Data data = program.getListing().getDataAt(addr);
            ghidra.program.model.data.DataType dataType = (data != null) ? data.getDataType() : null;

            if (dataType == null || !(dataType instanceof Structure)) {
                return Response.err("No structure data type found at " + structAddressStr);
            }

            Structure struct = (Structure) dataType;

            DataTypeComponent[] components = struct.getComponents();
            if (components.length > MAX_STRUCT_FIELDS) {
                return Response.err("Structure too large: " + components.length +
                           " fields (max " + MAX_STRUCT_FIELDS + ")");
            }

            List<Map<String, Object>> suggestions = new ArrayList<>();
            for (DataTypeComponent component : components) {
                List<String> suggestedNames = generateFieldNameSuggestions(component);

                if (suggestedNames.isEmpty()) {
                    suggestedNames.add(component.getFieldName() + "Value");
                    suggestedNames.add(component.getFieldName() + "Data");
                }

                Map<String, Object> fieldSuggestion = new LinkedHashMap<>();
                fieldSuggestion.put("offset", component.getOffset());
                fieldSuggestion.put("current_name", component.getFieldName());
                fieldSuggestion.put("field_type", component.getDataType().getName());
                fieldSuggestion.put("suggested_names", suggestedNames);
                fieldSuggestion.put("confidence", "medium");
                suggestions.add(fieldSuggestion);
            }

            Map<String, Object> response = new LinkedHashMap<>();
            response.put("struct_address", structAddressStr);
            response.put("struct_name", struct.getName());
            response.put("struct_size", struct.getLength());
            response.put("suggestions", suggestions);

            return Response.ok(response);
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    // ========================================================================
    // Disassemble bytes
    // ========================================================================

    /**
     * Disassemble undefined bytes at a given address range.
     */
    public Response disassembleBytes(String startAddress, String endAddress, Integer length,
                                     boolean restrictToExecuteMemory) {
        Program program = resolveProgram(null);
        if (program == null) {
            return Response.err("No program loaded");
        }

        if (startAddress == null || startAddress.isEmpty()) {
            return Response.err("start_address parameter required");
        }

        try {
            return threadingStrategy.executeWrite(program, "Disassemble Bytes", () -> {
                Address start = program.getAddressFactory().getAddress(startAddress);
                if (start == null) {
                    return Response.err("Invalid start address: " + startAddress);
                }

                Address end;
                if (endAddress != null && !endAddress.isEmpty()) {
                    end = program.getAddressFactory().getAddress(endAddress);
                    if (end == null) {
                        return Response.err("Invalid end address: " + endAddress);
                    }
                    try {
                        end = end.subtract(1);
                    } catch (Exception e) {
                        return Response.err("End address calculation failed: " + e.getMessage());
                    }
                } else if (length != null && length > 0) {
                    try {
                        end = start.add(length - 1);
                    } catch (Exception e) {
                        return Response.err("End address calculation from length failed: " + e.getMessage());
                    }
                } else {
                    Listing listing = program.getListing();
                    Address current = start;
                    int maxBytes = 100;
                    int count = 0;

                    while (count < maxBytes) {
                        CodeUnit cu = listing.getCodeUnitAt(current);
                        if (cu instanceof Instruction) break;
                        if (cu instanceof Data && ((Data) cu).isDefined()) break;
                        count++;
                        try {
                            current = current.add(1);
                        } catch (Exception e) {
                            break;
                        }
                    }

                    if (count == 0) {
                        return Response.err("No undefined bytes found at address (already disassembled or defined data)");
                    }

                    try {
                        end = current.subtract(1);
                    } catch (Exception e) {
                        end = current;
                    }
                }

                AddressSet addressSet = new AddressSet(start, end);
                long numBytes = addressSet.getNumAddresses();

                ghidra.app.cmd.disassemble.DisassembleCommand cmd =
                    new ghidra.app.cmd.disassemble.DisassembleCommand(addressSet, null, restrictToExecuteMemory);
                cmd.setSeedContext(null);
                cmd.setInitialContext(null);

                if (cmd.applyTo(program, ghidra.util.task.TaskMonitor.DUMMY)) {
                    JsonObject jo = new JsonObject();
                    jo.addProperty("success", true);
                    jo.addProperty("start_address", start.toString());
                    jo.addProperty("end_address", end.toString());
                    jo.addProperty("bytes_disassembled", numBytes);
                    jo.addProperty("message", "Successfully disassembled " + numBytes + " byte(s)");
                    return new Response.Ok(jo);
                } else {
                    return Response.err("Disassembly failed: " + cmd.getStatusMsg());
                }
            });
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    // ========================================================================
    // Private helper methods and inner classes
    // ========================================================================

    private static class FunctionMetrics {
        int basicBlockCount = 0;
        int instructionCount = 0;
        int callCount = 0;
        int cyclomaticComplexity = 0;
        int edgeCount = 0;
        Set<String> calledFunctions = new HashSet<>();
    }

    private FunctionMetrics calculateFunctionMetrics(Function func, BasicBlockModel blockModel, Program program) {
        FunctionMetrics metrics = new FunctionMetrics();

        try {
            CodeBlockIterator blockIter = blockModel.getCodeBlocksContaining(func.getBody(), null);
            while (blockIter.hasNext()) {
                CodeBlock block = blockIter.next();
                metrics.basicBlockCount++;

                CodeBlockReferenceIterator destIter = block.getDestinations(null);
                while (destIter.hasNext()) {
                    destIter.next();
                    metrics.edgeCount++;
                }
            }

            metrics.cyclomaticComplexity = metrics.edgeCount - metrics.basicBlockCount + 2;
            if (metrics.cyclomaticComplexity < 1) metrics.cyclomaticComplexity = 1;

            Listing listing = program.getListing();
            InstructionIterator instrIter = listing.getInstructions(func.getBody(), true);
            ReferenceManager refManager = program.getReferenceManager();

            while (instrIter.hasNext()) {
                Instruction instr = instrIter.next();
                metrics.instructionCount++;

                if (instr.getFlowType().isCall()) {
                    metrics.callCount++;
                    for (Reference ref : refManager.getReferencesFrom(instr.getAddress())) {
                        if (ref.getReferenceType().isCall()) {
                            Function calledFunc = program.getFunctionManager().getFunctionAt(ref.getToAddress());
                            if (calledFunc != null) {
                                metrics.calledFunctions.add(calledFunc.getName());
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            // Return partial metrics on error
        }

        return metrics;
    }

    private double calculateSimilarity(FunctionMetrics a, FunctionMetrics b) {
        double blockSim = 1.0 - Math.abs(a.basicBlockCount - b.basicBlockCount) /
                          (double) Math.max(Math.max(a.basicBlockCount, b.basicBlockCount), 1);
        double instrSim = 1.0 - Math.abs(a.instructionCount - b.instructionCount) /
                          (double) Math.max(Math.max(a.instructionCount, b.instructionCount), 1);
        double callSim = 1.0 - Math.abs(a.callCount - b.callCount) /
                         (double) Math.max(Math.max(a.callCount, b.callCount), 1);
        double complexitySim = 1.0 - Math.abs(a.cyclomaticComplexity - b.cyclomaticComplexity) /
                               (double) Math.max(Math.max(a.cyclomaticComplexity, b.cyclomaticComplexity), 1);

        double calledFuncSim = 0.0;
        if (!a.calledFunctions.isEmpty() || !b.calledFunctions.isEmpty()) {
            Set<String> intersection = new HashSet<>(a.calledFunctions);
            intersection.retainAll(b.calledFunctions);
            Set<String> union = new HashSet<>(a.calledFunctions);
            union.addAll(b.calledFunctions);
            calledFuncSim = union.isEmpty() ? 0.0 : (double) intersection.size() / union.size();
        }

        return 0.25 * blockSim + 0.20 * instrSim + 0.15 * callSim +
               0.20 * complexitySim + 0.20 * calledFuncSim;
    }

    private String getSeverity(String category) {
        switch (category) {
            case "debugger_detection": return "high";
            case "timing_checks": return "medium";
            case "process_enumeration": return "medium";
            case "vm_detection": return "high";
            case "exception_based": return "high";
            case "memory_checks": return "low";
            default: return "medium";
        }
    }

    private int getSeverityRank(String severity) {
        switch (severity) {
            case "critical": return 0;
            case "high": return 1;
            case "medium": return 2;
            case "low": return 3;
            default: return 4;
        }
    }

    private String getBehaviorSeverity(String behaviorType) {
        switch (behaviorType) {
            case "code_injection":
            case "privilege_escalation":
                return "critical";
            case "keylogging":
            case "lateral_movement":
            case "data_exfiltration":
                return "high";
            case "screen_capture":
            case "defense_evasion":
            case "crypto_operations":
                return "medium";
            case "process_manipulation":
                return "medium";
            default:
                return "low";
        }
    }

    private static class ThreatPattern {
        String id;
        String name;
        String severity;
        String[] apis;
        String description;

        ThreatPattern(String id, String name, String severity, String[] apis, String description) {
            this.id = id;
            this.name = name;
            this.severity = severity;
            this.apis = apis;
            this.description = description;
        }
    }

    private void checkAndAddIOC(List<Map<String, Object>> iocs, String value, Pattern pattern,
                                 String type, Address address, String funcContext) {
        java.util.regex.Matcher matcher = pattern.matcher(value);
        while (matcher.find()) {
            String match = matcher.group();
            if (type.equals("ipv4") && (match.startsWith("0.") || match.startsWith("255."))) continue;
            if (type.equals("domain") && match.length() < 4) continue;

            Map<String, Object> ioc = new LinkedHashMap<>();
            ioc.put("type", type);
            ioc.put("value", match);
            ioc.put("address", address.toString());
            ioc.put("function_context", funcContext);
            iocs.add(ioc);
        }
    }

    private double calculateIOCConfidence(Map<String, Object> ioc, Program program) {
        String type = (String) ioc.get("type");
        String value = (String) ioc.get("value");
        String funcContext = (String) ioc.get("function_context");

        double confidence = 0.5;

        switch (type) {
            case "url":
            case "ipv4":
                confidence += 0.2;
                break;
            case "registry_key":
                if (value.toLowerCase().contains("run") || value.toLowerCase().contains("services")) {
                    confidence += 0.3;
                }
                break;
            case "bitcoin_address":
                confidence += 0.4;
                break;
            case "file_path":
                if (value.toLowerCase().contains("temp") || value.toLowerCase().contains("appdata")) {
                    confidence += 0.2;
                }
                break;
        }

        if (!funcContext.equals("global")) {
            confidence += 0.1;
        }

        try {
            Address addr = program.getAddressFactory().getAddress((String) ioc.get("address"));
            ReferenceManager refManager = program.getReferenceManager();
            ReferenceIterator refs = refManager.getReferencesTo(addr);
            int refCount = 0;
            while (refs.hasNext() && refCount < 10) {
                refs.next();
                refCount++;
            }
            if (refCount > 0) {
                confidence += 0.1 * Math.min(refCount, 3);
            }
        } catch (Exception e) {
            // Ignore xref errors
        }

        return Math.min(confidence, 1.0);
    }

    private List<String> generateFieldNameSuggestions(DataTypeComponent component) {
        List<String> suggestions = new ArrayList<>();
        String typeName = component.getDataType().getName().toLowerCase();
        String currentName = component.getFieldName();

        if (typeName.contains("pointer") || typeName.startsWith("p")) {
            suggestions.add("p" + capitalizeFirst(currentName));
            suggestions.add("lp" + capitalizeFirst(currentName));
        } else if (typeName.contains("dword")) {
            suggestions.add("dw" + capitalizeFirst(currentName));
        } else if (typeName.contains("word")) {
            suggestions.add("w" + capitalizeFirst(currentName));
        } else if (typeName.contains("byte") || typeName.contains("char")) {
            suggestions.add("b" + capitalizeFirst(currentName));
            suggestions.add("sz" + capitalizeFirst(currentName));
        } else if (typeName.contains("int")) {
            suggestions.add("n" + capitalizeFirst(currentName));
            suggestions.add("i" + capitalizeFirst(currentName));
        }

        suggestions.add(currentName + "Value");
        suggestions.add(currentName + "Data");

        return suggestions;
    }

    private String capitalizeFirst(String str) {
        if (str == null || str.isEmpty()) return str;
        return Character.toUpperCase(str.charAt(0)) + str.substring(1);
    }

    // ========================================================================
    // Data classification
    // ========================================================================

    /**
     * Apply data classification atomically: resolve type, apply it, rename, and comment.
     */
    @SuppressWarnings("unchecked")
    public Response applyDataClassification(String addressStr, String classification,
                                            String name, String comment,
                                            Object typeDefinitionObj) {
        Program program = resolveProgram(null);
        if (program == null) return programNotFoundError(null);

        Address addr = parseAddress(program, addressStr);
        if (addr == null) {
            return Response.err("Invalid address: " + addressStr);
        }

        final Map<String, Object> typeDef;
        if (typeDefinitionObj instanceof Map) {
            typeDef = (Map<String, Object>) typeDefinitionObj;
        } else if (typeDefinitionObj == null) {
            typeDef = null;
        } else {
            return Response.err("type_definition must be a JSON object/dict, got: " +
                   typeDefinitionObj.getClass().getSimpleName() +
                   " with value: " + typeDefinitionObj);
        }

        try {
            final String[] typeApplied = {"none"};
            final List<String> operations = new ArrayList<>();

            return threadingStrategy.executeWrite(program, "Apply Data Classification", () -> {
                DataTypeManager dtm = program.getDataTypeManager();
                Listing listing = program.getListing();
                DataType dataTypeToApply = null;

                if ("PRIMITIVE".equals(classification)) {
                    if (typeDef == null) {
                        throw new IllegalArgumentException(
                            "PRIMITIVE classification requires type_definition parameter. " +
                            "Example: type_definition='{\"type\": \"dword\"}' or type_definition={\"type\": \"dword\"}");
                    }
                    if (!typeDef.containsKey("type")) {
                        throw new IllegalArgumentException(
                            "PRIMITIVE classification requires 'type' field in type_definition. " +
                            "Received: " + typeDef.keySet() + ". Example: {\"type\": \"dword\"}");
                    }

                    String typeStr = (String) typeDef.get("type");
                    dataTypeToApply = resolveDataTypeViaService(dtm, typeStr);
                    if (dataTypeToApply != null) {
                        typeApplied[0] = typeStr;
                        operations.add("resolved_primitive_type");
                    } else {
                        throw new IllegalArgumentException("Failed to resolve primitive type: " + typeStr);
                    }
                }
                else if ("STRUCTURE".equals(classification)) {
                    if (typeDef == null || !typeDef.containsKey("name") || !typeDef.containsKey("fields")) {
                        throw new IllegalArgumentException(
                            "STRUCTURE classification requires type_definition with 'name' and 'fields'. " +
                            "Example: {\"name\": \"MyStruct\", \"fields\": [{\"name\": \"field1\", \"type\": \"dword\"}]}");
                    }

                    String structName = (String) typeDef.get("name");
                    Object fieldsObj = typeDef.get("fields");

                    DataType existing = dtm.getDataType("/" + structName);
                    if (existing != null) {
                        dataTypeToApply = existing;
                        typeApplied[0] = structName;
                        operations.add("found_existing_structure");
                    } else {
                        StructureDataType struct = new StructureDataType(structName, 0);

                        if (fieldsObj instanceof List) {
                            List<Map<String, Object>> fieldsList = (List<Map<String, Object>>) fieldsObj;
                            for (Map<String, Object> field : fieldsList) {
                                String fieldName = (String) field.get("name");
                                String fieldType = (String) field.get("type");

                                DataType fieldDataType = resolveDataTypeViaService(dtm, fieldType);
                                if (fieldDataType != null) {
                                    struct.add(fieldDataType, fieldDataType.getLength(), fieldName, "");
                                }
                            }
                        }

                        dataTypeToApply = dtm.addDataType(struct, null);
                        typeApplied[0] = structName;
                        operations.add("created_structure");
                    }
                }
                else if ("ARRAY".equals(classification)) {
                    if (typeDef == null) {
                        throw new IllegalArgumentException(
                            "ARRAY classification requires type_definition with 'element_type' or 'element_struct', and 'count'. " +
                            "Example: {\"element_type\": \"dword\", \"count\": 64}");
                    }

                    DataType elementType = null;
                    int count = 1;

                    if (typeDef.containsKey("element_type")) {
                        String elementTypeStr = (String) typeDef.get("element_type");
                        elementType = resolveDataTypeViaService(dtm, elementTypeStr);
                        if (elementType == null) {
                            throw new IllegalArgumentException("Failed to resolve array element type: " + elementTypeStr);
                        }
                    } else if (typeDef.containsKey("element_struct")) {
                        String structName = (String) typeDef.get("element_struct");
                        elementType = dtm.getDataType("/" + structName);
                        if (elementType == null) {
                            throw new IllegalArgumentException("Failed to find struct for array element: " + structName);
                        }
                    } else {
                        throw new IllegalArgumentException(
                            "ARRAY type_definition must contain 'element_type' or 'element_struct'");
                    }

                    if (typeDef.containsKey("count")) {
                        Object countObj = typeDef.get("count");
                        if (countObj instanceof Integer) {
                            count = (Integer) countObj;
                        } else if (countObj instanceof Number) {
                            count = ((Number) countObj).intValue();
                        } else if (countObj instanceof String) {
                            count = Integer.parseInt((String) countObj);
                        }
                    } else {
                        throw new IllegalArgumentException("ARRAY type_definition must contain 'count' field");
                    }

                    if (count <= 0) {
                        throw new IllegalArgumentException("Array count must be positive, got: " + count);
                    }

                    ArrayDataType arrayType = new ArrayDataType(elementType, count, elementType.getLength());
                    dataTypeToApply = arrayType;
                    typeApplied[0] = elementType.getName() + "[" + count + "]";
                    operations.add("created_array");
                }
                else if ("STRING".equals(classification)) {
                    if (typeDef != null && typeDef.containsKey("type")) {
                        String typeStr = (String) typeDef.get("type");
                        dataTypeToApply = resolveDataTypeViaService(dtm, typeStr);
                        if (dataTypeToApply != null) {
                            typeApplied[0] = typeStr;
                            operations.add("resolved_string_type");
                        }
                    }
                }

                // Apply data type
                if (dataTypeToApply != null) {
                    CodeUnit existingCU = listing.getCodeUnitAt(addr);
                    if (existingCU != null) {
                        listing.clearCodeUnits(addr,
                            addr.add(Math.max(dataTypeToApply.getLength() - 1, 0)), false);
                    }

                    listing.createData(addr, dataTypeToApply);
                    operations.add("applied_type");
                }

                // Rename
                if (name != null && !name.isEmpty()) {
                    Data data = listing.getDefinedDataAt(addr);
                    if (data != null) {
                        SymbolTable symTable = program.getSymbolTable();
                        Symbol symbol = symTable.getPrimarySymbol(addr);
                        if (symbol != null) {
                            symbol.setName(name, SourceType.USER_DEFINED);
                        } else {
                            symTable.createLabel(addr, name, SourceType.USER_DEFINED);
                        }
                        operations.add("renamed");
                    }
                }

                // Set comment
                if (comment != null && !comment.isEmpty()) {
                    String unescapedComment = comment.replace("\\n", "\n")
                                                     .replace("\\t", "\t")
                                                     .replace("\\r", "\r");
                    listing.setComment(addr, CodeUnit.PRE_COMMENT, unescapedComment);
                    operations.add("commented");
                }

                Map<String, Object> result = new LinkedHashMap<>();
                result.put("success", true);
                result.put("address", addressStr);
                result.put("classification", classification);
                if (name != null) result.put("name", name);
                result.put("type_applied", typeApplied[0]);
                result.put("operations_performed", operations);
                return Response.ok(result);
            });
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    private DataType resolveDataTypeViaService(DataTypeManager dtm, String typeName) {
        if (dataTypeService != null) {
            return dataTypeService.resolveDataType(dtm, typeName);
        }
        // Fallback: direct lookup
        DataType dt = dtm.getDataType("/" + typeName);
        if (dt != null) return dt;
        return dtm.getDataType("/" + typeName.toLowerCase());
    }

    // ========================================================================
    // Function completeness analysis
    // ========================================================================

    /**
     * Analyze function documentation completeness.
     * Flushes decompiler cache first, then scores naming, typing, comments, etc.
     */
    public Response analyzeFunctionCompleteness(String functionAddress) {
        Program program = resolveProgram(null);
        if (program == null) return programNotFoundError(null);

        if (functionAddress == null || functionAddress.isEmpty()) {
            return Response.err("function_address parameter is required");
        }

        try {
            return threadingStrategy.executeRead(() -> {
                Address addr = parseAddress(program, functionAddress);
                if (addr == null) {
                    return Response.err("Invalid address: " + functionAddress);
                }

                Function func = program.getFunctionManager().getFunctionAt(addr);
                if (func == null) {
                    return Response.err("No function at address: " + functionAddress);
                }

                // Flush decompiler cache before analysis
                try {
                    DecompInterface tempDecomp = new DecompInterface();
                    tempDecomp.openProgram(program);
                    tempDecomp.flushCache();
                    tempDecomp.decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS, monitor);
                    tempDecomp.dispose();
                    Msg.info(AnalysisService.class, "Refreshed decompiler cache before completeness analysis for " + func.getName());
                } catch (Exception e) {
                    Msg.warn(AnalysisService.class, "Failed to refresh cache before completeness analysis: " + e.getMessage());
                }

                // Enhanced plate comment validation
                String plateComment = func.getComment();
                boolean hasPlateComment = plateComment != null && !plateComment.isEmpty();
                List<String> plateCommentIssues = new ArrayList<>();
                if (hasPlateComment) {
                    validatePlateCommentStructure(plateComment, plateCommentIssues);
                }

                // Check for undefined variables using decompilation
                List<String> undefinedVars = new ArrayList<>();
                boolean decompilationAvailable = false;

                DecompileResults decompResults = decompileFunction(func, program);
                if (decompResults != null && decompResults.decompileCompleted()) {
                    decompilationAvailable = true;
                    ghidra.program.model.pcode.HighFunction highFunction = decompResults.getHighFunction();

                    if (highFunction != null) {
                        for (Parameter param : func.getParameters()) {
                            if (param.getName().startsWith("param_")) {
                                undefinedVars.add(param.getName() + " (generic name)");
                            }
                            String typeName = param.getDataType().getName();
                            if (typeName.startsWith("undefined")) {
                                undefinedVars.add(param.getName() + " (type: " + typeName + ")");
                            }
                        }

                        Iterator<ghidra.program.model.pcode.HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
                        while (symbols.hasNext()) {
                            ghidra.program.model.pcode.HighSymbol symbol = symbols.next();
                            String symName = symbol.getName();
                            String typeName = symbol.getDataType().getName();

                            if (symName.startsWith("local_") ||
                                symName.matches(".*Var\\d+") ||
                                symName.matches("(i|u|d|f|p|b)Var\\d+")) {
                                undefinedVars.add(symName + " (generic name)");
                            }

                            if (typeName.startsWith("undefined")) {
                                undefinedVars.add(symName + " (type: " + typeName + ")");
                            }
                        }
                    }
                }

                // Fallback to low-level API if decompilation failed
                if (!decompilationAvailable) {
                    for (Parameter param : func.getParameters()) {
                        if (param.getName().startsWith("param_")) {
                            undefinedVars.add(param.getName() + " (generic name)");
                        }
                        String typeName = param.getDataType().getName();
                        if (typeName.startsWith("undefined")) {
                            undefinedVars.add(param.getName() + " (type: " + typeName + ")");
                        }
                    }

                    for (Variable local : func.getLocalVariables()) {
                        if (local.getName().startsWith("local_")) {
                            undefinedVars.add(local.getName() + " (generic name, may be phantom variable)");
                        }
                        String typeName = local.getDataType().getName();
                        if (typeName.startsWith("undefined")) {
                            undefinedVars.add(local.getName() + " (type: " + typeName + ", may be phantom variable)");
                        }
                    }
                }

                // Check Hungarian notation compliance
                List<String> hungarianViolations = new ArrayList<>();
                for (Parameter param : func.getParameters()) {
                    validateHungarianNotation(param.getName(), param.getDataType().getName(), false, hungarianViolations);
                }

                if (decompilationAvailable && decompResults != null && decompResults.getHighFunction() != null) {
                    ghidra.program.model.pcode.HighFunction highFunction = decompResults.getHighFunction();
                    Iterator<ghidra.program.model.pcode.HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
                    while (symbols.hasNext()) {
                        ghidra.program.model.pcode.HighSymbol symbol = symbols.next();
                        validateHungarianNotation(symbol.getName(), symbol.getDataType().getName(), false, hungarianViolations);
                    }
                } else {
                    for (Variable local : func.getLocalVariables()) {
                        validateHungarianNotation(local.getName(), local.getDataType().getName(), false, hungarianViolations);
                    }
                }

                // Enhanced validation: Check parameter type quality
                List<String> typeQualityIssues = new ArrayList<>();
                validateParameterTypeQuality(func, typeQualityIssues);

                // Check for unrenamed DAT_* globals and undocumented Ordinal calls
                List<String> unrenamedGlobals = new ArrayList<>();
                List<String> undocumentedOrdinals = new ArrayList<>();
                int inlineCommentCount = 0;
                int codeLineCount = 0;

                if (decompilationAvailable && decompResults != null) {
                    String decompiledCode = decompResults.getDecompiledFunction().getC();
                    if (decompiledCode != null) {
                        int[] commentStats = countCodeLinesAndComments(decompiledCode);
                        codeLineCount = commentStats[0];
                        inlineCommentCount = commentStats[1];

                        // Find DAT_* references
                        java.util.regex.Matcher datMatcher = Pattern.compile("DAT_[0-9a-fA-F]+").matcher(decompiledCode);
                        Set<String> foundDats = new HashSet<>();
                        while (datMatcher.find()) {
                            foundDats.add(datMatcher.group());
                        }
                        unrenamedGlobals.addAll(foundDats);

                        // Find Ordinal_XXXXX calls without nearby comments
                        java.util.regex.Matcher ordinalMatcher = Pattern.compile("Ordinal_\\d+").matcher(decompiledCode);
                        Set<String> foundOrdinals = new HashSet<>();
                        while (ordinalMatcher.find()) {
                            String ordinal = ordinalMatcher.group();
                            int pos = ordinalMatcher.start();
                            int lineStart = decompiledCode.lastIndexOf('\n', pos);
                            int lineEnd = decompiledCode.indexOf('\n', pos);
                            if (lineEnd == -1) lineEnd = decompiledCode.length();
                            String line = decompiledCode.substring(lineStart + 1, lineEnd);
                            if (!line.contains("/*") && !line.contains("//")) {
                                foundOrdinals.add(ordinal);
                            }
                        }
                        undocumentedOrdinals.addAll(foundOrdinals);
                    }
                }

                double commentDensity = codeLineCount > 0 ? (inlineCommentCount * 10.0 / codeLineCount) : 0;

                double completenessScore;
                if (comparisonService != null) {
                    completenessScore = comparisonService.calculateCompletenessScore(func, undefinedVars.size(),
                        plateCommentIssues.size(), hungarianViolations.size(), typeQualityIssues.size(),
                        unrenamedGlobals.size(), undocumentedOrdinals.size(), commentDensity);
                } else {
                    completenessScore = calculateCompletenessScoreLocal(func, undefinedVars.size(),
                        plateCommentIssues.size(), hungarianViolations.size(), typeQualityIssues.size(),
                        unrenamedGlobals.size(), undocumentedOrdinals.size(), commentDensity);
                }

                List<String> recommendations = generateWorkflowRecommendations(
                    func, undefinedVars, plateCommentIssues, hungarianViolations, typeQualityIssues,
                    unrenamedGlobals, undocumentedOrdinals, commentDensity, completenessScore
                );

                Map<String, Object> r = new LinkedHashMap<>();
                r.put("function_name", func.getName());
                r.put("has_custom_name", !func.getName().startsWith("FUN_"));
                r.put("has_prototype", func.getSignature() != null);
                r.put("has_calling_convention", func.getCallingConvention() != null);
                r.put("has_plate_comment", hasPlateComment);
                r.put("plate_comment_issues", plateCommentIssues);
                r.put("decompilation_available", decompilationAvailable);
                r.put("undefined_variables", undefinedVars);
                r.put("hungarian_notation_violations", hungarianViolations);
                r.put("type_quality_issues", typeQualityIssues);
                r.put("unrenamed_globals", unrenamedGlobals);
                r.put("undocumented_ordinals", undocumentedOrdinals);
                r.put("inline_comment_count", inlineCommentCount);
                r.put("code_line_count", codeLineCount);
                r.put("comment_density", Double.parseDouble(String.format("%.2f", commentDensity)));
                r.put("completeness_score", completenessScore);
                r.put("recommendations", recommendations);
                return Response.ok(r);
            });
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

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

    /**
     * Count code lines and inline comments inside a function body.
     * Returns [codeLineCount, inlineCommentCount].
     */
    private int[] countCodeLinesAndComments(String decompiledCode) {
        String[] lines = decompiledCode.split("\n");
        boolean inFunctionBody = false;
        boolean inPlateComment = false;
        int braceDepth = 0;
        int codeLineCount = 0;
        int inlineCommentCount = 0;

        for (String line : lines) {
            String trimmed = line.trim();

            if (!inFunctionBody && trimmed.startsWith("/*")) {
                inPlateComment = true;
            }
            if (inPlateComment && trimmed.endsWith("*/")) {
                inPlateComment = false;
                continue;
            }
            if (inPlateComment) continue;

            for (char c : trimmed.toCharArray()) {
                if (c == '{') {
                    braceDepth++;
                    inFunctionBody = true;
                } else if (c == '}') {
                    braceDepth--;
                }
            }

            if (inFunctionBody && !trimmed.isEmpty() &&
                !trimmed.startsWith("/*") && !trimmed.startsWith("*") && !trimmed.startsWith("//")) {
                codeLineCount++;
            }

            if (inFunctionBody && trimmed.contains("/*")) {
                if (!trimmed.contains("WARNING:")) {
                    inlineCommentCount++;
                }
            }
            if (inFunctionBody && trimmed.contains("//")) {
                inlineCommentCount++;
            }
        }

        return new int[]{codeLineCount, inlineCommentCount};
    }

    private void validatePlateCommentStructure(String plateComment, List<String> issues) {
        if (plateComment == null || plateComment.isEmpty()) {
            issues.add("Plate comment is empty");
            return;
        }

        String[] lines = plateComment.split("\n");
        if (lines.length < 10) {
            issues.add("Plate comment has only " + lines.length + " lines (minimum 10 required)");
        }

        boolean hasAlgorithm = false;
        boolean hasParameters = false;
        boolean hasReturns = false;
        boolean hasNumberedSteps = false;

        for (String line : lines) {
            String trimmed = line.trim();
            if (trimmed.startsWith("Algorithm:") || trimmed.equals("Algorithm")) hasAlgorithm = true;
            if (trimmed.matches("^\\d+\\.\\s+.*")) hasNumberedSteps = true;
            if (trimmed.startsWith("Parameters:") || trimmed.equals("Parameters")) hasParameters = true;
            if (trimmed.startsWith("Returns:") || trimmed.equals("Returns")) hasReturns = true;
        }

        if (!hasAlgorithm) issues.add("Missing Algorithm section");
        if (hasAlgorithm && !hasNumberedSteps) issues.add("Algorithm section exists but has no numbered steps");
        if (!hasParameters) issues.add("Missing Parameters section");
        if (!hasReturns) issues.add("Missing Returns section");
    }

    private void validateHungarianNotation(String varName, String typeName, boolean isGlobal, List<String> violations) {
        if (varName.startsWith("param_") || varName.startsWith("local_") ||
            varName.startsWith("iVar") || varName.startsWith("uVar") ||
            varName.startsWith("dVar") || varName.startsWith("fVar") ||
            varName.startsWith("in_") || varName.startsWith("extraout_")) {
            return;
        }

        if (typeName.startsWith("undefined")) {
            return;
        }

        String baseTypeName = typeName.replaceAll("\\[.*\\]", "").replaceAll("\\s*\\*", "").trim();
        String expectedPrefix = getExpectedHungarianPrefix(baseTypeName, typeName.contains("*"), typeName.contains("["));

        if (expectedPrefix == null) {
            return;
        }

        String fullExpectedPrefix = isGlobal ? "g_" + expectedPrefix : expectedPrefix;

        boolean hasCorrectPrefix = false;
        if (expectedPrefix.contains("|")) {
            String[] validPrefixes = expectedPrefix.split("\\|");
            for (String prefix : validPrefixes) {
                String fullPrefix = isGlobal ? "g_" + prefix : prefix;
                if (varName.startsWith(fullPrefix)) {
                    hasCorrectPrefix = true;
                    break;
                }
            }
        } else {
            hasCorrectPrefix = varName.startsWith(fullExpectedPrefix);
        }

        if (!hasCorrectPrefix) {
            violations.add(varName + " (type: " + typeName + ", expected prefix: " + fullExpectedPrefix + ")");
        }
    }

    private String getExpectedHungarianPrefix(String typeName, boolean isPointer, boolean isArray) {
        if (isArray) {
            if (typeName.equals("byte")) return "ab";
            if (typeName.equals("ushort")) return "aw";
            if (typeName.equals("uint")) return "ad";
            if (typeName.equals("char")) return "sz";
            return null;
        }

        if (isPointer) {
            if (typeName.equals("void")) return "p";
            if (typeName.equals("char")) return "sz|lpsz";
            if (typeName.equals("wchar_t")) return "wsz";
            return "p";
        }

        switch (typeName) {
            case "byte": return "b|by";
            case "char": return "c|ch";
            case "bool": return "f";
            case "short": return "n|s";
            case "ushort": return "w";
            case "int": return "n|i";
            case "uint": return "dw";
            case "long": return "l";
            case "ulong": return "dw";
            case "longlong": return "ll";
            case "ulonglong": return "qw";
            case "float": return "fl";
            case "double": return "d";
            case "float10": return "ld";
            case "HANDLE": return "h";
            default: return null;
        }
    }

    private void validateParameterTypeQuality(Function func, List<String> issues) {
        Program program = func.getProgram();
        DataTypeManager dtm = program.getDataTypeManager();

        String[] statePrefixes = {"Initialized", "Allocated", "Created", "Updated",
                                  "Processed", "Deleted", "Modified", "Constructed",
                                  "Freed", "Destroyed", "Copied", "Cloned"};

        for (Parameter param : func.getParameters()) {
            DataType paramType = param.getDataType();
            String typeName = paramType.getName();

            if (paramType instanceof Pointer) {
                Pointer ptrType = (Pointer) paramType;
                DataType pointedTo = ptrType.getDataType();
                if (pointedTo != null && pointedTo.getName().equals("void")) {
                    issues.add("Generic void* parameter: " + param.getName() +
                              " (should use specific structure type)");
                }
            }

            for (String prefix : statePrefixes) {
                if (typeName.startsWith(prefix)) {
                    issues.add("State-based type name: " + typeName +
                              " on parameter " + param.getName() +
                              " (should use identity-based name)");
                    break;
                }
            }

            if (paramType instanceof Pointer) {
                String baseType = typeName.replace(" *", "").trim();
                for (String prefix : statePrefixes) {
                    if (baseType.startsWith(prefix)) {
                        String identityName = baseType.substring(prefix.length());
                        DataType identityType = dtm.getDataType("/" + identityName);
                        if (identityType != null) {
                            issues.add("Type duplication: " + baseType + " and " + identityName +
                                      " exist (consider consolidating to " + identityName + ")");
                        }
                    }
                }
            }
        }
    }

    private double calculateCompletenessScoreLocal(Function func, int undefinedCount, int plateCommentIssueCount,
                                                    int hungarianViolationCount, int typeQualityIssueCount,
                                                    int unrenamedGlobalsCount, int undocumentedOrdinalsCount,
                                                    double commentDensity) {
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

    private List<String> generateWorkflowRecommendations(
            Function func,
            List<String> undefinedVars,
            List<String> plateCommentIssues,
            List<String> hungarianViolations,
            List<String> typeQualityIssues,
            List<String> unrenamedGlobals,
            List<String> undocumentedOrdinals,
            double commentDensity,
            double completenessScore) {

        List<String> recommendations = new ArrayList<>();

        if (completenessScore >= 100.0) {
            recommendations.add("Function is fully documented - no further action needed.");
            return recommendations;
        }

        if (!unrenamedGlobals.isEmpty()) {
            recommendations.add("UNRENAMED DAT_* GLOBALS DETECTED - Must rename before documentation is complete:");
            recommendations.add("1. Found " + unrenamedGlobals.size() + " DAT_* reference(s): " + String.join(", ", unrenamedGlobals.subList(0, Math.min(5, unrenamedGlobals.size()))));
            recommendations.add("2. Use rename_or_label() or rename_data() to give meaningful names to each global");
            recommendations.add("3. Apply Hungarian notation with g_ prefix: g_dwPlayerCount, g_pCurrentGame, g_abEncryptionKey");
            recommendations.add("4. If global is a structure, apply type with apply_data_type() first, then rename");
            recommendations.add("5. Consult KNOWN_ORDINALS.md and existing codebase for naming conventions");
        }

        if (!undocumentedOrdinals.isEmpty()) {
            recommendations.add("UNDOCUMENTED ORDINAL CALLS - Add inline comments for each:");
            recommendations.add("1. Found " + undocumentedOrdinals.size() + " Ordinal call(s) without comments: " + String.join(", ", undocumentedOrdinals.subList(0, Math.min(5, undocumentedOrdinals.size()))));
            recommendations.add("2. Consult docs/KNOWN_ORDINALS.md for Ordinal mappings (Storm.dll, Fog.dll ordinals documented)");
            recommendations.add("3. Use set_decompiler_comment() or batch_set_comments() to add inline comment explaining the call");
            recommendations.add("4. Format: /* Ordinal_123 = StorageFunctionName - brief description */");
        }

        if (!undefinedVars.isEmpty()) {
            recommendations.add("UNDEFINED TYPES DETECTED - Follow FUNCTION_DOC_WORKFLOW_V4.md Phase 2 'Type Audit' section:");
            recommendations.add("1. Type Resolution: Apply type normalization before renaming:");
            recommendations.add("   - undefined1 -> byte (8-bit integer)");
            recommendations.add("   - undefined2 -> ushort/short (16-bit integer)");
            recommendations.add("   - undefined4 -> uint/int/float/pointer (32-bit - check usage context)");
            recommendations.add("   - undefined8 -> double/ulonglong/longlong (64-bit)");
            recommendations.add("   - undefined1[N] -> byte[N] (byte array for XMM spills, buffers)");
            recommendations.add("2. Use set_local_variable_type() with lowercase builtin types (uint, ushort, byte) NOT uppercase Windows types (UINT, USHORT, BYTE)");
            recommendations.add("3. CRITICAL: Check disassembly with get_disassembly() for assembly-only undefined types:");
            recommendations.add("   - Stack temporaries: [EBP + local_offset] not in get_function_variables()");
            recommendations.add("   - XMM register spills: undefined1[16] at stack locations");
            recommendations.add("   - Intermediate calculation results not appearing in decompiled view");
            recommendations.add("4. After resolving ALL undefined types, rename variables with Hungarian notation using rename_variables()");
        }

        if (!plateCommentIssues.isEmpty()) {
            recommendations.add("PLATE COMMENT ISSUES - Follow FUNCTION_DOC_WORKFLOW_V4.md Phase 7 'Documentation' section:");
            for (String issue : plateCommentIssues) {
                if (issue.contains("Missing Algorithm section")) {
                    recommendations.add("1. Add Algorithm section with numbered steps describing operations (validation, function calls, error handling)");
                } else if (issue.contains("no numbered steps")) {
                    recommendations.add("2. Add numbered steps in Algorithm section (1., 2., 3., etc.)");
                } else if (issue.contains("Missing Parameters section")) {
                    recommendations.add("3. Add Parameters section documenting all parameters with types and purposes (include IMPLICIT keyword for undocumented register params)");
                } else if (issue.contains("Missing Returns section")) {
                    recommendations.add("4. Add Returns section explaining return values, success codes, error conditions, NULL/zero cases");
                } else if (issue.contains("lines (minimum 10 required)")) {
                    recommendations.add("5. Expand plate comment to minimum 10 lines with comprehensive documentation");
                }
            }
            recommendations.add("Use set_plate_comment() to create/update plate comment following docs/prompts/PLATE_COMMENT_FORMAT_GUIDE.md");
        }

        if (!hungarianViolations.isEmpty()) {
            recommendations.add("HUNGARIAN NOTATION VIOLATIONS - Follow FUNCTION_DOC_WORKFLOW_V4.md Phase 5 'Variables' and docs/HUNGARIAN_NOTATION.md:");
            recommendations.add("1. Verify type-to-prefix mapping matches Ghidra type:");
            recommendations.add("   - byte -> b/by | char -> c/ch | bool -> f | short -> n/s | ushort -> w");
            recommendations.add("   - int -> n/i | uint -> dw | long -> l | ulong -> dw");
            recommendations.add("   - longlong -> ll | ulonglong -> qw | float -> fl | double -> d");
            recommendations.add("   - void* -> p | typed pointers -> p+StructName (pUnitAny)");
            recommendations.add("   - byte[N] -> ab | ushort[N] -> aw | uint[N] -> ad");
            recommendations.add("   - char* -> sz/lpsz | wchar_t* -> wsz");
            recommendations.add("2. First set correct type with set_local_variable_type() using lowercase builtin");
            recommendations.add("3. Then rename with rename_variables() using correct Hungarian prefix");
            recommendations.add("4. For globals, add g_ prefix before type prefix: g_dwProcessId, g_abEncryptionKey");
        }

        if (!typeQualityIssues.isEmpty()) {
            recommendations.add("TYPE QUALITY ISSUES - Follow FUNCTION_DOC_WORKFLOW_V4.md Phase 3 'Structures' section:");
            for (String issue : typeQualityIssues) {
                if (issue.contains("Generic void*")) {
                    recommendations.add("1. Replace generic void* parameters with specific structure types using set_function_prototype()");
                    recommendations.add("   Example: void ProcessData(void* pData) -> void ProcessData(UnitAny* pUnit)");
                } else if (issue.contains("State-based type name")) {
                    recommendations.add("2. Rename state-based type names to identity-based names:");
                    recommendations.add("   BAD: InitializedGameObject, AllocatedBuffer, ProcessedData");
                    recommendations.add("   GOOD: GameObject, Buffer, DataRecord");
                    recommendations.add("   Use create_struct() with identity-based name, document legacy name in comments");
                } else if (issue.contains("Type duplication")) {
                    recommendations.add("3. Consolidate duplicate types - use identity-based version, delete state-based variant");
                }
            }
        }

        if (commentDensity < 0.67) {
            recommendations.add("LOW INLINE COMMENT DENSITY - Add more explanatory comments:");
            recommendations.add("1. Current density: " + String.format("%.2f", commentDensity) + " comments per 10 lines (target: 0.67+)");
            recommendations.add("2. Add inline comments for:");
            recommendations.add("   - Complex calculations or magic numbers");
            recommendations.add("   - Non-obvious conditional branches");
            recommendations.add("   - Ordinal/DLL calls explaining their purpose");
            recommendations.add("   - Structure field accesses explaining data meaning");
            recommendations.add("   - Error handling paths explaining expected failures");
            recommendations.add("3. Use set_decompiler_comment() for individual comments or batch_set_comments() for multiple");
        }

        if (completenessScore < 100.0) {
            recommendations.add("COMPLETE WORKFLOW (FUNCTION_DOC_WORKFLOW_V4.md):");
            recommendations.add("1. Initialization: Use analyze_function_complete() to gather decompiled code, xrefs, callees, callers, disassembly, variables");
            recommendations.add("2. Undefined Type Audit: Check BOTH decompiled code AND disassembly (get_disassembly()) for all undefined types");
            recommendations.add("3. Structure Identification: Create structures BEFORE renaming (create_struct, apply_data_type)");
            recommendations.add("4. Function Naming: Use rename_function_by_address() with PascalCase");
            recommendations.add("5. Prototype: Use set_function_prototype() with specific typed parameters");
            recommendations.add("6. Labels: Use batch_create_labels() for jump targets (snake_case)");
            recommendations.add("7. Variable Types: Use set_local_variable_type() with lowercase builtins");
            recommendations.add("8. Variable Renaming: Use rename_variables() with Hungarian notation");
            recommendations.add("9. Plate Comment: Use set_plate_comment() with Algorithm, Parameters, Returns sections");
            recommendations.add("10. Inline Comments: Use batch_set_comments() for decompiler and disassembly comments");
            recommendations.add("11. Verification: Re-run analyze_function_completeness() to confirm 100% score");
        }

        return recommendations;
    }
}
