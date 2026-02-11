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
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;

import java.util.*;

/**
 * Read-only analysis service for byte pattern search, data region analysis,
 * array bound detection, assembly context retrieval, and structure field usage.
 *
 * All methods are read-only and do not require write transactions.
 */
public class AnalysisService extends BaseService {

    public AnalysisService(ProgramProvider programProvider, ThreadingStrategy threadingStrategy) {
        super(programProvider, threadingStrategy);
    }

    /**
     * Search memory for hex byte patterns with wildcards (??)
     */
    public String searchBytePatterns(String pattern, String mask) {
        Program program = resolveProgram(null);
        if (program == null) {
            return programNotFoundError(null);
        }

        if (pattern == null || pattern.trim().isEmpty()) {
            return "{\"error\": \"Pattern is required\"}";
        }

        try {
            StringBuilder result = new StringBuilder();
            result.append("[");

            // Parse hex pattern (e.g., "E8 ?? ?? ?? ??" or "E8????????")
            String cleanPattern = pattern.trim().toUpperCase().replaceAll("\\s+", "");

            // Convert pattern to byte array and mask
            int patternLen = cleanPattern.length() / 2;
            byte[] patternBytes = new byte[patternLen];
            byte[] maskBytes = new byte[patternLen];

            int byteIndex = 0;
            for (int i = 0; i < cleanPattern.length() && byteIndex < patternLen; i += 2) {
                if (cleanPattern.charAt(i) == '?' ||
                    (i + 1 < cleanPattern.length() && cleanPattern.charAt(i + 1) == '?')) {
                    patternBytes[byteIndex] = 0;
                    maskBytes[byteIndex] = 0; // Don't check this byte
                } else {
                    String hexByte = cleanPattern.substring(i, Math.min(i + 2, cleanPattern.length()));
                    patternBytes[byteIndex] = (byte) Integer.parseInt(hexByte, 16);
                    maskBytes[byteIndex] = (byte) 0xFF; // Check this byte
                }
                byteIndex++;
            }

            // Search memory for pattern
            Memory memory = program.getMemory();
            int matchCount = 0;
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
                    boolean matches = true;
                    for (int j = 0; j < patternBytes.length; j++) {
                        if (maskBytes[j] != 0 && blockData[i + j] != patternBytes[j]) {
                            matches = false;
                            break;
                        }
                    }

                    if (matches) {
                        if (matchCount > 0) result.append(",");
                        Address matchAddr = blockStart.add(i);
                        result.append("{\"address\": \"").append(matchAddr.toString()).append("\"}");
                        matchCount++;

                        if (matchCount >= MAX_MATCHES) {
                            result.append(",{\"note\": \"Limited to ").append(MAX_MATCHES).append(" matches\"}");
                            break;
                        }
                    }
                }

                if (matchCount >= MAX_MATCHES) break;
            }

            if (matchCount == 0) {
                result.append("{\"note\": \"No matches found\"}");
            }

            result.append("]");
            return result.toString();
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Analyze a data region comprehensively
     */
    public String analyzeDataRegion(String startAddressStr, int maxScanBytes,
                                    boolean includeXrefMap, boolean includeAssemblyPatterns,
                                    boolean includeBoundaryDetection) {
        Program program = resolveProgram(null);
        if (program == null) {
            return programNotFoundError(null);
        }

        try {
            Address startAddr = program.getAddressFactory().getAddress(startAddressStr);
            if (startAddr == null) {
                return "{\"error\": \"Invalid address: " + startAddressStr + "\"}";
            }

            ReferenceManager refMgr = program.getReferenceManager();
            Listing listing = program.getListing();

            Address endAddr = startAddr;
            Set<String> uniqueXrefs = new HashSet<>();
            int byteCount = 0;
            StringBuilder xrefMapJson = new StringBuilder();
            xrefMapJson.append("\"xref_map\": {");
            boolean firstXrefEntry = true;

            for (int i = 0; i < maxScanBytes; i++) {
                Address scanAddr = startAddr.add(i);

                // Check for boundary
                if (includeBoundaryDetection) {
                    Symbol[] symbols = program.getSymbolTable().getSymbols(scanAddr);
                    if (symbols.length > 0 && i > 0) {
                        for (Symbol sym : symbols) {
                            String name = sym.getName();
                            if (!name.startsWith("DAT_") && !name.equals(startAddr.toString())) {
                                endAddr = scanAddr.subtract(1);
                                byteCount = i;
                                break;
                            }
                        }
                        if (byteCount > 0) break;
                    }
                }

                // Get xrefs
                ReferenceIterator refIter = refMgr.getReferencesTo(scanAddr);
                List<String> refsAtThisByte = new ArrayList<>();

                while (refIter.hasNext()) {
                    Reference ref = refIter.next();
                    String fromAddr = ref.getFromAddress().toString();
                    refsAtThisByte.add(fromAddr);
                    uniqueXrefs.add(fromAddr);
                }

                if (includeXrefMap && !refsAtThisByte.isEmpty()) {
                    if (!firstXrefEntry) xrefMapJson.append(",");
                    firstXrefEntry = false;

                    xrefMapJson.append("\"").append(scanAddr.toString()).append("\": [");
                    for (int j = 0; j < refsAtThisByte.size(); j++) {
                        if (j > 0) xrefMapJson.append(",");
                        xrefMapJson.append("\"").append(refsAtThisByte.get(j)).append("\"");
                    }
                    xrefMapJson.append("]");
                }

                endAddr = scanAddr;
                byteCount = i + 1;
            }
            xrefMapJson.append("}");

            // Get current name and type
            Data data = listing.getDataAt(startAddr);
            String currentName = (data != null && data.getLabel() != null) ?
                                data.getLabel() : "DAT_" + startAddr.toString().replace(":", "");
            String currentType = (data != null) ?
                                data.getDataType().getName() : "undefined";

            // Classify
            String classification = "PRIMITIVE";
            if (uniqueXrefs.size() > 3) {
                classification = "ARRAY";
            } else if (uniqueXrefs.size() > 1) {
                classification = "STRUCTURE";
            }

            // Build result
            StringBuilder result = new StringBuilder();
            result.append("{");
            result.append("\"start_address\": \"").append(startAddr.toString()).append("\",");
            result.append("\"end_address\": \"").append(endAddr.toString()).append("\",");
            result.append("\"byte_span\": ").append(byteCount).append(",");

            if (includeXrefMap) {
                result.append(xrefMapJson.toString()).append(",");
            }

            result.append("\"unique_xref_addresses\": [");
            int idx = 0;
            for (String xref : uniqueXrefs) {
                if (idx++ > 0) result.append(",");
                result.append("\"").append(xref).append("\"");
            }
            result.append("],");

            result.append("\"xref_count\": ").append(uniqueXrefs.size()).append(",");
            result.append("\"classification_hint\": \"").append(classification).append("\",");
            result.append("\"current_name\": \"").append(escapeJson(currentName)).append("\",");
            result.append("\"current_type\": \"").append(escapeJson(currentType)).append("\"");
            result.append("}");

            return result.toString();
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Detect array bounds based on xref analysis
     */
    public String detectArrayBounds(String addressStr, boolean analyzeLoopBounds,
                                    boolean analyzeIndexing, int maxScanRange) {
        Program program = resolveProgram(null);
        if (program == null) {
            return programNotFoundError(null);
        }

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) {
                return "{\"error\": \"Invalid address: " + addressStr + "\"}";
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

            StringBuilder result = new StringBuilder();
            result.append("{");
            result.append("\"address\": \"").append(addr.toString()).append("\",");
            result.append("\"estimated_size\": ").append(estimatedSize).append(",");
            result.append("\"stride\": 1,");
            result.append("\"element_count\": ").append(estimatedSize).append(",");
            result.append("\"confidence\": \"medium\",");
            result.append("\"detection_method\": \"xref_analysis\"");
            result.append("}");

            return result.toString();
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Get assembly context around xref sources
     */
    public String getAssemblyContext(String xrefSourcesStr, int contextInstructions, String includePatterns) {
        Program program = resolveProgram(null);
        if (program == null) {
            return programNotFoundError(null);
        }

        StringBuilder json = new StringBuilder();
        json.append("{");

        try {
            // Parse comma-separated addresses
            String[] addresses = xrefSourcesStr.split(",");
            Listing listing = program.getListing();
            boolean first = true;

            for (String addrStr : addresses) {
                addrStr = addrStr.trim();
                if (addrStr.isEmpty()) continue;

                if (!first) json.append(",");
                first = false;

                json.append("\"").append(addrStr).append("\": {");

                try {
                    Address addr = program.getAddressFactory().getAddress(addrStr);
                    if (addr != null) {
                        Instruction instr = listing.getInstructionAt(addr);
                        json.append("\"address\": \"").append(addrStr).append("\",");

                        if (instr != null) {
                            json.append("\"instruction\": \"").append(escapeJson(instr.toString())).append("\",");

                            // Get context before
                            json.append("\"context_before\": [");
                            Address prevAddr = addr;
                            for (int i = 0; i < contextInstructions; i++) {
                                Instruction prevInstr = listing.getInstructionBefore(prevAddr);
                                if (prevInstr == null) break;
                                prevAddr = prevInstr.getAddress();
                                if (i > 0) json.append(",");
                                json.append("\"").append(prevAddr).append(": ").append(escapeJson(prevInstr.toString())).append("\"");
                            }
                            json.append("],");

                            // Get context after
                            json.append("\"context_after\": [");
                            Address nextAddr = addr;
                            for (int i = 0; i < contextInstructions; i++) {
                                Instruction nextInstr = listing.getInstructionAfter(nextAddr);
                                if (nextInstr == null) break;
                                nextAddr = nextInstr.getAddress();
                                if (i > 0) json.append(",");
                                json.append("\"").append(nextAddr).append(": ").append(escapeJson(nextInstr.toString())).append("\"");
                            }
                            json.append("],");

                            json.append("\"mnemonic\": \"").append(instr.getMnemonicString()).append("\"");
                        } else {
                            json.append("\"error\": \"No instruction at address\"");
                        }
                    } else {
                        json.append("\"error\": \"Invalid address\"");
                    }
                } catch (Exception e) {
                    json.append("\"error\": \"").append(escapeJson(e.getMessage())).append("\"");
                }

                json.append("}");
            }
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }

        json.append("}");
        return json.toString();
    }

    /**
     * Analyze how structure fields are accessed
     */
    public String analyzeStructFieldUsage(String addressStr, String structName, int maxFunctions) {
        Program program = resolveProgram(null);
        if (program == null) {
            return programNotFoundError(null);
        }

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) {
                return "{\"error\": \"Invalid address: " + addressStr + "\"}";
            }

            // Get xrefs to understand usage
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

            StringBuilder result = new StringBuilder();
            result.append("{");
            result.append("\"struct_address\": \"").append(addr.toString()).append("\",");
            result.append("\"struct_name\": ").append(structName != null ? "\"" + escapeJson(structName) + "\"" : "null").append(",");
            result.append("\"functions_analyzed\": ").append(referencingFunctions.size()).append(",");
            result.append("\"referencing_functions\": [");
            for (int i = 0; i < referencingFunctions.size(); i++) {
                if (i > 0) result.append(",");
                result.append("\"").append(escapeJson(referencingFunctions.get(i))).append("\"");
            }
            result.append("]");
            result.append("}");

            return result.toString();
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Get field access context for a structure field
     */
    public String getFieldAccessContext(String structAddressStr, int fieldOffset, int numExamples) {
        Program program = resolveProgram(null);
        if (program == null) {
            return programNotFoundError(null);
        }

        try {
            Address structAddr = program.getAddressFactory().getAddress(structAddressStr);
            if (structAddr == null) {
                return "{\"error\": \"Invalid address: " + structAddressStr + "\"}";
            }

            Address fieldAddr = structAddr.add(fieldOffset);
            ReferenceManager refMgr = program.getReferenceManager();
            ReferenceIterator refIter = refMgr.getReferencesTo(fieldAddr);

            List<String> examples = new ArrayList<>();
            Listing listing = program.getListing();

            while (refIter.hasNext() && examples.size() < numExamples) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                Instruction instr = listing.getInstructionAt(fromAddr);
                Function func = program.getFunctionManager().getFunctionContaining(fromAddr);

                StringBuilder example = new StringBuilder();
                example.append("{\"from_address\": \"").append(fromAddr.toString()).append("\"");
                example.append(", \"ref_type\": \"").append(ref.getReferenceType().getName()).append("\"");
                if (instr != null) {
                    example.append(", \"instruction\": \"").append(escapeJson(instr.toString())).append("\"");
                }
                if (func != null) {
                    example.append(", \"function\": \"").append(escapeJson(func.getName())).append("\"");
                }
                example.append("}");
                examples.add(example.toString());
            }

            StringBuilder result = new StringBuilder();
            result.append("{");
            result.append("\"struct_address\": \"").append(structAddr.toString()).append("\",");
            result.append("\"field_offset\": ").append(fieldOffset).append(",");
            result.append("\"field_address\": \"").append(fieldAddr.toString()).append("\",");
            result.append("\"examples\": [");
            for (int i = 0; i < examples.size(); i++) {
                if (i > 0) result.append(",");
                result.append(examples.get(i));
            }
            result.append("]");
            result.append("}");

            return result.toString();
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }
}
