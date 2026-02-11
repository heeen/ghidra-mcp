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

import java.util.List;
import java.util.Map;

/**
 * Shared service for comment-related endpoints.
 *
 * Handles set_decompiler_comment, set_disassembly_comment, set_plate_comment,
 * and batch_set_comments.
 */
public class CommentService extends BaseService {

    public CommentService(ProgramProvider programProvider, ThreadingStrategy threadingStrategy) {
        super(programProvider, threadingStrategy);
    }

    /**
     * Set a decompiler (PRE) comment at an address.
     * Endpoint: /set_decompiler_comment
     */
    public String setDecompilerComment(String addressStr, String comment) {
        return setComment(addressStr, comment, CodeUnit.PRE_COMMENT, "Set decompiler comment");
    }

    /**
     * Set a disassembly (EOL) comment at an address.
     * Endpoint: /set_disassembly_comment
     */
    public String setDisassemblyComment(String addressStr, String comment) {
        return setComment(addressStr, comment, CodeUnit.EOL_COMMENT, "Set disassembly comment");
    }

    /**
     * Set a plate comment on a function.
     * Endpoint: /set_plate_comment
     */
    public String setPlateComment(String functionAddress, String comment) {
        Program program = resolveProgram(null);
        if (program == null) {
            return "Error: No program loaded";
        }
        if (functionAddress == null || functionAddress.isEmpty()) {
            return "Error: Function address is required";
        }
        if (comment == null) {
            return "Error: Comment is required";
        }

        Address addr = parseAddress(program, functionAddress);
        if (addr == null) {
            return "Error: Invalid address: " + functionAddress;
        }

        try {
            return threadingStrategy.executeWrite(program, "Set plate comment", () -> {
                Function func = program.getFunctionManager().getFunctionAt(addr);
                if (func == null) {
                    func = program.getFunctionManager().getFunctionContaining(addr);
                }
                if (func == null) {
                    return "Error: No function found at address: " + functionAddress;
                }

                Listing listing = program.getListing();
                listing.setComment(func.getEntryPoint(), CodeUnit.PLATE_COMMENT, comment);
                return "Success: Set plate comment for " + func.getName();
            });
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Set multiple comments in a single batch operation.
     * Endpoint: /batch_set_comments
     *
     * @param functionAddress  Address of the function (for plate comment context)
     * @param decompilerComments  List of {address, comment} maps for PRE_COMMENT
     * @param disassemblyComments List of {address, comment} maps for EOL_COMMENT
     * @param plateComment  Plate comment text (may be null)
     */
    public String batchSetComments(String functionAddress,
                                   List<Map<String, String>> decompilerComments,
                                   List<Map<String, String>> disassemblyComments,
                                   String plateComment) {
        Program program = resolveProgram(null);
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
        }
        if (functionAddress == null || functionAddress.isEmpty()) {
            return "{\"error\": \"Function address is required\"}";
        }

        Address addr = parseAddress(program, functionAddress);
        if (addr == null) {
            return "{\"error\": \"Invalid address: " + escapeJson(functionAddress) + "\"}";
        }

        try {
            return threadingStrategy.executeWrite(program, "Batch set comments", () -> {
                Function func = program.getFunctionManager().getFunctionAt(addr);
                if (func == null) {
                    func = program.getFunctionManager().getFunctionContaining(addr);
                }
                if (func == null) {
                    return "{\"error\": \"No function found at address: " + escapeJson(functionAddress) + "\"}";
                }

                Listing listing = program.getListing();
                int plateSet = 0;
                int decompilerSet = 0;
                int disassemblySet = 0;

                // Set plate comment if provided
                if (plateComment != null && !plateComment.isEmpty() && !plateComment.equals("null")) {
                    listing.setComment(func.getEntryPoint(), CodeUnit.PLATE_COMMENT, plateComment);
                    plateSet = 1;
                }

                // Set decompiler comments (PRE_COMMENT)
                if (decompilerComments != null) {
                    for (Map<String, String> entry : decompilerComments) {
                        String addrStr = entry.get("address");
                        String text = entry.get("comment");
                        if (addrStr != null && text != null) {
                            Address commentAddr = parseAddress(program, addrStr);
                            if (commentAddr != null) {
                                listing.setComment(commentAddr, CodeUnit.PRE_COMMENT, text);
                                decompilerSet++;
                            }
                        }
                    }
                }

                // Set disassembly comments (EOL_COMMENT)
                if (disassemblyComments != null) {
                    for (Map<String, String> entry : disassemblyComments) {
                        String addrStr = entry.get("address");
                        String text = entry.get("comment");
                        if (addrStr != null && text != null) {
                            Address commentAddr = parseAddress(program, addrStr);
                            if (commentAddr != null) {
                                listing.setComment(commentAddr, CodeUnit.EOL_COMMENT, text);
                                disassemblySet++;
                            }
                        }
                    }
                }

                return "{\"success\": true, \"plate_comments_set\": " + plateSet +
                       ", \"decompiler_comments_set\": " + decompilerSet +
                       ", \"disassembly_comments_set\": " + disassemblySet + "}";
            });
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    private String setComment(String addressStr, String comment, int commentType, String transactionName) {
        Program program = resolveProgram(null);
        if (program == null) {
            return "Error: No program loaded";
        }

        Address addr = parseAddress(program, addressStr);
        if (addr == null) {
            return "Error: Invalid address: " + addressStr;
        }

        try {
            return threadingStrategy.executeWrite(program, transactionName, () -> {
                Listing listing = program.getListing();
                listing.setComment(addr, commentType, comment);
                return "Success: Set comment at " + addressStr;
            });
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}
