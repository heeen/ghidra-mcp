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

import com.xebyte.core.ProgramProvider;
import com.xebyte.core.ThreadingStrategy;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;

import java.io.File;
import java.util.*;

/**
 * Headless endpoint handler implementation.
 *
 * Contains the business logic for all REST API endpoints, adapted for headless
 * operation (no GUI dependencies).
 */
public class HeadlessEndpointHandler {

    private static final String VERSION = "1.9.4-headless";

    private final ProgramProvider programProvider;
    private final ThreadingStrategy threadingStrategy;

    public HeadlessEndpointHandler(ProgramProvider programProvider, ThreadingStrategy threadingStrategy) {
        this.programProvider = programProvider;
        this.threadingStrategy = threadingStrategy;
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
    // PROGRAM MANAGEMENT ENDPOINTS
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
    // PHASE 4: ADVANCED FEATURES ENDPOINTS
    // ==========================================================================

    /**
     * Run a Ghidra script (simplified for headless mode)
     */
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

}
