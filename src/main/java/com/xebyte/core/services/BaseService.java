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
import ghidra.program.model.listing.Program;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

import java.util.List;

/**
 * Base class for shared service implementations.
 *
 * Provides common utilities used by all domain services: program resolution,
 * error formatting, JSON escaping, and pagination. Parameterized by
 * {@link ProgramProvider} and {@link ThreadingStrategy} so the same service
 * code works in both GUI and headless mode.
 */
public abstract class BaseService {

    protected final ProgramProvider programProvider;
    protected final ThreadingStrategy threadingStrategy;
    protected final TaskMonitor monitor;

    protected BaseService(ProgramProvider programProvider, ThreadingStrategy threadingStrategy) {
        this.programProvider = programProvider;
        this.threadingStrategy = threadingStrategy;
        this.monitor = new ConsoleTaskMonitor();
    }

    /**
     * Resolve a program by name, falling back to the current program.
     */
    protected Program resolveProgram(String programName) {
        return programProvider.resolveProgram(programName);
    }

    /**
     * Return a JSON error string when a program cannot be found.
     */
    protected String programNotFoundError(String programName) {
        if (programName != null && !programName.isEmpty()) {
            return "{\"error\": \"Program not found: " + escapeJson(programName) + "\"}";
        }
        return "{\"error\": \"No program currently loaded\"}";
    }

    /**
     * Paginate a list of pre-formatted strings.
     */
    protected String paginateList(List<String> items, int offset, int limit) {
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

    /**
     * Escape a string for safe inclusion in a JSON value.
     */
    protected String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    /**
     * Parse an address string in the context of a program.
     */
    protected Address parseAddress(Program program, String addressStr) {
        if (addressStr == null || addressStr.isEmpty()) {
            return null;
        }
        return program.getAddressFactory().getAddress(addressStr);
    }
}
