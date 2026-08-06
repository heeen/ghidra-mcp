package com.xebyte.core;

import ghidra.program.model.listing.Program;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Cheap change token for out-of-band edits the bridge cannot see.
 *
 * <p>{@link Program#getModificationNumber()} advances on real DB changes
 * (rename, comment, struct edit, undo/redo, GUI writes, scripts) and never on a
 * read. It is not idempotent per <em>intent</em>, only per <em>write</em>:
 * renaming a function to the name it already has measured +0, but re-setting an
 * identical comment measured +1, so an unchanged body can still bump the token.
 * That direction is the safe one — it over-invalidates rather than serving stale
 * text. The bridge polls this and emits {@code resources/updated} for URIs it
 * already knows about, catching everything write-hook invalidation is blind to,
 * at program coarseness.
 *
 * @since 7.1.0
 */
public class ChangeTokenService {

    private final ProgramProvider programProvider;

    public ChangeTokenService(ProgramProvider programProvider) {
        this.programProvider = programProvider;
    }

    @McpTool(path = "/get_change_token",
        description = "Return program.getModificationNumber() — a cheap monotonic token that "
            + "moves on real DB changes (rename, comment, struct edit, undo/redo, GUI writes, "
            + "scripts) and never on a read. Used by the bridge to invalidate cached "
            + "function resources after out-of-band edits.",
        category = "program", access = ToolAccess.READ_ONLY)
    public Response getChangeToken(
            @Param(value = "program", defaultValue = "",
                   description = "Target program name (omit for the active program).") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("program", program.getName());
        out.put("modification_number", program.getModificationNumber());
        return Response.ok(out);
    }
}
