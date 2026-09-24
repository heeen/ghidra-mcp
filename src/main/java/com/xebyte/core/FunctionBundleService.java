package com.xebyte.core;

import ghidra.app.decompiler.ClangCommentToken;
import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * One read that answers everything an agent asks about a function.
 *
 * <p>Reviewing a single function used to cost five round trips —
 * {@code decompile_function} + {@code get_function_variables} +
 * {@code get_function_callers} + {@code get_comment} + {@code get_function_xrefs} — and
 * every write forced the agent to re-read to see its effect. This endpoint collapses that
 * into one call backed by **one** decompilation, which matters because the plugin has no
 * decompiler cache: each decompile builds and disposes a fresh {@code DecompInterface}, so
 * two bundled reads composed from existing endpoints would decompile the same function
 * twice.
 *
 * <p>It also carries {@code call_context} — a window of the caller's actual decompiled
 * source centred on the call, three lines by default, because the line that decides whether
 * the call happens and the line that consumes its result are usually the ones next to it.
 * That is the context a reader wants without paying for a separate read per caller, and it
 * costs one decompile per *unique* caller (~43 ms measured), so it is deduped and capped.
 * Widening the window costs nothing extra — the caller is already decompiled.
 *
 * <p>Deliberately excluded: completeness scoring. {@code /analyze_function_completeness}
 * decompiles again, and a second decompile would defeat the point of this endpoint. Call
 * that tool directly when a score is wanted.
 *
 * <p>Threading: the whole bundle is built on the calling HTTP worker thread with no
 * {@code threadingStrategy} wrapper, following {@link CommentService}. In GUI mode
 * {@code SwingThreadingStrategy} hops onto the EDT, and decompiling several callers there
 * would stall the UI for hundreds of milliseconds; Ghidra's program database is safe for
 * concurrent reads, so the hop buys nothing here.
 *
 * @since 7.1.0
 */
public class FunctionBundleService {

    /** Hard caps: a bundle is a read for an agent, not a bulk export. */
    private static final int MAX_CALLERS = 50;
    private static final int MAX_CALLEES = 50;
    private static final int MAX_XREFS = 100;
    private static final int MAX_DISASM = 200;
    private static final int MAX_DECOMPILED_CHARS = 120_000;
    /** Bulk cap matches {@code decompile_function(functions=)} — one decompile budget per entry. */
    private static final int MAX_FUNCTIONS = 20;
    /** Widest call-site window. Past this a reader should just read the caller's bundle. */
    private static final int MAX_CALL_CONTEXT_LINES = 21;

    /** Subset keys accepted by {@code fields=}; omitted/empty means all. */
    static final Set<String> BUNDLE_FIELDS = Set.of(
            "signature", "classification", "return_type", "entry_point",
            "body_start", "body_end", "decompiled_code",
            "plate_comment", "comments", "labels", "parameters", "locals",
            "callers", "call_context", "callees", "xrefs", "disassembly",
            "jump_targets");

    private final ProgramProvider programProvider;
    private final ThreadingStrategy threadingStrategy;
    private final FunctionService functionService;

    public FunctionBundleService(ProgramProvider programProvider,
            ThreadingStrategy threadingStrategy, FunctionService functionService) {
        this.programProvider = programProvider;
        this.threadingStrategy = threadingStrategy;
        this.functionService = functionService;
    }

    @McpTool(path = "/get_functions",
        description = "Everything about one or many functions in a single call. Pass "
            + "functions= as a comma-separated list of names or addresses for bulk mode "
            + "(up to 20); omit it and pass function=/name=/address= for one. Pass fields= "
            + "as a comma-separated subset to skip work you do not need — omitted or empty "
            + "returns everything. When the requested fields need no decompiled text (e.g. "
            + "fields=callers,callees,signature,labels,entry_point), the target function is "
            + "NOT decompiled (238 ms cold / 5–10 ms warm per function); only decompiled_code "
            + "(and call_context when enabled) pays that cost. Decompiled text renders EOL "
            + "comments (// style), so comments written with set_comment are visible in the "
            + "code. Replaces get_function_by_address, get_function_variables, "
            + "get_function_xrefs, decompile_function, get_function_bundle, and the former "
            + "get_function_callers/callees/labels/signature tools. Completeness scoring is "
            + "NOT included — call analyze_function_completeness for that.",
        category = "function", access = ToolAccess.READ_ONLY)
    public Response getFunctions(
            @Param(value = "function", paramType = "address", defaultValue = "",
                   aliases = {"name", "address", "function_address", "function_name"},
                   description = "Single mode: function name or address (0x<hex> or "
                               + "<space>:<hex>). Ignored when functions= is set.") String functionRef,
            @Param(value = "functions", defaultValue = "",
                   description = "Bulk mode: comma-separated function references (names or "
                               + "addresses). When set, function= is ignored. Returns a map "
                               + "keyed by the reference asked for.") String functionsParam,
            @Param(value = "fields", defaultValue = "",
                   description = "Comma-separated subset: signature, classification, return_type, "
                               + "entry_point, body_start, body_end, decompiled_code, "
                               + "plate_comment, comments, labels, parameters, locals, callers, "
                               + "call_context, callees, xrefs, disassembly, jump_targets. "
                               + "Omit or leave empty for the full bundle.") String fieldsParam,
            @Param(value = "include_call_context", defaultValue = "true",
                   description = "Include each caller's decompiled call-site line. Costs one "
                               + "decompilation per unique caller (~43ms); set false for the "
                               + "cheapest possible bundle. Ignored unless call_context is "
                               + "requested (explicitly or via an empty fields=).") boolean includeCallContext,
            @Param(value = "call_context_limit", defaultValue = "6",
                   description = "Maximum number of UNIQUE callers to decompile for call "
                               + "context.") int callContextLimit,
            @Param(value = "call_context_lines", defaultValue = "3",
                   aliases = {"call_context_window"},
                   description = "Lines of the caller's decompilation to return per call site, "
                               + "centred on the call. 1 is the call line alone; the default 3 "
                               + "adds the line above and below, which is usually where the "
                               + "guard and the use of the result live. Clamped to 1-21; costs "
                               + "no extra decompilation.") int callContextLines,
            @Param(value = "include_disasm", defaultValue = "false",
                   description = "Include the raw instruction listing. Off by default: it roughly "
                               + "doubles the payload and agents rarely read it.") boolean includeDisasm,
            @Param(value = "program", defaultValue = "",
                   description = "Target program name (omit to use the active program — always "
                               + "specify when multiple programs are open)") String programName) {

        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        Set<String> fields;
        try {
            fields = parseFields(fieldsParam);
            if (fields != null && fields.isEmpty()) {
                fields = null;
            }
        } catch (IllegalArgumentException e) {
            return Response.err(e.getMessage());
        }

        final int ctxLimit = Math.max(0, callContextLimit);
        final int ctxLines = Math.clamp(callContextLines, 1, MAX_CALL_CONTEXT_LINES);
        final Set<String> resolvedFields = fields;

        if (functionsParam != null && !functionsParam.isBlank()) {
            return getFunctionsBulk(program, functionsParam, resolvedFields, includeCallContext,
                ctxLimit, ctxLines, includeDisasm);
        }

        if (functionRef == null || functionRef.isEmpty()) {
            return Response.err("function name or address required (or pass functions= for bulk)");
        }

        Function func = ServiceUtils.resolveFunction(program, functionRef);
        if (func == null) {
            String parseError = ServiceUtils.getLastParseError();
            return Response.err("Function not found: " + functionRef
                + (parseError != null && !parseError.isEmpty() ? " (" + parseError + ")" : ""));
        }

        try {
            return Response.ok(buildBundle(program, func, resolvedFields, includeCallContext,
                ctxLimit, ctxLines, includeDisasm));
        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.toString();
            return Response.err("Failed to build bundle for " + func.getName() + ": " + msg);
        }
    }

    /** Internal/tests: single-function entry with the pre-consolidation name. */
    public Response getFunctionBundle(String functionRef, String fieldsParam,
            boolean includeCallContext, int callContextLimit, int callContextLines,
            boolean includeDisasm, String programName) {
        return getFunctions(functionRef, "", fieldsParam, includeCallContext, callContextLimit,
            callContextLines, includeDisasm, programName);
    }

    private Response getFunctionsBulk(Program program, String functionsParam, Set<String> fields,
            boolean includeCallContext, int callContextLimit, int callContextLines,
            boolean includeDisasm) {
        String[] refs = functionsParam.split(",");
        Map<String, Object> out = new LinkedHashMap<>();
        Map<String, Object> functions = new LinkedHashMap<>();
        int requested = 0;
        int resolved = 0;

        for (String raw : refs) {
            if (requested >= MAX_FUNCTIONS) {
                break;
            }
            String funcRef = raw.trim();
            if (funcRef.isEmpty()) {
                continue;
            }
            requested++;
            Function func = ServiceUtils.resolveFunction(program, funcRef);
            if (func == null) {
                String parseError = ServiceUtils.getLastParseError();
                Map<String, Object> err = new LinkedHashMap<>();
                err.put("error", "Function not found: " + funcRef
                    + (parseError != null && !parseError.isEmpty() ? " (" + parseError + ")" : ""));
                functions.put(funcRef, err);
                continue;
            }
            try {
                functions.put(funcRef, buildBundle(program, func, fields, includeCallContext,
                    callContextLimit, callContextLines, includeDisasm));
                resolved++;
            } catch (Exception e) {
                String msg = e.getMessage() != null ? e.getMessage() : e.toString();
                Map<String, Object> err = new LinkedHashMap<>();
                err.put("error", "Failed to build bundle for " + func.getName() + ": " + msg);
                functions.put(funcRef, err);
            }
        }

        if (requested == 0) {
            return Response.err("functions parameter is required for bulk mode");
        }

        out.put("functions", functions);
        out.put("count", resolved);
        out.put("requested", requested);
        if (refs.length > MAX_FUNCTIONS || requested > MAX_FUNCTIONS) {
            out.put("truncated", true);
            out.put("max_functions", MAX_FUNCTIONS);
        }
        return Response.ok(out);
    }

    /**
     * The bundle's own decompiler settings: show EOL comments, in {@code //} style.
     *
     * <p>An agent writes EOL comments through {@code set_comment}/{@code batch_set_comments}
     * and then reads the function back — and none of them appeared in the code, because the
     * decompiler's EOL option is off by default and this program's saved options keep it off.
     * They were only visible as an address in {@code comments[]}, which is exactly not where
     * a reader is looking.
     *
     * <p>Scoped to this endpoint rather than {@code createConfiguredDecompiler}: the shared
     * path feeds {@code analyze_function_completeness}, whose comment counter special-cases
     * Ghidra's {@code WARNING:} banners in its {@code /*} branch but not its {@code //} one,
     * and fun-doc's {@code port_pipeline._strip_comments}, which strips only {@code /* … *}{@code /}.
     * Under {@code //} both would silently change behaviour, and both are scoring inputs.
     *
     * <p>Ghidra renders a comment on its own line above the statement, never trailing it, so
     * this reads as {@code // note} then the code — {@code x = 1; // note} is not something
     * the decompiler will produce.
     */
    private static void bundleDecompilerOptions(ghidra.app.decompiler.DecompileOptions opts) {
        opts.setEOLCommentIncluded(true);
        opts.setCommentStyle(ghidra.app.decompiler.DecompileOptions.CommentStyleEnum.CPPStyle);
    }

    private static Set<String> parseFields(String fieldsParam) {
        if (fieldsParam == null || fieldsParam.isBlank()) {
            return null;
        }
        Set<String> fields = new LinkedHashSet<>();
        for (String part : fieldsParam.split(",")) {
            String token = part.trim().toLowerCase();
            if (token.isEmpty()) {
                continue;
            }
            if (!BUNDLE_FIELDS.contains(token)) {
                throw new IllegalArgumentException("Unknown field: " + part.trim()
                    + ". Valid fields: " + String.join(", ", BUNDLE_FIELDS));
            }
            fields.add(token);
        }
        return fields.isEmpty() ? null : fields;
    }

    /**
     * Intra-function control flow: where the jumps inside this function go.
     *
     * <p>Folded in from the former {@code /get_function_jump_targets}. It reads
     * instructions out of the function body and never decompiles -- measured at
     * 0.6 ms warm against the full bundle's 228 ms -- so it costs nothing to
     * carry by default, and {@code fields=} excludes it for callers who do not
     * want it.
     *
     * <p>Conditional jumps contribute their fall-through as well: a branch has
     * two successors, and reporting only the taken edge would describe a control
     * flow graph that does not exist.
     */
    private static List<String> collectJumpTargets(Program program, Function func) {
        java.util.Set<ghidra.program.model.address.Address> targets = new java.util.HashSet<>();
        ghidra.program.model.listing.InstructionIterator instructions =
                program.getListing().getInstructions(func.getBody(), true);
        while (instructions.hasNext()) {
            ghidra.program.model.listing.Instruction instr = instructions.next();
            if (!instr.getFlowType().isJump()) {
                continue;
            }
            for (ghidra.program.model.symbol.Reference ref : instr.getReferencesFrom()) {
                ghidra.program.model.address.Address to = ref.getToAddress();
                if (to != null && program.getMemory().contains(to)) {
                    targets.add(to);
                }
            }
            if (instr.getFlowType().isConditional()) {
                ghidra.program.model.address.Address fallThrough = instr.getFallThrough();
                if (fallThrough != null) {
                    targets.add(fallThrough);
                }
            }
        }
        List<ghidra.program.model.address.Address> sorted = new ArrayList<>(targets);
        java.util.Collections.sort(sorted);
        List<String> out = new ArrayList<>(sorted.size());
        for (ghidra.program.model.address.Address a : sorted) {
            out.add(a.toString(false));
        }
        return out;
    }

    private static boolean wantsField(Set<String> fields, String name) {
        return fields == null || fields.contains(name);
    }

    private Map<String, Object> buildBundle(Program program, Function func,
            Set<String> fields, boolean includeCallContext, int callContextLimit,
            int callContextLines, boolean includeDisasm) {
        Address entry = func.getEntryPoint();
        Map<String, Object> out = new LinkedHashMap<>();
        Map<String, Object> truncation = new LinkedHashMap<>();

        out.put("name", func.getName());
        out.putAll(ServiceUtils.addressToJson(entry, program));

        boolean wantsAll = fields == null;
        boolean needsTargetDecompile = wantsAll || wantsField(fields, "decompiled_code");
        boolean needsCallContext = wantsField(fields, "call_context")
            && includeCallContext && callContextLimit > 0;

        if (wantsField(fields, "signature")) {
            out.put("signature", func.getSignature().toString());
        }
        if (wantsField(fields, "classification")) {
            out.put("classification", AnalysisService.classifyFunction(func, program));
        }
        if (wantsField(fields, "return_type")) {
            String returnType = func.getReturnType().getName();
            out.put("return_type", returnType);
            if (returnType.startsWith("undefined")) {
                out.put("return_type_resolved", false);
                out.put("return_type_warning", "Return type is '" + returnType
                    + "' -- verify the return register at RET. Do not trust a decompiler 'void'.");
            } else {
                out.put("return_type_resolved", true);
            }
        }
        if (wantsField(fields, "entry_point")) {
            out.put("entry_point", entry.toString(false));
        }
        if (wantsField(fields, "body_start")) {
            out.put("body_start", func.getBody().getMinAddress().toString(false));
        }
        if (wantsField(fields, "body_end")) {
            out.put("body_end", func.getBody().getMaxAddress().toString(false));
        }

        DecompileResults decomp = null;
        boolean decompiled = false;
        if (needsTargetDecompile) {
            decomp = functionService.decompileFunctionNoRetry(
                func, program, FunctionBundleService::bundleDecompilerOptions);
            decompiled = decomp != null && decomp.decompileCompleted()
                && decomp.getDecompiledFunction() != null;
            if (wantsField(fields, "decompiled_code")) {
                if (decompiled) {
                    String code = decomp.getDecompiledFunction().getC();
                    if (code != null) {
                        if (code.length() > MAX_DECOMPILED_CHARS) {
                            out.put("decompiled_code", code.substring(0, MAX_DECOMPILED_CHARS));
                            truncation.put("decompiled_code", true);
                            out.put("decompiled_code_note", "Truncated at " + MAX_DECOMPILED_CHARS
                                + " chars; call get_functions with fields=decompiled_code for more.");
                        } else {
                            out.put("decompiled_code", code);
                        }
                    }
                } else {
                    out.put("decompiled_code", null);
                    out.put("decompile_failed", true);
                }
            }
        }

        if (wantsField(fields, "plate_comment")) {
            out.put("plate_comment", func.getComment());
            List<String> plateIssues = NamingConventions.validatePlateCommentStructure(func.getComment());
            if (!plateIssues.isEmpty()) {
                out.put("plate_comment_issues", plateIssues);
            }
        }
        if (wantsField(fields, "comments")) {
            out.put("comments", collectComments(program, func));
        }
        if (wantsField(fields, "labels")) {
            out.put("labels", collectLabels(program, func));
        }
        if (wantsField(fields, "jump_targets")) {
            out.put("jump_targets", collectJumpTargets(program, func));
        }
        if (wantsField(fields, "parameters")) {
            out.put("parameters", collectParameters(func));
        }
        if (wantsField(fields, "locals")) {
            out.put("locals", collectLocals(func, decompiled ? decomp.getHighFunction() : null));
        }

        List<Function> callers = null;
        if (wantsField(fields, "callers") || needsCallContext) {
            callers = findCallers(program, func);
        }
        if (wantsField(fields, "callers") && callers != null) {
            out.put("caller_count", callers.size());
            out.put("callers", summarizeFunctions(program, callers, MAX_CALLERS));
            if (callers.size() > MAX_CALLERS) truncation.put("callers", true);
        }

        if (needsCallContext && callers != null && !callers.isEmpty()) {
            List<Map<String, Object>> context =
                collectCallContext(program, entry, callers, callContextLimit, callContextLines);
            out.put("call_context", context);
            if (callers.size() > callContextLimit) truncation.put("call_context", true);
        }

        if (wantsField(fields, "callees")) {
            List<Function> callees = calleesOf(func);
            out.put("callee_count", callees.size());
            out.put("callees", summarizeFunctions(program, callees, MAX_CALLEES));
            if (callees.size() > MAX_CALLEES) truncation.put("callees", true);
        }

        if (wantsField(fields, "xrefs")) {
            out.put("xrefs", collectXrefs(program, entry, truncation));
        }

        if (wantsField(fields, "disassembly") && includeDisasm) {
            out.put("disassembly", collectDisassembly(program, func, truncation));
        }

        Map<String, Object> revision = new LinkedHashMap<>();
        revision.put("modification_number", program.getModificationNumber());
        revision.put("decompiled", decompiled);
        out.put("revision", revision);

        if (!truncation.isEmpty()) {
            out.put("truncation", truncation);
        }
        return out;
    }

    /** All five comment kinds at every address in the body, with body-relative offsets. */
    private List<Map<String, Object>> collectComments(Program program, Function func) {
        Listing listing = program.getListing();
        Address entry = func.getEntryPoint();
        List<Map<String, Object>> comments = new ArrayList<>();
        int[] kinds = {CodeUnit.PLATE_COMMENT, CodeUnit.PRE_COMMENT, CodeUnit.EOL_COMMENT,
                       CodeUnit.POST_COMMENT, CodeUnit.REPEATABLE_COMMENT};
        String[] kindNames = {"plate", "pre", "eol", "post", "repeatable"};
        Iterator<Address> addresses = func.getBody().getAddresses(true);
        while (addresses.hasNext()) {
            Address addr = addresses.next();
            for (int i = 0; i < kinds.length; i++) {
                String text = listing.getComment(kinds[i], addr);
                if (text == null || text.isEmpty()) continue;
                Map<String, Object> item = new LinkedHashMap<>();
                item.putAll(ServiceUtils.addressToJson(addr, program));
                item.put("relative_offset", addr.subtract(entry));
                item.put("kind", kindNames[i]);
                item.put("text", text);
                comments.add(item);
            }
        }
        return comments;
    }

    private List<Map<String, Object>> collectLabels(Program program, Function func) {
        List<Map<String, Object>> labels = new ArrayList<>();
        SymbolTable symbolTable = program.getSymbolTable();
        Address entry = func.getEntryPoint();
        SymbolIterator symbols = symbolTable.getSymbolIterator();
        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            if (symbol.getSymbolType() != SymbolType.LABEL) continue;
            if (!func.getBody().contains(symbol.getAddress())) continue;
            Map<String, Object> item = new LinkedHashMap<>();
            item.putAll(ServiceUtils.addressToJson(symbol.getAddress(), program));
            item.put("relative_offset", symbol.getAddress().subtract(entry));
            item.put("name", symbol.getName());
            item.put("source", symbol.getSource().toString());
            labels.add(item);
        }
        return labels;
    }

    private List<Map<String, Object>> collectParameters(Function func) {
        List<Map<String, Object>> params = new ArrayList<>();
        int ordinal = 0;
        for (Variable param : func.getParameters()) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("ordinal", ordinal++);
            item.put("name", param.getName());
            item.put("type", param.getDataType().getName());
            item.put("storage", param.getVariableStorage().toString());
            if (param.getComment() != null && !param.getComment().isEmpty()) {
                item.put("comment", param.getComment());
            }
            params.add(item);
        }
        return params;
    }

    /**
     * Locals from the decompiler's view when available — that is the set whose names the
     * agent actually sees in {@code decompiled_code} — falling back to the listing's
     * low-level variables when decompilation failed.
     */
    /**
     * Where a decompiler variable actually lives, or null when that is not a thing a
     * reader can act on.
     *
     * <p>Goes through {@link VariableStorage#toString()} — the same rendering
     * {@code /get_function_variables} and this bundle's own parameters use — so a register
     * comes back as {@code RDI:8} rather than {@code register:00001200:8}. The raw varnode
     * address this used to print is an offset into the register address space: it names no
     * register, and for a parameter the register IS the calling convention, which is the
     * one thing worth reading here.
     *
     * <p>p-code temporaries ({@code unique:}/hash storage) return null: an SSA temp has no
     * storage a reader could rename, retype or find in the frame, so the field is omitted
     * rather than filled with an address that means nothing outside the decompiler.
     */
    private static String describeStorage(HighSymbol symbol) {
        VariableStorage storage = symbol.getStorage();
        if (storage == null || !storage.isValid()) return null;
        if (storage.isUniqueStorage() || storage.isHashStorage()) return null;
        String text = storage.toString();
        return text == null || text.isEmpty() ? null : text;
    }

    private List<Map<String, Object>> collectLocals(Function func, HighFunction high) {
        List<Map<String, Object>> locals = new ArrayList<>();
        if (high != null) {
            Iterator<HighSymbol> symbols = high.getLocalSymbolMap().getSymbols();
            while (symbols.hasNext()) {
                HighSymbol symbol = symbols.next();
                Map<String, Object> item = new LinkedHashMap<>();
                String name = symbol.getName();
                item.put("name", name);
                item.put("type", symbol.getDataType().getName());
                String storage = describeStorage(symbol);
                if (storage != null) {
                    item.put("storage", storage);
                }
                // Decompiler-invented names: not real storage the user can rename usefully.
                item.put("is_phantom", name.startsWith("extraout_") || name.startsWith("in_")
                    || name.startsWith("unaff_"));
                item.put("in_decompiled_code", true);
                locals.add(item);
            }
            return locals;
        }
        for (Variable local : func.getLocalVariables()) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("name", local.getName());
            item.put("type", local.getDataType().getName());
            item.put("storage", local.getVariableStorage().toString());
            item.put("is_phantom", false);
            item.put("in_decompiled_code", false);
            locals.add(item);
        }
        return locals;
    }

    /**
     * Callers as the union of address references and Ghidra's own calling-function set —
     * the thorough form {@code /get_function_callers} uses. {@code getCallingFunctions}
     * alone misses callers reachable only through data/indirect references.
     */
    private List<Function> findCallers(Program program, Function func) {
        Set<Function> callers = new LinkedHashSet<>();
        FunctionManager functionManager = program.getFunctionManager();
        ReferenceManager refManager = program.getReferenceManager();
        ReferenceIterator refs = refManager.getReferencesTo(func.getEntryPoint());
        while (refs.hasNext()) {
            Reference ref = refs.next();
            Function containing = functionManager.getFunctionContaining(ref.getFromAddress());
            if (containing != null) callers.add(containing);
        }
        try {
            callers.addAll(func.getCallingFunctions(null));
        } catch (Exception ignored) {
            // Ghidra could not compute them; the address references above still stand.
        }
        List<Function> sorted = new ArrayList<>(callers);
        sorted.sort((a, b) -> a.getName().compareTo(b.getName()));
        return sorted;
    }

    private List<Function> calleesOf(Function func) {
        Set<Function> callees;
        try {
            callees = new LinkedHashSet<>(func.getCalledFunctions(null));
        } catch (Exception e) {
            return List.of();
        }
        List<Function> sorted = new ArrayList<>(callees);
        sorted.sort((a, b) -> a.getName().compareTo(b.getName()));
        return sorted;
    }

    private List<Map<String, Object>> summarizeFunctions(Program program,
            List<Function> functions, int cap) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Function f : functions) {
            if (out.size() >= cap) break;
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("name", f.getName());
            item.putAll(ServiceUtils.addressToJson(f.getEntryPoint(), program));
            out.add(item);
        }
        return out;
    }

    /**
     * The caller's own source lines around each call site — "who calls me, and how".
     *
     * <p>Deduped by caller function before decompiling: a caller that calls the target six
     * times must be decompiled once, not six times. Measured ~43 ms per unique caller.
     */
    private List<Map<String, Object>> collectCallContext(Program program, Address target,
            List<Function> callers, int limit, int contextLines) {
        List<Map<String, Object>> out = new ArrayList<>();
        FunctionManager functionManager = program.getFunctionManager();

        // Call sites grouped by the caller that contains them.
        Map<Function, List<Address>> sitesByCaller = new LinkedHashMap<>();
        ReferenceIterator refs = program.getReferenceManager().getReferencesTo(target);
        while (refs.hasNext()) {
            Reference ref = refs.next();
            if (!ref.getReferenceType().isCall()) continue;
            Function containing = functionManager.getFunctionContaining(ref.getFromAddress());
            if (containing == null) continue;
            sitesByCaller.computeIfAbsent(containing, k -> new ArrayList<>()).add(ref.getFromAddress());
        }

        int decompiled = 0;
        for (Map.Entry<Function, List<Address>> entry : sitesByCaller.entrySet()) {
            if (decompiled >= limit) break;
            Function caller = entry.getKey();
            decompiled++;
            DecompileResults results = functionService.decompileFunctionNoRetry(
                caller, program, FunctionBundleService::bundleDecompilerOptions);
            List<ClangLine> lines = (results != null && results.decompileCompleted()
                && results.getCCodeMarkup() != null)
                ? DecompilerUtils.toLines(results.getCCodeMarkup())
                : List.of();
            for (Address site : entry.getValue()) {
                Map<String, Object> item = new LinkedHashMap<>();
                item.put("caller", caller.getName());
                item.put("caller_address", caller.getEntryPoint().toString(false));
                item.put("site_address", site.toString(false));
                int at = indexOfLineContaining(lines, site);
                if (at >= 0) {
                    item.put("line_number", lines.get(at).getLineNumber());
                    // Window is centred on the call, biased upward when it cannot be split
                    // evenly: the guard that decides whether the call happens reads better
                    // than one more line after it.
                    int before = contextLines / 2;
                    int from = Math.max(0, at - before);
                    int to = Math.min(lines.size(), from + contextLines);
                    from = Math.max(0, to - contextLines);
                    StringBuilder text = new StringBuilder();
                    for (int i = from; i < to; i++) {
                        if (i > from) text.append('\n');
                        // ClangLine.toString() gives "<n>: <tokens>" with the indentation
                        // dropped — the indent is a separate field. Put it back: whether the
                        // neighbouring line is inside the branch above it or after it is most
                        // of what makes a window worth more than the call line alone.
                        ClangLine line = lines.get(i);
                        text.append(line.getLineNumber()).append(": ")
                            .append(line.getIndentString());
                        for (ClangToken token : line.getAllTokens()) {
                            text.append(token.getText());
                        }
                        stripTrailingInPlace(text);
                    }
                    item.put("text", text.toString());
                    if (contextLines > 1) {
                        item.put("first_line_number", lines.get(from).getLineNumber());
                        item.put("last_line_number", lines.get(to - 1).getLineNumber());
                    }
                } else {
                    item.put("text", null);
                }
                out.add(item);
            }
        }
        return out;
    }

    private int indexOfLineContaining(List<ClangLine> lines, Address site) {
        for (int i = 0; i < lines.size(); i++) {
            for (ClangToken token : lines.get(i).getAllTokens()) {
                // Comment tokens carry the address they are attached to, so a rendered EOL
                // comment at the call site would match before the call itself and centre the
                // window on the note instead of the code it annotates.
                if (token instanceof ClangCommentToken) continue;
                Address min = token.getMinAddress();
                if (min != null && min.equals(site)) return i;
            }
        }
        return -1;
    }

    /** Drop trailing whitespace from what has been appended so far. */
    private static void stripTrailingInPlace(StringBuilder text) {
        int end = text.length();
        while (end > 0 && Character.isWhitespace(text.charAt(end - 1))
                && text.charAt(end - 1) != '\n') {
            end--;
        }
        text.setLength(end);
    }

    /**
     * References to the entry point, carrying the reference TYPE — which
     * {@code analyze_function_complete} drops, leaving a caller unable to tell a call from
     * a data reference.
     */
    private List<Map<String, Object>> collectXrefs(Program program, Address entry,
            Map<String, Object> truncation) {
        List<Map<String, Object>> out = new ArrayList<>();
        ReferenceIterator refs = program.getReferenceManager().getReferencesTo(entry);
        int total = 0;
        while (refs.hasNext()) {
            Reference ref = refs.next();
            total++;
            if (out.size() >= MAX_XREFS) continue;
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("from", ref.getFromAddress().toString(false));
            item.put("type", ref.getReferenceType().getName());
            Function containing = program.getFunctionManager()
                .getFunctionContaining(ref.getFromAddress());
            if (containing != null) item.put("from_function", containing.getName());
            out.add(item);
        }
        if (total > out.size()) truncation.put("xrefs", true);
        return out;
    }

    private List<Map<String, Object>> collectDisassembly(Program program, Function func,
            Map<String, Object> truncation) {
        List<Map<String, Object>> out = new ArrayList<>();
        InstructionIterator instructions = program.getListing().getInstructions(func.getBody(), true);
        int total = 0;
        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            total++;
            if (out.size() >= MAX_DISASM) continue;
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("address", instruction.getAddress().toString(false));
            item.put("mnemonic", instruction.getMnemonicString());
            List<String> operands = new ArrayList<>();
            for (int i = 0; i < instruction.getNumOperands(); i++) {
                operands.add(instruction.getDefaultOperandRepresentation(i));
            }
            item.put("operands", String.join(", ", operands));
            out.add(item);
        }
        if (total > out.size()) truncation.put("disassembly", true);
        return out;
    }

    /** Whether a {@code fields=} subset pays for target decompilation. */
    public static boolean requiresTargetDecompile(Set<String> fields) {
        return fields == null || fields.contains("decompiled_code");
    }
}
