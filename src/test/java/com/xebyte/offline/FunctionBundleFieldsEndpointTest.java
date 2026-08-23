package com.xebyte.offline;

import com.xebyte.core.FunctionBundleService;
import com.xebyte.core.FunctionService;
import com.xebyte.core.ProgramProvider;
import com.xebyte.core.Response;
import ghidra.program.model.listing.Program;
import junit.framework.TestCase;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Set;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * {@code fields=} on {@code /get_function_bundle}: subset reads must not pay
 * for a decompile when they only need listing-level facts.
 */
public class FunctionBundleFieldsEndpointTest extends TestCase {

    public void testRequiresTargetDecompileOnlyForDecompiledCodeOrFullBundle() {
        assertTrue(FunctionBundleService.requiresTargetDecompile(null));
        assertTrue(FunctionBundleService.requiresTargetDecompile(
                Set.of("decompiled_code")));
        assertFalse(FunctionBundleService.requiresTargetDecompile(
                Set.of("callers", "callees", "signature", "labels")));
    }

    public void testUnknownFieldErrorsWithValidList() {
        Program program = mock(Program.class);
        ProgramProvider provider = mock(ProgramProvider.class);
        when(provider.getCurrentProgram()).thenReturn(program);
        FunctionBundleService svc = new FunctionBundleService(
                provider, new NoopThreadingStrategy(), mock(FunctionService.class));
        Response r = svc.getFunctionBundle("401000", "callers,nope", false, 0, 3, false, "");
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().contains("Unknown field"));
        assertTrue(((Response.Err) r).message().contains("callers"));
    }

    public void testRemovedEndpointsGoneFromSourceAndCatalog() throws IOException {
        String catalog = Files.readString(Paths.get("tests/endpoints.json"), StandardCharsets.UTF_8);
        String xref = Files.readString(
                Paths.get("src/main/java/com/xebyte/core/XrefCallGraphService.java"),
                StandardCharsets.UTF_8);
        String symbol = Files.readString(
                Paths.get("src/main/java/com/xebyte/core/SymbolLabelService.java"),
                StandardCharsets.UTF_8);
        String docs = Files.readString(
                Paths.get("src/main/java/com/xebyte/core/DocumentationHashService.java"),
                StandardCharsets.UTF_8);
        for (String gone : new String[] {
                "/get_function_callees",
                "/get_function_callers",
                "/get_function_labels",
                "/get_function_signature" }) {
            assertFalse("must not register " + gone,
                    xref.contains("path = \"" + gone + "\"")
                            || symbol.contains("path = \"" + gone + "\"")
                            || docs.contains("path = \"" + gone + "\""));
            assertFalse("catalog must not list " + gone,
                    catalog.contains("\"path\": \"" + gone + "\""));
        }
        String bundle = Files.readString(
                Paths.get("src/main/java/com/xebyte/core/FunctionBundleService.java"),
                StandardCharsets.UTF_8);
        assertTrue(bundle.contains("path = \"/get_function_bundle\""));
        assertTrue(bundle.contains("fields"));
        assertTrue(xref.contains("path = \"/get_function_jump_targets\""));
    }
}
