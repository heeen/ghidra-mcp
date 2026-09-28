package com.xebyte.offline;

import com.xebyte.core.AmbiguousProgramException;
import com.xebyte.core.ProgramScriptService;
import com.xebyte.core.ProjectProgramProvider;
import com.xebyte.core.Response;
import com.xebyte.headless.HeadlessProgramProvider;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.*;

/**
 * The program model both servers now share: how a name resolves, and what closing does
 * with unsaved edits.
 *
 * <p>Before the two providers shared a base, headless resolved only bare names of
 * programs someone had explicitly opened (so {@code program=/fw/gnutrue} and any
 * unopened project file answered "Program not found"), {@code close_program save=true}
 * released without saving, and {@code switch_program} reported success while doing
 * nothing. The GUI's {@code save=false} still saved, through the cache release.
 */
public class ProjectProgramProviderTest {

    /** A provider over a mocked project; nothing GUI- or headless-specific. */
    private static final class Fixture extends ProjectProgramProvider {
        final Project project;
        final ProjectData data;

        Fixture() {
            super(null, true);
            project = mock(Project.class);
            data = mock(ProjectData.class);
            when(project.getProjectData()).thenReturn(data);
        }

        @Override
        protected Project project() {
            return project;
        }

        @Override
        public Program getCurrentProgram() {
            return null;
        }

        @Override
        public void setCurrentProgram(Program program) {
        }

        /** A project file at {@code path} whose open yields a fresh mocked program. */
        Program file(String path) throws Exception {
            Program p = programAt(path);
            DomainFile df = p.getDomainFile();
            when(df.getDomainObject(any(), anyBoolean(), anyBoolean(), any())).thenReturn(p);
            when(data.getFile(path)).thenReturn(df);
            return p;
        }
    }

    private static Program programAt(String path) {
        Program p = mock(Program.class);
        DomainFile df = mock(DomainFile.class);
        when(df.getPathname()).thenReturn(path);
        when(df.getName()).thenReturn(path.substring(path.lastIndexOf('/') + 1));
        when(p.getDomainFile()).thenReturn(df);
        when(p.getName()).thenReturn(path.substring(path.lastIndexOf('/') + 1));
        return p;
    }

    // ------------------------------------------------------------------ match

    @Test
    public void exactPathWinsOverSameNameElsewhere() {
        Program v1 = programAt("/1.10/D2Common.dll");
        Program v2 = programAt("/1.13d/D2Common.dll");
        assertSame(v2, ProjectProgramProvider.match(List.of(v1, v2), "/1.13d/D2Common.dll"));
    }

    @Test
    public void bareNameShared_byTwoVersionsIsAmbiguousNotAGuess() {
        Program v1 = programAt("/1.10/D2Common.dll");
        Program v2 = programAt("/1.13d/D2Common.dll");
        try {
            ProjectProgramProvider.match(List.of(v1, v2), "D2Common.dll");
            fail("two programs share the name; picking one sends writes to a guess");
        } catch (AmbiguousProgramException e) {
            assertEquals(List.of("/1.10/D2Common.dll", "/1.13d/D2Common.dll"), e.candidates());
            assertTrue(e.getMessage(), e.getMessage().contains("full project path"));
        }
    }

    @Test
    public void exactNameBeatsASubstringNeighbour() {
        Program gnu = programAt("/fw/gnu");
        Program gnutrue = programAt("/fw/gnutrue");
        assertSame(gnu, ProjectProgramProvider.match(List.of(gnutrue, gnu), "gnu"));
    }

    @Test
    public void substringOnlyWhenUnique() {
        Program a = programAt("/fw/gnutrue");
        Program b = programAt("/fw/gnufalse");
        assertSame(a, ProjectProgramProvider.match(List.of(a), "true"));
        assertThrows(AmbiguousProgramException.class,
            () -> ProjectProgramProvider.match(List.of(a, b), "gnu"));
    }

    @Test
    public void pathNeverSubstringMatches() {
        Program orig = programAt("/Mods/D2Common.dll.orig");
        assertNull(ProjectProgramProvider.match(List.of(orig), "/Mods/D2Common.dll"));
    }

    // -------------------------------------------------------------- resolution

    @Test
    public void unopenedProjectFileOpensOnDemandByPath() throws Exception {
        Fixture f = new Fixture();
        Program p = f.file("/fw/gnutrue");
        assertSame(p, f.getProgram("/fw/gnutrue"));
        assertEquals(1, f.getAllOpenPrograms().length);
        // ...and a second lookup is served from the cache, not re-opened.
        assertSame(p, f.getProgram("gnutrue"));
        verify(p.getDomainFile(), times(1)).getDomainObject(any(), anyBoolean(), anyBoolean(), any());
    }

    @Test
    public void projectFileBeatsASubstringOfAnOpenProgram() throws Exception {
        Fixture f = new Fixture();
        Program gnutrue = f.file("/gnutrue");
        Program gnu = f.file("/gnu");
        assertSame(gnutrue, f.getProgram("/gnutrue"));
        assertSame("'gnu' names the file gnu, not the open gnutrue", gnu, f.getProgram("gnu"));
    }

    @Test
    public void unknownNameIsNull() {
        assertNull(new Fixture().getProgram("nope"));
    }

    // ----------------------------------------------------------------- closing

    @Test
    public void closeWithSaveSavesUnsavedEdits() throws Exception {
        Fixture f = new Fixture();
        Program p = f.file("/fw/a");
        f.getProgram("/fw/a");
        when(p.isChanged()).thenReturn(true);

        assertTrue(f.closeProgram(p, true));
        verify(p.getDomainFile()).save(any(TaskMonitor.class));
        verify(p).release(any());
        assertEquals(0, f.getAllOpenPrograms().length);
    }

    @Test
    public void closeWithoutSaveDiscards() throws Exception {
        Fixture f = new Fixture();
        Program p = f.file("/fw/a");
        f.getProgram("/fw/a");
        when(p.isChanged()).thenReturn(true);

        assertTrue(f.releaseCachedProgram("/fw/a", false));
        verify(p.getDomainFile(), never()).save(any(TaskMonitor.class));
        verify(p).release(any());
    }

    @Test
    public void closeByPathIsExact() throws Exception {
        Fixture f = new Fixture();
        Program target = f.file("/Mods/D2Common.dll");
        Program orig = f.file("/Mods/D2Common.dll.orig");
        f.getProgram("/Mods/D2Common.dll");
        f.getProgram("/Mods/D2Common.dll.orig");

        assertTrue(f.closeProgramByPath("/Mods/D2Common.dll"));
        verify(target).release(any());
        verify(orig, never()).release(any());
        assertArrayEquals(new Program[] {orig}, f.getAllOpenPrograms());
    }

    // --------------------------------------------------------------- switching

    @Test
    public void headlessSwitchAmongSeveralSaysItDidNotSwitch() {
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.trackOpenProgram(programAt("/a.dll"));
        provider.trackOpenProgram(programAt("/b.dll"));

        Response r = new ProgramScriptService(provider, new NoopThreadingStrategy()).switchProgram("b.dll");

        assertTrue("headless keeps no current program, so success would be a lie: " + r,
            r instanceof Response.Err);
        assertTrue(r.toString(), r.toString().contains("program=\\\"/b.dll\\\"")
            || r.toString().contains("program=\"/b.dll\""));
    }

    @Test
    public void switchToAnAmbiguousNameIsRefused() {
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.trackOpenProgram(programAt("/1.10/D2Common.dll"));
        provider.trackOpenProgram(programAt("/1.13d/D2Common.dll"));

        Response r = new ProgramScriptService(provider, new NoopThreadingStrategy()).switchProgram("D2Common.dll");

        assertTrue(r instanceof Response.Err);
        assertTrue(r.toString(), r.toString().contains("ambiguous"));
    }
}
