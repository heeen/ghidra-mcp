package com.xebyte.offline;

import com.xebyte.core.checkout.Checkout;
import com.xebyte.core.checkout.CheckoutConfig;
import com.xebyte.core.checkout.CheckoutKey;
import com.xebyte.core.checkout.CheckoutRegistry;
import com.xebyte.core.checkout.CheckoutRoot;
import com.xebyte.core.checkout.SweepProgress;
import ghidra.program.model.listing.Program;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Found in a live RE session: close_program(save=false) kept the discarded edits in the
 * tree, and STATUS.md went on saying clean. A close that leaves the tree describing
 * something a reopen will not show marks it stale, with a reason, for a reconcile on reopen.
 */
public class CheckoutStaleOnCloseTest {

    private Path tempRoot;
    private Checkout checkout;
    private final CheckoutRegistry registry = CheckoutRegistry.getInstance();

    @Before
    public void setUp() throws IOException {
        registry.clearForTests();
        tempRoot = Files.createTempDirectory("stale-on-close");
        checkout = new Checkout(CheckoutKey.of("/fw", tempRoot.toString()), "fw",
                CheckoutConfig.defaults(), CheckoutRoot.ofResolved(tempRoot));
        registry.register(checkout);
        // Swept at 4, saved at 4, then one comment spliced at 5.
        checkout.setProgress(checkout.progress().withPhase(SweepProgress.Phase.COMPLETE).sweptAt(4L));
        checkout.setSavedAtModification(4L);
    }

    @After
    public void tearDown() {
        registry.clearForTests();
    }

    private static Program program(boolean changed) {
        Program p = mock(Program.class);
        when(p.isChanged()).thenReturn(changed);
        return p;
    }

    @Test
    public void discardingEditsTheTreeTookInMakesItStale() throws IOException {
        checkout.setProgress(checkout.progress().reconciledAt(5L, 1, 0));

        registry.noteClosing(checkout.id(), program(true));

        assertEquals(SweepProgress.Phase.STALE, checkout.progress().phase());
        assertTrue(checkout.progress().lastError(), checkout.progress().lastError().contains("without saving"));
        assertTrue(checkout.recoverOnReattach());
        String status = Files.readString(tempRoot.resolve("STATUS.md"));
        assertTrue(status, status.contains("state: stale"));
    }

    @Test
    public void discardingEditsTheTreeNeverSawLeavesItAlone() {
        // Edited after the last splice, closed before the drain ran: the tree still shows
        // the saved state, which is exactly what a reopen shows.
        registry.noteClosing(checkout.id(), program(true));

        assertEquals(SweepProgress.Phase.COMPLETE, checkout.progress().phase());
        assertFalse(checkout.recoverOnReattach());
    }

    @Test
    public void savedEditsStillQueuedAtCloseMakeItStale() {
        registry.dirtyQueue().markDirty(checkout.id(), List.of("00100000"));

        registry.noteClosing(checkout.id(), program(false));

        assertEquals(SweepProgress.Phase.STALE, checkout.progress().phase());
        assertTrue(checkout.progress().lastError(), checkout.progress().lastError().contains("before saved changes"));
        assertTrue(checkout.recoverOnReattach());
    }

    @Test
    public void aSaveMovesTheBaseline() {
        checkout.setProgress(checkout.progress().reconciledAt(5L, 1, 0));
        registry.noteSaved(checkout.id(), 5L);

        registry.noteClosing(checkout.id(), program(false));

        assertEquals(SweepProgress.Phase.COMPLETE, checkout.progress().phase());
        assertFalse(checkout.recoverOnReattach());
    }
}
