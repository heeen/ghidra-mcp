package com.xebyte.offline;

import com.xebyte.core.checkout.CheckoutObserver;
import com.xebyte.core.checkout.DirtyQueue;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.DomainObjectChangeRecord;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectEvent;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.util.FunctionChangeRecord;
import ghidra.program.util.ProgramChangeRecord;
import ghidra.program.util.ProgramEvent;
import ghidra.util.task.TaskMonitor;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Event→address translation for {@link CheckoutObserver}. No decompile, no
 * disk — the observer must stay EDT-safe.
 */
public class CheckoutObserverTest {

    @Test
    public void functionAddedDirtiesEntry() {
        Address entry = addr("00100000");
        Function func = mock(Function.class);
        when(func.getEntryPoint()).thenReturn(entry);
        ProgramChangeRecord rec = new ProgramChangeRecord(
                ProgramEvent.FUNCTION_ADDED, entry, entry, func, null, func);

        CheckoutObserver.Hint hint = CheckoutObserver.translate(event(rec), program());
        assertEquals(Set.of("00100000"), hint.addresses());
        assertFalse(hint.needsReconcile());
    }

    @Test
    public void functionRemovedYieldsAddressEvenWhenGoneFromProgram() {
        // THE BUG: looking up by address after FUNCTION_REMOVED returns null
        // and the removal is silently dropped. Address must come off the record.
        Address entry = addr("00100abc");
        Function gone = mock(Function.class);
        when(gone.getEntryPoint()).thenReturn(entry);

        FunctionManager fm = mock(FunctionManager.class);
        when(fm.getFunctionAt(any())).thenReturn(null);
        when(fm.getFunctionContaining(any())).thenReturn(null);
        Program program = mock(Program.class);
        when(program.getFunctionManager()).thenReturn(fm);

        ProgramChangeRecord rec = new ProgramChangeRecord(
                ProgramEvent.FUNCTION_REMOVED, entry, entry, gone, gone, null);

        CheckoutObserver.Hint hint = CheckoutObserver.translate(event(rec), program);
        assertEquals(Set.of("00100abc"), hint.addresses());
        assertFalse(hint.needsReconcile());
    }

    @Test
    public void functionBodyChangedDirtiesEntry() {
        Address entry = addr("00200000");
        Function func = mock(Function.class);
        when(func.getEntryPoint()).thenReturn(entry);
        ProgramChangeRecord rec = new ProgramChangeRecord(
                ProgramEvent.FUNCTION_BODY_CHANGED, entry, entry, func, null, null);

        CheckoutObserver.Hint hint = CheckoutObserver.translate(event(rec), program());
        assertEquals(Set.of("00200000"), hint.addresses());
    }

    @Test
    public void signatureChangeAlsoDirtiesCallers() {
        Address entry = addr("00100000");
        Address callerEntry = addr("00100100");
        Function callee = mock(Function.class);
        Function caller = mock(Function.class);
        when(callee.getEntryPoint()).thenReturn(entry);
        when(caller.getEntryPoint()).thenReturn(callerEntry);
        when(callee.getCallingFunctions(any(TaskMonitor.class)))
                .thenReturn(Set.of(caller));

        FunctionChangeRecord rec = new FunctionChangeRecord(
                callee, FunctionChangeRecord.FunctionChangeType.PARAMETERS_CHANGED);
        assertTrue("PARAMETERS_CHANGED must count as signature",
                rec.isFunctionSignatureChange());

        // FunctionChangeRecord's event type is FUNCTION_CHANGED (set by ctor).
        // Build an event that carries it.
        DomainObjectChangedEvent ev = event(rec);
        CheckoutObserver.Hint hint = CheckoutObserver.translate(ev, program());
        assertTrue(hint.addresses().contains("00100000"));
        assertTrue(
                "signature change must dirty callers: " + hint.addresses(),
                hint.addresses().contains("00100100"));
    }

    @Test
    public void symbolRenamedDirtiesContainingFunction() {
        Address at = addr("00100040");
        Address entry = addr("00100000");
        Function containing = mock(Function.class);
        when(containing.getEntryPoint()).thenReturn(entry);

        FunctionManager fm = mock(FunctionManager.class);
        when(fm.getFunctionContaining(at)).thenReturn(containing);
        Program program = mock(Program.class);
        when(program.getFunctionManager()).thenReturn(fm);

        ProgramChangeRecord rec = new ProgramChangeRecord(
                ProgramEvent.SYMBOL_RENAMED, at, at, null, "old", "new");

        CheckoutObserver.Hint hint = CheckoutObserver.translate(event(rec), program);
        assertEquals(Set.of("00100000"), hint.addresses());
    }

    @Test
    public void commentChangedDirtiesContainingFunction() {
        Address at = addr("00100010");
        Address entry = addr("00100000");
        Function containing = mock(Function.class);
        when(containing.getEntryPoint()).thenReturn(entry);

        FunctionManager fm = mock(FunctionManager.class);
        when(fm.getFunctionContaining(at)).thenReturn(containing);
        Program program = mock(Program.class);
        when(program.getFunctionManager()).thenReturn(fm);

        ProgramChangeRecord rec = new ProgramChangeRecord(
                ProgramEvent.COMMENT_CHANGED, at, at, null, null, "note");

        CheckoutObserver.Hint hint = CheckoutObserver.translate(event(rec), program);
        assertEquals(Set.of("00100000"), hint.addresses());
    }

    @Test
    public void codeAddedDirtiesOverlappingFunctions() {
        Address start = addr("00100000");
        Address end = addr("00100100");
        Address entryA = addr("00100000");
        Address entryB = addr("00100080");
        Function a = mock(Function.class);
        Function b = mock(Function.class);
        when(a.getEntryPoint()).thenReturn(entryA);
        when(b.getEntryPoint()).thenReturn(entryB);

        FunctionManager fm = mock(FunctionManager.class);
        // Prefer the containing fallback — AddressSet construction with mock
        // addresses is unreliable offline. Overlap intent is the same.
        when(fm.getFunctionContaining(start)).thenReturn(a);
        when(fm.getFunctionContaining(end)).thenReturn(b);
        when(fm.getFunctionsOverlapping(any()))
                .thenThrow(new RuntimeException("force fallback"));

        Program program = mock(Program.class);
        when(program.getFunctionManager()).thenReturn(fm);

        ProgramChangeRecord rec = new ProgramChangeRecord(
                ProgramEvent.CODE_ADDED, start, end, null, null, null);

        CheckoutObserver.Hint hint = CheckoutObserver.translate(event(rec), program);
        assertTrue(hint.addresses().contains("00100000"));
        assertTrue(hint.addresses().contains("00100080"));
    }

    @Test
    public void restoredSetsNeedsReconcileAndEnumeratesNothing() {
        DomainObjectChangeRecord restored =
                new DomainObjectChangeRecord(DomainObjectEvent.RESTORED);
        // Mix in a FUNCTION_ADDED — RESTORED must still win without enumerating.
        Address entry = addr("00100000");
        ProgramChangeRecord added = new ProgramChangeRecord(
                ProgramEvent.FUNCTION_ADDED, entry, entry, null, null, null);

        CheckoutObserver.Hint hint = CheckoutObserver.translate(
                event(restored, added), program());
        assertTrue(hint.needsReconcile());
        assertTrue(
                "RESTORED must not enumerate: " + hint.addresses(),
                hint.addresses().isEmpty());
    }

    @Test
    public void boundCollapseIsOwnedByDirtyQueue() {
        // Observer yields addresses; DirtyQueue collapses storms. Pin the
        // contract that translate itself does not invent needsReconcile for
        // a large batch of ordinary records.
        List<DomainObjectChangeRecord> records = new ArrayList<>();
        for (int i = 0; i < 50; i++) {
            Address a = addr(String.format("%08x", 0x100000 + i));
            records.add(new ProgramChangeRecord(
                    ProgramEvent.FUNCTION_ADDED, a, a, null, null, null));
        }
        DomainObjectChangedEvent ev = new DomainObjectChangedEvent(
                mock(DomainObject.class), records);
        CheckoutObserver.Hint hint = CheckoutObserver.translate(ev, program());
        assertFalse(hint.needsReconcile());
        assertEquals(50, hint.addresses().size());
        assertEquals(DirtyQueue.ADDRESS_BOUND, 2000);
    }

    // -------------------------------------------------------------------------

    private static Program program() {
        Program program = mock(Program.class);
        FunctionManager fm = mock(FunctionManager.class);
        when(program.getFunctionManager()).thenReturn(fm);
        return program;
    }

    private static Address addr(String hex) {
        Address a = mock(Address.class);
        when(a.toString(false)).thenReturn(hex);
        return a;
    }

    private static DomainObjectChangedEvent event(DomainObjectChangeRecord... records) {
        return new DomainObjectChangedEvent(
                mock(DomainObject.class), List.of(records));
    }
}
