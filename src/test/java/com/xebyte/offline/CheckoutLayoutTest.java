package com.xebyte.offline;

import com.xebyte.core.checkout.CheckoutLayout;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Offline tests for {@link CheckoutLayout} filename padding and sanitisation.
 */
public class CheckoutLayoutTest {

    @Test
    public void filenamePaddingGivesLexicalOrderEqualToAddressOrder() {
        int pointerSize = 4; // 8 hex chars
        long[] addresses = {0x10L, 0x100L, 0x1000L, 0xffffL, 0x10000L, 0x6fdd1234L};
        List<String> names = new ArrayList<>();
        for (long addr : addresses) {
            names.add(CheckoutLayout.functionFileName(addr, "Fn", pointerSize));
        }
        List<String> sorted = new ArrayList<>(names);
        Collections.sort(sorted);
        assertEquals(
                "zero-padded hex must make lexical order match address order",
                names, sorted);

        assertEquals("00000010_Fn.c", names.get(0));
        assertEquals("00000100_Fn.c", names.get(1));
        assertEquals("6fdd1234_Fn.c", names.get(5));
    }

    @Test
    public void filenamePaddingFor64BitPointers() {
        String name = CheckoutLayout.functionFileName(0x180001000L, "ParseHeader", 8);
        assertEquals("0000000180001000_ParseHeader.c", name);
    }

    @Test
    public void sanitisesCppOperatorAndTemplateNames() {
        assertEquals("operator", CheckoutLayout.sanitiseName("operator<<"));
        assertEquals(
                "std_vector_int_push_back",
                CheckoutLayout.sanitiseName("std::vector<int>::push_back"));
        assertEquals(
                "MyClass_operator",
                CheckoutLayout.sanitiseName("MyClass::operator=="));
    }

    @Test
    public void sanitiseKeepsSafeCharsetAndCollapsesRuns() {
        // Underscore is itself safe, so runs of '_' are preserved.
        assertEquals("foo__bar.baz-1", CheckoutLayout.sanitiseName("foo__bar.baz-1"));
        // Multiple unsafe chars collapse to a single underscore.
        assertEquals("a_b", CheckoutLayout.sanitiseName("a<<<>>>b"));
    }

    @Test
    public void sanitiseTruncatesTo96() {
        String longName = "a".repeat(200);
        String sanitised = CheckoutLayout.sanitiseName(longName);
        assertEquals(96, sanitised.length());
    }

    @Test
    public void layoutPathsAreStableRelativeNames() {
        assertEquals("checkout.json", CheckoutLayout.checkoutJson());
        assertEquals("STATUS.md", CheckoutLayout.statusMd());
        assertEquals("README.md", CheckoutLayout.readmeMd());
        assertEquals("modules/index.md", CheckoutLayout.modulesIndexMd());
        assertEquals("modules/c05/README.md", CheckoutLayout.moduleReadme("c05"));
        assertEquals(
                "modules/c05/00001000_Foo.c",
                CheckoutLayout.moduleFunctionFile("c05", "00001000_Foo.c"));
        assertEquals("index/by-address.tsv", CheckoutLayout.byAddressTsv());
        assertEquals("callgraph.tsv", CheckoutLayout.callgraphTsv());
        assertEquals("strings.txt", CheckoutLayout.stringsTxt());
        assertEquals("globals.txt", CheckoutLayout.globalsTxt());
    }

    @Test
    public void functionFileNameUsesSanitisedName() {
        String file = CheckoutLayout.functionFileName(0x1000L, "operator<<", 4);
        assertEquals("00001000_operator.c", file);
        assertFalse(file.contains("<"));
        assertTrue(file.endsWith(".c"));
    }
}
