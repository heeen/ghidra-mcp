package com.xebyte.offline;

import com.xebyte.core.checkout.AddressIndex;
import com.xebyte.core.checkout.AddressIndex.Row;
import com.xebyte.core.checkout.Checkout;
import com.xebyte.core.checkout.CheckoutConfig;
import com.xebyte.core.checkout.CheckoutKey;
import com.xebyte.core.checkout.CheckoutLayout;
import com.xebyte.core.checkout.CheckoutRoot;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.*;

/** index/addresses.tsv: written whole by a sweep, kept current by every pass that rewrites blocks. */
public class AddressIndexTest {

    private Path tempRoot;
    private Checkout checkout;

    private static final Row POOL = new Row("0x08016e58", "data", "", "gpio_init", "08001000");
    private static final Row BASE = new Row("0x40020000", "pointer", "0x08016e58", "gpio_init", "08001000");
    private static final Row REG = new Row("0x40003c0c", "store", "", "dma_start", "08002000");

    @Before
    public void setUp() throws IOException {
        tempRoot = Files.createTempDirectory("address-index-test");
        checkout = new Checkout(CheckoutKey.of("/fw", tempRoot.toString()), "fw",
            CheckoutConfig.defaults(), CheckoutRoot.ofResolved(tempRoot));
    }

    @After
    public void tearDown() throws IOException {
        try (var walk = Files.walk(tempRoot)) {
            walk.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        }
    }

    private String text() throws IOException {
        return Files.readString(tempRoot.resolve(CheckoutLayout.addressesTsv()), StandardCharsets.UTF_8);
    }

    @Test
    public void aSweepWritesRowsSortedByAddressSoGrepAndSortAgree() throws IOException {
        AddressIndex.write(checkout, List.of(REG, BASE, POOL));
        assertEquals("address\tkind\tvia\tfunction\tentry\n"
            + "0x08016e58\tdata\t\tgpio_init\t08001000\n"
            + "0x40003c0c\tstore\t\tdma_start\t08002000\n"
            + "0x40020000\tpointer\t0x08016e58\tgpio_init\t08001000\n", text());
        assertEquals(List.of(POOL, REG, BASE), AddressIndex.parse(text()));
    }

    @Test
    public void aRewrittenFunctionsRowsAreReplacedAndTheOthersKept() throws IOException {
        AddressIndex.write(checkout, List.of(POOL, BASE, REG));
        Row renamed = new Row("0x40020000", "pointer", "0x08016e58", "gpio_port_init", "08001000");

        AddressIndex.update(checkout, Map.of("08001000", List.of(renamed)));

        assertEquals(List.of(REG, renamed), AddressIndex.parse(text()));
    }

    @Test
    public void aFunctionLeavingTheTreeTakesItsRowsWithIt() throws IOException {
        AddressIndex.write(checkout, List.of(POOL, BASE, REG));
        AddressIndex.retain(checkout, Set.of("08002000"));
        assertEquals(List.of(REG), AddressIndex.parse(text()));
    }

    @Test
    public void aTreeSweptBeforeTheIndexExistedIsNotGivenAPartialOne() throws IOException {
        AddressIndex.update(checkout, Map.of("08001000", List.of(POOL)));
        AddressIndex.retain(checkout, Set.of());
        assertFalse("a partial index would read as complete",
            Files.exists(tempRoot.resolve(CheckoutLayout.addressesTsv())));
    }
}
