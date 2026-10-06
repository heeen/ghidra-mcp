package com.xebyte.offline;

import com.xebyte.core.checkout.CheckoutConfig;
import com.xebyte.core.checkout.ExclusionRule;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Offline tests for {@link CheckoutConfig} clamps and {@link ExclusionRule} parsing.
 */
public class CheckoutConfigTest {

    @Test
    public void parsesAllThreeExclusionKinds() {
        ExclusionRule tag = ExclusionRule.parse("tag:LIB_CRT");
        assertEquals(ExclusionRule.Kind.TAG, tag.kind());
        assertEquals("LIB_CRT", tag.value());

        ExclusionRule part = ExclusionRule.parse("partition:c07");
        assertEquals(ExclusionRule.Kind.PARTITION, part.kind());
        assertEquals("c07", part.value());

        ExclusionRule range = ExclusionRule.parse("range:6fdd0000-6fde0000");
        assertEquals(ExclusionRule.Kind.RANGE, range.kind());
        assertEquals("6fdd0000-6fde0000", range.value());
    }

    @Test
    public void malformedExclusionThrowsNamingAcceptedForms() {
        String[] bad = {
                "",
                "LIB_CRT",
                "name:Foo.*",
                "tag:",
                ":LIB_CRT",
                "range:onlylo",
                "regex:.*",
        };
        for (String spec : bad) {
            try {
                ExclusionRule.parse(spec);
                fail("expected IllegalArgumentException for: " + spec);
            } catch (IllegalArgumentException expected) {
                assertTrue(
                        "message must name accepted forms: " + expected.getMessage(),
                        expected.getMessage().contains("tag:")
                                && expected.getMessage().contains("partition:")
                                && expected.getMessage().contains("range:"));
            }
        }
    }

    @Test
    public void throttlePercentClampsToZeroThroughNinety() {
        assertEquals(0, CheckoutConfig.defaults().withThrottlePercent(-5).throttlePercent());
        assertEquals(90, CheckoutConfig.defaults().withThrottlePercent(150).throttlePercent());
        assertEquals(10, CheckoutConfig.defaults().throttlePercent());
        assertEquals(45, CheckoutConfig.builder().throttlePercent(45).build().throttlePercent());
    }

    @Test
    public void bandSizeFloorsAtOne() {
        assertEquals(1, CheckoutConfig.defaults().withBandSize(0).bandSize());
        assertEquals(1, CheckoutConfig.defaults().withBandSize(-9).bandSize());
        assertEquals(20, CheckoutConfig.defaults().bandSize());
        assertEquals(64, CheckoutConfig.builder().bandSize(64).build().bandSize());
    }

    @Test
    public void defaultsUseEmptyListsMeaningFullCascade() {
        CheckoutConfig cfg = CheckoutConfig.defaults();
        assertTrue(cfg.enabledStrategies().isEmpty());
        assertTrue(cfg.exclusions().isEmpty());
        assertTrue(cfg.includeOnly().isEmpty());
        assertEquals(30, cfg.decompileTimeoutSeconds());
        assertEquals(600, cfg.analysisWaitSeconds());
        assertEquals(32768, cfg.maxFileBytes());
        assertTrue(cfg.disassembleMissing());
    }

    @Test
    public void disassembleMissingDefaultsTrueAndRoundTrips() {
        assertTrue(CheckoutConfig.defaults().disassembleMissing());
        assertFalse(CheckoutConfig.builder().disassembleMissing(false).build().disassembleMissing());
        assertTrue(CheckoutConfig.defaults().withDisassembleMissing(false).withDisassembleMissing(true)
                .disassembleMissing());
    }

    @Test
    public void maxFileBytesFloorsAt4096AndDefaultsTo32768() {
        assertEquals(4096, CheckoutConfig.defaults().withMaxFileBytes(100).maxFileBytes());
        assertEquals(4096, CheckoutConfig.defaults().withMaxFileBytes(0).maxFileBytes());
        assertEquals(32768, CheckoutConfig.defaults().maxFileBytes());
        assertEquals(65536, CheckoutConfig.builder().maxFileBytes(65536).build().maxFileBytes());
    }

    @Test
    public void withersPreserveAndReplaceFields() {
        CheckoutConfig cfg = CheckoutConfig.defaults()
                .withExclusions(List.of(ExclusionRule.parse("tag:LIB_CRT")))
                .withIncludeOnly(List.of(ExclusionRule.parse("partition:c03")))
                .withEnabledStrategies(List.of("literal_locality"));
        assertEquals(1, cfg.exclusions().size());
        assertEquals(1, cfg.includeOnly().size());
        assertEquals(List.of("literal_locality"), cfg.enabledStrategies());
    }
}
