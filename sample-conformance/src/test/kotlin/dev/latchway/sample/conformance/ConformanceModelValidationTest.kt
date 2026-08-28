package dev.latchway.sample.conformance

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ConformanceModelValidationTest {
    @Test
    fun modelLimitUsesUtf8Bytes() {
        assertTrue(isValidModel("a".repeat(256)))
        assertTrue(isValidModel("é".repeat(128)))
        assertFalse(isValidModel("é".repeat(129)))
        assertFalse(isValidModel(" model"))
        assertFalse(isValidModel("model\n"))
    }
}
