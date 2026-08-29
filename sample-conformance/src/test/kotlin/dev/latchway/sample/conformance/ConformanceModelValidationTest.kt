package dev.latchway.sample.conformance

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
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

    @Test
    fun proofTamperChangesSignatureMaterialWithoutChangingJwtShape() {
        val original = "header.payload.ABCDEFG"
        val tampered = tamperedDpopProof(original)
        assertEquals(listOf(6, 7, 7), tampered.split('.').map(String::length))
        assertEquals("header.payload.BBCDEFG", tampered)
        assertNotEquals(original, tampered)
        assertThrows(IllegalArgumentException::class.java) { tamperedDpopProof("not-a-jwt") }
    }
}
