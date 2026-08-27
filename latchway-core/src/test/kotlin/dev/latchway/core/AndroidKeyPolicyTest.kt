package dev.latchway.core

import org.junit.Assert.assertEquals
import org.junit.Test

class AndroidKeyPolicyTest {
    @Test
    fun strongBoxIsPreferredThenDefaultKeystoreIsFallback() {
        assertEquals(
            listOf(KeyGenerationAttempt.STRONGBOX, KeyGenerationAttempt.DEFAULT_KEYSTORE),
            AndroidKeystoreInstallationSigner.generationAttempts(
                KeyPolicy(preferStrongBox = true),
                apiLevel = 37,
                strongBoxFeaturePresent = true,
            ),
        )
    }

    @Test
    fun unsupportedStrongBoxSkipsImpossibleAttempt() {
        assertEquals(
            listOf(KeyGenerationAttempt.DEFAULT_KEYSTORE),
            AndroidKeystoreInstallationSigner.generationAttempts(
                KeyPolicy(preferStrongBox = true),
                apiLevel = 27,
                strongBoxFeaturePresent = true,
            ),
        )
        assertEquals(
            listOf(KeyGenerationAttempt.DEFAULT_KEYSTORE),
            AndroidKeystoreInstallationSigner.generationAttempts(
                KeyPolicy(preferStrongBox = true),
                apiLevel = 37,
                strongBoxFeaturePresent = false,
            ),
        )
    }

    @Test
    fun explicitPolicyCanAvoidStrongBoxAttempt() {
        assertEquals(
            listOf(KeyGenerationAttempt.DEFAULT_KEYSTORE),
            AndroidKeystoreInstallationSigner.generationAttempts(
                KeyPolicy(preferStrongBox = false, allowSoftwareBacked = true),
                apiLevel = 37,
                strongBoxFeaturePresent = true,
            ),
        )
    }
}
