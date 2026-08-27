package dev.latchway.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test
import java.nio.charset.StandardCharsets
import javax.crypto.AEADBadTagException
import javax.crypto.spec.SecretKeySpec

class SessionStateEncryptionTest {
    private val snapshot = SessionSnapshot(
        accessToken = SecretValue.of("access-secret-" + "a".repeat(64)),
        refreshToken = SecretValue.of("refresh-secret-" + "r".repeat(32)),
        accessExpiresAtEpochSeconds = 2_000,
        refreshExpiresAtEpochSeconds = 4_000,
        installation = InstallationSummary(
            id = "ins_01J00000000000000000000001",
            platform = "android",
            dpopJkt = "bX0yCl562RPdpf8cJHVLBeUXu6PWExYJ0w-Bydre3q8",
            status = "active",
        ),
        trust = TrustSummary(
            provider = "play_integrity",
            level = "strong_device_verified",
            verifiedAt = "2026-08-27T00:00:00Z",
            expiresAt = "2026-08-27T01:00:00Z",
        ),
    )

    @Test
    fun stateRoundTripsThroughAesGcmWithoutPlaintextCredentials() {
        val key = SecretKeySpec(ByteArray(32) { it.toByte() }, "AES")
        val aad = "application/environment/key-binding".toByteArray(StandardCharsets.UTF_8)
        val plaintext = encodeSnapshot(snapshot).toByteArray(StandardCharsets.UTF_8)
        val encrypted = SessionStateEncryption.encrypt(key, aad, plaintext)

        val ciphertextText = String(encrypted.ciphertext, StandardCharsets.ISO_8859_1)
        assertFalse(ciphertextText.contains("access-secret"))
        assertFalse(ciphertextText.contains("refresh-secret"))
        val restored = decodeSnapshot(
            String(SessionStateEncryption.decrypt(key, aad, encrypted), StandardCharsets.UTF_8),
        )
        assertEquals(snapshot.accessToken.reveal(), restored.accessToken.reveal())
        assertEquals(snapshot.refreshToken.reveal(), restored.refreshToken.reveal())
        assertEquals(snapshot.installation, restored.installation)
        assertEquals(snapshot.trust, restored.trust)
    }

    @Test
    fun stateRejectsTamperingAndWrongBinding() {
        val key = SecretKeySpec(ByteArray(32) { it.toByte() }, "AES")
        val aad = "correct-binding".toByteArray(StandardCharsets.UTF_8)
        val encrypted = SessionStateEncryption.encrypt(
            key,
            aad,
            encodeSnapshot(snapshot).toByteArray(StandardCharsets.UTF_8),
        )
        encrypted.ciphertext[0] = (encrypted.ciphertext[0].toInt() xor 1).toByte()
        assertThrows(AEADBadTagException::class.java) {
            SessionStateEncryption.decrypt(key, aad, encrypted)
        }

        val untampered = SessionStateEncryption.encrypt(
            key,
            aad,
            encodeSnapshot(snapshot).toByteArray(StandardCharsets.UTF_8),
        )
        assertThrows(AEADBadTagException::class.java) {
            SessionStateEncryption.decrypt(key, "wrong-binding".toByteArray(), untampered)
        }
    }
}
