package dev.latchway.sample.conformance

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import kotlinx.coroutines.runBlocking

class ConformanceModelValidationTest {
    @Test
    fun applicationPinsUseTheExactCompleteProtectedKeySet() {
        val expected = mapOf(
            "application_identifier" to "dev.latchway.conformance",
            "app_version" to "1.0.0",
            "build_number" to "1",
            "signing_certificate_sha256" to "a".repeat(64),
            "cloud_project_number" to "123",
            "installer_package" to "com.android.vending",
            "play_track" to "internal",
            "require_licensed" to "true",
            "source_commit" to "b".repeat(40),
            "core_commit" to "c".repeat(40),
            "contract_bundle_sha256" to "d".repeat(64),
            "gateway_image_digest" to "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "gateway_configuration_sha256" to "f".repeat(64),
            "gateway_origin" to "https://gateway.example.test",
            "gateway_environment" to "production",
            "gateway_deployment_key_id" to "deployment-key",
            "gateway_deployment_statement_sha256" to "0".repeat(64),
            "gateway_deployment_public_key_sha256" to "1".repeat(64),
            "error_mapping_feature" to "missing_feature",
        )
        fun build(pins: Map<String, String>): Map<String, String> =
            completeApplicationPins(
                expectedPins = pins,
                applicationIdentifier = "dev.latchway.conformance",
                appVersion = "1.0.0",
                buildNumber = "1",
                signingCertificateSha256 = "a".repeat(64),
                cloudProjectNumber = "123",
                installerPackage = "com.android.vending",
                playTrack = "internal",
                requireLicensed = "true",
                gatewayEnvironment = "production",
                errorMappingFeature = "missing_feature",
            )

        assertEquals(expected, build(expected))
        assertThrows(IllegalArgumentException::class.java) {
            build(expected - "error_mapping_feature")
        }
    }

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

    @Test
    fun oneUseIdentityProviderReturnsTheGrantExactlyOnceAndRedactsItself() = runBlocking {
        val provider = OneUseIdentityTokenProvider("header.payload.signature")
        assertEquals("header.payload.signature", provider.identityToken())
        assertEquals("OneUseIdentityTokenProvider(token=[REDACTED])", provider.toString())
        val error = assertThrows(dev.latchway.core.LatchwayException::class.java) {
            runBlocking { provider.identityToken() }
        }
        assertEquals(dev.latchway.core.LatchwayErrorCode.IDENTITY_TOKEN_MISSING, error.code)
    }

    @Test
    fun bootstrapSlotRejectsMismatchAndConsumesMatchingCoordinates() = runBlocking {
        val slot = OneTimeIdentityGrantSlotState()
        val token = "header.payload.signature"
        val hash = MessageDigest.getInstance("SHA-256")
            .digest(token.toByteArray(StandardCharsets.US_ASCII))
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }
        val coordinates = BootstrapCoordinates(
            PHYSICAL_GRANT_AUDIENCE,
            "a".repeat(40),
            "app_0${"A".repeat(25)}",
            "dev.latchway.conformance",
            "firebase",
            "play-integrity-123-1",
            "123",
            "1",
            hash,
        )
        slot.offer(coordinates, token.toByteArray(StandardCharsets.US_ASCII))
        val consumed = slot.take(coordinates)
        assertEquals(token, consumed?.token)
        assertFalse(consumed.toString().contains(token))
        assertThrows(IllegalArgumentException::class.java) {
            slot.offer(
                coordinates,
                token.toByteArray(StandardCharsets.US_ASCII),
            )
        }
        assertEquals(null, slot.take(coordinates))

        val rejected = OneTimeIdentityGrantSlotState()
        val wrongHash = coordinates.copy(grantSha256 = "b".repeat(64))
        assertThrows(IllegalArgumentException::class.java) {
            rejected.offer(
                wrongHash,
                token.toByteArray(StandardCharsets.US_ASCII),
            )
        }
        assertEquals(null, rejected.take(coordinates))
        assertThrows(IllegalArgumentException::class.java) {
            rejected.offer(coordinates, token.toByteArray(StandardCharsets.US_ASCII))
        }

        val timedOut = OneTimeIdentityGrantSlotState(grantWaitMillis = 1)
        assertEquals(null, timedOut.take(coordinates))
        assertThrows(IllegalArgumentException::class.java) {
            timedOut.offer(coordinates, token.toByteArray(StandardCharsets.US_ASCII))
        }
        assertEquals(null, timedOut.take(coordinates))
    }

    @Test
    fun bootstrapSlotFailsClosedForWrongCoordinatesOversizeAndNonJwt() {
        runBlocking {
            val token = "header.payload.signature"
            val bytes = token.toByteArray(StandardCharsets.US_ASCII)
            val hash = MessageDigest.getInstance("SHA-256").digest(bytes)
                .joinToString("") { "%02x".format(it.toInt() and 0xff) }
            val coordinates = BootstrapCoordinates(
                PHYSICAL_GRANT_AUDIENCE,
                "a".repeat(40),
                "app_0${"A".repeat(25)}",
                "dev.latchway.conformance",
                "firebase",
                "play-integrity-123-1",
                "123",
                "1",
                hash,
            )

            val mismatch = OneTimeIdentityGrantSlotState()
            mismatch.offer(coordinates, bytes.copyOf())
            assertEquals(
                null,
                mismatch.take(coordinates.copy(runId = "play-integrity-123-2", runAttempt = "2")),
            )
            assertThrows(IllegalArgumentException::class.java) {
                mismatch.offer(coordinates, bytes.copyOf())
            }

            val oversize = OneTimeIdentityGrantSlotState()
            val oversizedBytes = ByteArray(65_537) { 'a'.code.toByte() }
            assertThrows(IllegalArgumentException::class.java) {
                oversize.offer(coordinates, oversizedBytes)
            }
            assertTrue(oversizedBytes.all { it == 0.toByte() })

            val malformed = OneTimeIdentityGrantSlotState()
            val malformedBytes = "not an identity jwt".toByteArray(StandardCharsets.US_ASCII)
            val malformedCoordinates = coordinates.copy(
                grantSha256 = MessageDigest.getInstance("SHA-256").digest(malformedBytes)
                    .joinToString("") { "%02x".format(it.toInt() and 0xff) },
            )
            assertThrows(IllegalArgumentException::class.java) {
                malformed.offer(malformedCoordinates, malformedBytes)
            }
            assertTrue(malformedBytes.all { it == 0.toByte() })

            assertThrows(IllegalArgumentException::class.java) {
                coordinates.copy(audience = "wrong-audience")
            }
            assertThrows(IllegalArgumentException::class.java) {
                coordinates.copy(sourceCommit = "not-a-commit")
            }
            assertThrows(IllegalArgumentException::class.java) {
                coordinates.copy(applicationId = "not-an-application")
            }
            assertThrows(IllegalArgumentException::class.java) {
                coordinates.copy(packageName = "not-a-package")
            }
            assertThrows(IllegalArgumentException::class.java) {
                coordinates.copy(identityProvider = "Not_Canonical")
            }
            assertThrows(IllegalArgumentException::class.java) {
                coordinates.copy(grantSha256 = "not-a-hash")
            }
            assertThrows(IllegalArgumentException::class.java) {
                coordinates.copy(runId = "play-integrity-999-1")
            }
        }
    }

    @Test
    fun identityGrantMustBeACompactAsciiJwt() {
        assertTrue(isValidIdentityJwt("header.payload.signature"))
        assertFalse(isValidIdentityJwt("opaque grant"))
        assertFalse(isValidIdentityJwt("header.payload"))
        assertFalse(isValidIdentityJwt("header.payload.signature\n"))
    }
}
