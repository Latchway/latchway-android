package dev.latchway.playintegrity

import com.google.android.play.core.integrity.model.StandardIntegrityErrorCode
import dev.latchway.core.AttestationChallenge
import dev.latchway.core.AttestationMode
import dev.latchway.core.LatchwayErrorCode
import dev.latchway.core.LatchwayException
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class PlayIntegrityAttestationProviderTest {
    private val clientDataHash = "_olyNCtdPHkFUvDTWccbtmIxHPMcgEByopXVu_cSCvo"

    @Test
    fun serverClientDataHashIsForwardedAsRequestHashWithoutRehashing() = runBlocking {
        val gateway = RecordingGateway()
        val provider = PlayIntegrityAttestationProvider.forTesting(gateway)

        val evidence = provider.attest(challenge())

        assertEquals(listOf(clientDataHash), gateway.requestHashes)
        assertEquals(1, gateway.prepareCount)
        assertEquals("play_integrity", evidence.provider)
        assertEquals("integrity-token-from-google-play", evidence.evidence["integrity_token"])
        assertTrue(evidence.toString().contains("[REDACTED]"))
    }

    @Test
    fun invalidProviderIsRenewedOnceAndRequestIsRetried() = runBlocking {
        val gateway = RecordingGateway(
            failures = ArrayDeque(listOf(StandardIntegrityErrorCode.INTEGRITY_TOKEN_PROVIDER_INVALID)),
        )
        val provider = PlayIntegrityAttestationProvider.forTesting(gateway)

        provider.attest(challenge())

        assertEquals(2, gateway.prepareCount)
        assertEquals(1, gateway.invalidateCount)
        assertEquals(2, gateway.requestHashes.size)
    }

    @Test
    fun documentedTransientFailuresUseBoundedExponentialBackoff() = runBlocking {
        val gateway = RecordingGateway(
            failures = ArrayDeque(
                listOf(
                    StandardIntegrityErrorCode.GOOGLE_SERVER_UNAVAILABLE,
                    StandardIntegrityErrorCode.CLIENT_TRANSIENT_ERROR,
                ),
            ),
        )
        val delays = ArrayList<Long>()
        val provider = PlayIntegrityAttestationProvider.forTesting(
            gateway = gateway,
            retryPolicy = PlayIntegrityRetryPolicy(
                maximumAttempts = 3,
                initialDelayMillis = 100,
                maximumDelayMillis = 150,
            ),
            sleeper = { delays += it },
        )

        provider.attest(challenge())

        assertEquals(listOf(100L, 150L), delays)
        assertEquals(3, gateway.requestHashes.size)
    }

    @Test
    fun permanentFailureIsNotRetriedOrReportedAsSuccess() = runBlocking {
        val gateway = RecordingGateway(
            failures = ArrayDeque(listOf(StandardIntegrityErrorCode.APP_UID_MISMATCH)),
        )
        val provider = PlayIntegrityAttestationProvider.forTesting(gateway)

        val error = assertThrows(LatchwayException::class.java) {
            runBlocking { provider.attest(challenge()) }
        }

        assertEquals(LatchwayErrorCode.ATTESTATION_INVALID, error.code)
        assertEquals(false, error.retryable)
        assertEquals(1, gateway.requestHashes.size)
    }

    @Test
    fun unavailableApiIsConfigurationOrDeviceFailureNotATransientRetry() = runBlocking {
        val gateway = RecordingGateway(
            failures = ArrayDeque(listOf(StandardIntegrityErrorCode.API_NOT_AVAILABLE)),
        )
        val provider = PlayIntegrityAttestationProvider.forTesting(gateway)

        val error = assertThrows(LatchwayException::class.java) {
            runBlocking { provider.attest(challenge()) }
        }

        assertEquals(LatchwayErrorCode.ATTESTATION_INVALID, error.code)
        assertEquals(false, error.retryable)
        assertEquals(1, gateway.requestHashes.size)
    }

    @Test
    fun cloudProjectNumberMustBeCanonicalAndMatchBeforePlayIsCalled() {
        val invalidOptions = listOf(
            emptyMap(),
            mapOf("cloud_project_number" to null),
            mapOf("cloud_project_number" to 123_456_789L),
            mapOf("cloud_project_number" to 123_456_789.0),
            mapOf("cloud_project_number" to ""),
            mapOf("cloud_project_number" to " 123456789"),
            mapOf("cloud_project_number" to "+123456789"),
            mapOf("cloud_project_number" to "0123456789"),
            mapOf("cloud_project_number" to "0"),
            mapOf("cloud_project_number" to "-123456789"),
            mapOf("cloud_project_number" to "9223372036854775808"),
            mapOf("cloud_project_number" to "123456788"),
        )

        for (options in invalidOptions) {
            val gateway = RecordingGateway()
            val provider = PlayIntegrityAttestationProvider.forTesting(
                gateway = gateway,
                cloudProjectNumber = 123_456_789L,
            )

            val error = assertThrows(LatchwayException::class.java) {
                runBlocking { provider.attest(challenge(options)) }
            }

            assertEquals(LatchwayErrorCode.ATTESTATION_INVALID, error.code)
            assertEquals(0, gateway.prepareCount)
            assertTrue(gateway.requestHashes.isEmpty())
        }
    }

    private fun challenge(
        providerOptions: Map<String, Any?> = mapOf("cloud_project_number" to "123456789"),
    ): AttestationChallenge = AttestationChallenge(
        challengeId = "chl_01J00000000000000000000001",
        provider = "play_integrity",
        mode = AttestationMode.REQUIRED,
        clientDataHash = clientDataHash,
        providerOptions = providerOptions,
    )

    private class RecordingGateway(
        private val failures: ArrayDeque<Int> = ArrayDeque(),
    ) : StandardIntegrityGateway {
        var prepareCount = 0
        var invalidateCount = 0
        val requestHashes = ArrayList<String>()

        override suspend fun prepare() {
            prepareCount++
        }

        override suspend fun request(requestHash: String): String {
            requestHashes += requestHash
            if (failures.isNotEmpty()) throw IntegrityGatewayException(failures.removeFirst())
            return "integrity-token-from-google-play"
        }

        override suspend fun invalidate() {
            invalidateCount++
        }
    }
}
