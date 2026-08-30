package dev.latchway.playintegrity

import com.google.android.play.core.integrity.model.StandardIntegrityErrorCode
import dev.latchway.core.AttestationChallenge
import dev.latchway.core.AttestationMode
import dev.latchway.core.LatchwayErrorCode
import dev.latchway.core.LatchwayException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import java.util.concurrent.atomic.AtomicInteger
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

    @Test
    fun wrongProviderFailsBeforePlayIsCalled() = runBlocking {
        val gateway = RecordingGateway()
        val provider = PlayIntegrityAttestationProvider.forTesting(gateway)

        val error = assertThrows(LatchwayException::class.java) {
            runBlocking { provider.attest(challenge(provider = "app_attest")) }
        }

        assertEquals(LatchwayErrorCode.ATTESTATION_UNSUPPORTED, error.code)
        assertEquals(0, gateway.prepareCount)
        assertTrue(gateway.requestHashes.isEmpty())
    }

    @Test
    fun requestHashContractRejectsMalformedValuesBeforeProviderConstruction() {
        for (hash in listOf("a".repeat(42), "a".repeat(44), "!".repeat(43), "_".repeat(43))) {
            assertThrows(IllegalArgumentException::class.java) {
                challenge(clientDataHash = hash)
            }
        }
    }

    @Test
    fun integrityTokenBoundsFailClosed() = runBlocking {
        for (token in listOf("x".repeat(15), "x".repeat(262_145))) {
            val gateway = RecordingGateway(token = token)
            val provider = PlayIntegrityAttestationProvider.forTesting(gateway)

            val error = assertThrows(LatchwayException::class.java) {
                runBlocking { provider.attest(challenge()) }
            }

            assertEquals(LatchwayErrorCode.ATTESTATION_INVALID, error.code)
            assertEquals(false, error.retryable)
            assertEquals(1, gateway.requestHashes.size)
        }
    }

    @Test
    fun cancellationPropagatesWithoutBeingReclassified() = runBlocking {
        val gateway = RecordingGateway(requestFailure = CancellationException("cancelled"))
        val provider = PlayIntegrityAttestationProvider.forTesting(gateway)

        assertThrows(CancellationException::class.java) {
            runBlocking { provider.attest(challenge()) }
        }
        assertEquals(1, gateway.requestHashes.size)
    }

    @Test
    fun unexpectedProviderFailureUsesStableRedactedError() = runBlocking {
        val gateway = RecordingGateway(requestFailure = IllegalStateException("provider-secret-detail"))
        val provider = PlayIntegrityAttestationProvider.forTesting(gateway)

        val error = assertThrows(LatchwayException::class.java) {
            runBlocking { provider.attest(challenge()) }
        }

        assertEquals(LatchwayErrorCode.ATTESTATION_INVALID, error.code)
        assertEquals(false, error.retryable)
        assertTrue(!error.toString().contains("provider-secret-detail"))
    }

    @Test
    fun prepareFailuresAreBoundedAndPreventTokenRequests() = runBlocking {
        val transientGateway = RecordingGateway(
            prepareFailures = ArrayDeque(listOf(StandardIntegrityErrorCode.NETWORK_ERROR)),
        )
        val delays = ArrayList<Long>()
        val transientProvider = PlayIntegrityAttestationProvider.forTesting(
            gateway = transientGateway,
            retryPolicy = PlayIntegrityRetryPolicy(maximumAttempts = 2, initialDelayMillis = 50),
            sleeper = { delays += it },
        )

        transientProvider.warmUp()
        assertEquals(2, transientGateway.prepareCount)
        assertEquals(listOf(50L), delays)

        val permanentGateway = RecordingGateway(
            prepareFailures = ArrayDeque(listOf(StandardIntegrityErrorCode.API_NOT_AVAILABLE)),
        )
        val permanentProvider = PlayIntegrityAttestationProvider.forTesting(permanentGateway)
        val error = assertThrows(LatchwayException::class.java) {
            runBlocking { permanentProvider.attest(challenge()) }
        }
        assertEquals(LatchwayErrorCode.ATTESTATION_INVALID, error.code)
        assertEquals(1, permanentGateway.prepareCount)
        assertTrue(permanentGateway.requestHashes.isEmpty())
    }

    @Test
    fun concurrentWarmUpIsSingleFlight() = runBlocking {
        val gateway = RecordingGateway(prepareDelayMillis = 10)
        val provider = PlayIntegrityAttestationProvider.forTesting(gateway)

        coroutineScope {
            List(32) { async { provider.warmUp() } }.awaitAll()
        }

        assertEquals(1, gateway.prepareCount)
        assertTrue(gateway.requestHashes.isEmpty())
    }

    @Test
    fun concurrentInvalidProviderFailuresRotateOneObservedGenerationOnce() = runBlocking {
        val attempts = 16
        val gateway = ConcurrentInvalidGateway(attempts, clientDataHash)
        val provider = PlayIntegrityAttestationProvider.forTesting(gateway)

        coroutineScope {
            List(attempts) { async { provider.attest(challenge()) } }.awaitAll()
        }

        assertEquals(2, gateway.prepareCount)
        assertEquals(1, gateway.invalidateCount)
        assertEquals(attempts * 2, gateway.requestCount.get())
    }

    @Test
    fun requestPausedAfterGenerationSampleCanRenewTheNewGenerationItActuallyUses() = runBlocking {
        val rotatingRequestHash = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        val gateway = RotateAfterSampleGateway(
            pausedRequestHash = clientDataHash,
            rotatingRequestHash = rotatingRequestHash,
        )
        val provider = PlayIntegrityAttestationProvider.forTesting(gateway)

        val pausedRequest = async { provider.attest(challenge()) }
        gateway.pausedRequestEntered.await()
        val rotatingEvidence = provider.attest(challenge(clientDataHash = rotatingRequestHash))
        gateway.releasePausedRequest.complete(Unit)
        val pausedEvidence = pausedRequest.await()

        assertEquals("integrity-token-from-google-play", rotatingEvidence.evidence["integrity_token"])
        assertEquals("integrity-token-from-google-play", pausedEvidence.evidence["integrity_token"])
        assertEquals(3, gateway.prepareCount.get())
        assertEquals(2, gateway.invalidateCount.get())
        assertEquals(listOf(2, 2, 3), gateway.pausedRequestGenerations)
    }

    private fun challenge(
        providerOptions: Map<String, Any?> = mapOf("cloud_project_number" to "123456789"),
        provider: String = "play_integrity",
        clientDataHash: String = this.clientDataHash,
    ): AttestationChallenge = AttestationChallenge(
        challengeId = "chl_01J00000000000000000000001",
        provider = provider,
        mode = AttestationMode.REQUIRED,
        clientDataHash = clientDataHash,
        providerOptions = providerOptions,
    )

    private class RecordingGateway(
        private val failures: ArrayDeque<Int> = ArrayDeque(),
        private val prepareFailures: ArrayDeque<Int> = ArrayDeque(),
        private val requestFailure: Throwable? = null,
        private val token: String = "integrity-token-from-google-play",
        private val prepareDelayMillis: Long = 0,
    ) : StandardIntegrityGateway {
        var prepareCount = 0
        var invalidateCount = 0
        val requestHashes = ArrayList<String>()

        override suspend fun prepare() {
            prepareCount++
            if (prepareDelayMillis > 0) delay(prepareDelayMillis)
            if (prepareFailures.isNotEmpty()) {
                throw IntegrityGatewayException(prepareFailures.removeFirst())
            }
        }

        override suspend fun request(requestHash: String): String {
            requestHashes += requestHash
            requestFailure?.let { throw it }
            if (failures.isNotEmpty()) throw IntegrityGatewayException(failures.removeFirst())
            return token
        }

        override suspend fun invalidate() {
            invalidateCount++
        }
    }

    private class ConcurrentInvalidGateway(
        private val firstGenerationParticipants: Int,
        private val expectedRequestHash: String,
    ) : StandardIntegrityGateway {
        var prepareCount = 0
        var invalidateCount = 0
        val requestCount = AtomicInteger()
        private val firstGenerationArrivals = AtomicInteger()
        private val releaseFirstGeneration = CompletableDeferred<Unit>()

        override suspend fun prepare() {
            prepareCount++
        }

        override suspend fun request(requestHash: String): String {
            check(requestHash == expectedRequestHash)
            requestCount.incrementAndGet()
            if (prepareCount == 1) {
                if (firstGenerationArrivals.incrementAndGet() == firstGenerationParticipants) {
                    releaseFirstGeneration.complete(Unit)
                }
                releaseFirstGeneration.await()
                throw IntegrityGatewayException(StandardIntegrityErrorCode.INTEGRITY_TOKEN_PROVIDER_INVALID)
            }
            return "integrity-token-from-google-play"
        }

        override suspend fun invalidate() {
            invalidateCount++
        }
    }

    private class RotateAfterSampleGateway(
        private val pausedRequestHash: String,
        private val rotatingRequestHash: String,
    ) : StandardIntegrityGateway {
        val prepareCount = AtomicInteger()
        val invalidateCount = AtomicInteger()
        val pausedRequestEntered = CompletableDeferred<Unit>()
        val releasePausedRequest = CompletableDeferred<Unit>()
        val pausedRequestGenerations = ArrayList<Int>()
        private val pausedRequestCount = AtomicInteger()

        override suspend fun prepare() {
            prepareCount.incrementAndGet()
        }

        override suspend fun request(requestHash: String): String {
            if (requestHash == pausedRequestHash) {
                if (pausedRequestCount.incrementAndGet() == 1) {
                    pausedRequestEntered.complete(Unit)
                    releasePausedRequest.await()
                }
                val generation = prepareCount.get()
                pausedRequestGenerations += generation
                if (generation <= 2) {
                    throw IntegrityGatewayException(
                        StandardIntegrityErrorCode.INTEGRITY_TOKEN_PROVIDER_INVALID,
                    )
                }
            } else {
                check(requestHash == rotatingRequestHash)
                if (prepareCount.get() == 1) {
                    throw IntegrityGatewayException(
                        StandardIntegrityErrorCode.INTEGRITY_TOKEN_PROVIDER_INVALID,
                    )
                }
            }
            return "integrity-token-from-google-play"
        }

        override suspend fun invalidate() {
            invalidateCount.incrementAndGet()
        }
    }
}
